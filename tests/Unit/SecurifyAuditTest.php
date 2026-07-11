<?php

namespace Skycoder\SecurifyAudit\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Skycoder\SecurifyAudit\SecurifyAudit;
use Skycoder\SecurifyAudit\Tests\TestCase;

class SecurifyAuditTest extends TestCase
{
    #[Test]
    public function it_can_be_instantiated()
    {
        $audit = new SecurifyAudit($this->app);

        $this->assertInstanceOf(SecurifyAudit::class, $audit);
    }

    #[Test]
    public function it_returns_an_array_of_results()
    {
        $audit = new SecurifyAudit($this->app);
        $results = $audit->run();

        $this->assertIsArray($results);
        $this->assertNotEmpty($results);
    }

    #[Test]
    public function each_result_has_required_keys()
    {
        $audit = new SecurifyAudit($this->app);
        $results = $audit->run();

        foreach ($results as $result) {
            $this->assertArrayHasKey('analyzer', $result);
            $this->assertArrayHasKey('status', $result);
            $this->assertArrayHasKey('severity', $result);
            $this->assertArrayHasKey('message', $result);
            $this->assertContains($result['status'], ['passed', 'failed', 'warning', 'error']);
        }
    }

    #[Test]
    public function it_returns_perfect_score_when_all_pass()
    {
        $results = [
            [
                'analyzer' => 'Test Analyzer',
                'description' => 'Test',
                'status' => 'passed',
                'severity' => 'critical',
                'message' => 'All good.',
            ],
            [
                'analyzer' => 'Test Analyzer 2',
                'description' => 'Test',
                'status' => 'passed',
                'severity' => 'high',
                'message' => 'All good.',
            ],
        ];

        $audit = $this->createAuditWithResults($results);

        $this->assertEquals(100, $audit->getScore());
        $this->assertEquals('A+', $audit->getGrade());
    }

    #[Test]
    public function it_calculates_score_with_penalties()
    {
        $results = [
            [
                'analyzer' => 'Failed Critical',
                'description' => 'Test',
                'status' => 'failed',
                'severity' => 'critical',
                'message' => 'Critical failure.',
            ],
            [
                'analyzer' => 'Passed High',
                'description' => 'Test',
                'status' => 'passed',
                'severity' => 'high',
                'message' => 'All good.',
            ],
        ];

        $audit = $this->createAuditWithResults($results);

        $score = $audit->getScore();
        // 1 critical failed = 20 penalty out of 30 max = ~67 score
        $this->assertGreaterThan(0, $score);
        $this->assertLessThan(100, $score);
    }

    #[Test]
    public function it_returns_zero_score_when_all_fail()
    {
        $results = [
            [
                'analyzer' => 'Fail 1',
                'description' => 'Test',
                'status' => 'failed',
                'severity' => 'critical',
                'message' => 'Fail.',
            ],
            [
                'analyzer' => 'Fail 2',
                'description' => 'Test',
                'status' => 'failed',
                'severity' => 'high',
                'message' => 'Fail.',
            ],
        ];

        $audit = $this->createAuditWithResults($results);

        $this->assertEquals(0, $audit->getScore());
        $this->assertEquals('F', $audit->getGrade());
    }

    #[Test]
    public function it_returns_correct_grade_for_each_score_range()
    {
        $ranges = [
            [100, 'A+'],
            [95, 'A+'],
            [94, 'A'],
            [90, 'A'],
            [89, 'A-'],
            [85, 'A-'],
            [84, 'B+'],
            [80, 'B+'],
            [79, 'B'],
            [75, 'B'],
            [74, 'B-'],
            [70, 'B-'],
            [69, 'C+'],
            [65, 'C+'],
            [64, 'C'],
            [60, 'C'],
            [59, 'C-'],
            [55, 'C-'],
            [54, 'D'],
            [50, 'D'],
            [49, 'F'],
            [0, 'F'],
        ];

        $audit = $this->getMockBuilder(SecurifyAudit::class)
            ->setConstructorArgs([$this->app])
            ->onlyMethods(['getScore'])
            ->getMock();

        $currentScore = null;
        $audit->method('getScore')->willReturnCallback(function () use (&$currentScore) {
            return $currentScore;
        });

        foreach ($ranges as [$score, $expectedGrade]) {
            $currentScore = $score;

            $this->assertEquals(
                $expectedGrade,
                $audit->getGrade(),
                "Score {$score} should yield grade {$expectedGrade}"
            );
        }
    }

    #[Test]
    public function it_filters_passed_results()
    {
        $results = [
            ['analyzer' => 'A', 'status' => 'passed', 'severity' => 'low', 'message' => 'ok'],
            ['analyzer' => 'B', 'status' => 'failed', 'severity' => 'high', 'message' => 'fail'],
            ['analyzer' => 'C', 'status' => 'warning', 'severity' => 'medium', 'message' => 'warn'],
        ];

        $audit = $this->createAuditWithResults($results);

        $this->assertCount(1, $audit->getPassed());
        $this->assertCount(1, $audit->getFailed());
        $this->assertCount(1, $audit->getWarnings());
    }

    #[Test]
    public function it_filters_by_severity()
    {
        $results = [
            ['analyzer' => 'A', 'status' => 'failed', 'severity' => 'critical', 'message' => 'crit'],
            ['analyzer' => 'B', 'status' => 'failed', 'severity' => 'high', 'message' => 'high'],
            ['analyzer' => 'C', 'status' => 'warning', 'severity' => 'medium', 'message' => 'med'],
        ];

        $audit = $this->createAuditWithResults($results);

        $this->assertCount(1, $audit->getBySeverity('critical'));
        $this->assertCount(1, $audit->getBySeverity('high'));
        $this->assertCount(1, $audit->getBySeverity('medium'));
        $this->assertCount(0, $audit->getBySeverity('low'));
    }

    #[Test]
    public function it_returns_score_breakdown()
    {
        $results = [
            [
                'analyzer' => 'A',
                'description' => 'Test',
                'status' => 'failed',
                'severity' => 'critical',
                'message' => 'fail',
            ],
            [
                'analyzer' => 'B',
                'description' => 'Test',
                'status' => 'warning',
                'severity' => 'high',
                'message' => 'warn',
            ],
            [
                'analyzer' => 'C',
                'description' => 'Test',
                'status' => 'passed',
                'severity' => 'low',
                'message' => 'pass',
            ],
        ];

        $audit = $this->createAuditWithResults($results);
        $breakdown = $audit->getScoreBreakdown();

        $this->assertEquals(1, $breakdown['critical']['failed']);
        $this->assertEquals(1, $breakdown['high']['warning']);
        $this->assertEquals(1, $breakdown['low']['passed']);
    }

    #[Test]
    public function it_handles_empty_results()
    {
        $audit = $this->createAuditWithResults([]);

        $this->assertEquals(100, $audit->getScore());
        $this->assertEquals('A+', $audit->getGrade());
        $this->assertCount(0, $audit->getResults());
        $this->assertCount(0, $audit->getPassed());
        $this->assertCount(0, $audit->getFailed());
        $this->assertCount(0, $audit->getWarnings());
    }


}
