<?php

namespace Skycoder\SecurifyAudit\Tests\Unit;

use Skycoder\SecurifyAudit\Analyzers\Security\AppDebugAnalyzer;
use Skycoder\SecurifyAudit\Tests\TestCase;

class AppDebugAnalyzerTest extends TestCase
{
    /** @test */
    public function it_passes_when_not_in_production_and_debug_is_off()
    {
        $this->app['config']->set('app.debug', false);

        $analyzer = new AppDebugAnalyzer($this->app);
        $result = $analyzer->analyze();

        $this->assertEquals('passed', $result['status']);
    }

    /** @test */
    public function it_warns_when_not_in_production_but_debug_is_on()
    {
        $this->app['config']->set('app.debug', true);

        $analyzer = new AppDebugAnalyzer($this->app);
        $result = $analyzer->analyze();

        $this->assertEquals('warning', $result['status']);
    }

    /** @test */
    public function it_fails_when_in_production_and_debug_is_on()
    {
        $this->app['config']->set('app.debug', true);
        $this->app['config']->set('app.env', 'production');

        $analyzer = new AppDebugAnalyzer($this->app);
        $result = $analyzer->analyze();

        $this->assertEquals('failed', $result['status']);
    }

    /** @test */
    public function it_returns_critical_severity()
    {
        $analyzer = new AppDebugAnalyzer($this->app);

        $this->assertEquals('critical', $analyzer->getSeverity());
    }
}
