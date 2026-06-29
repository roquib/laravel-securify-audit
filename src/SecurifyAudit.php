<?php

namespace Skycoder\SecurifyAudit;

use Illuminate\Contracts\Foundation\Application;

class SecurifyAudit
{
    /**
     * @var Application
     */
    protected $app;

    /**
     * @var array
     */
    protected $results = [];

    /**
     * @var array
     */
    protected $analyzers = [];

    /**
     * Severity weights for scoring
     *
     * @var array
     */
    protected $weights = [
        'failed' => [
            'critical' => 20,
            'high'     => 10,
            'medium'   => 5,
            'low'      => 2,
        ],
        'warning' => [
            'critical' => 10,
            'high'     => 5,
            'medium'   => 2,
            'low'      => 1,
        ],
        'passed' => [
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'low'      => 0,
        ],
    ];

    /**
     * SecurifyAudit constructor.
     *
     * @param Application $app
     */
    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->registerAnalyzers();
    }

    /**
     * Register all analyzers
     *
     * @return void
     */
    protected function registerAnalyzers()
    {
        $securityEnabled    = config('securify-audit.analyzers.security', true);
        $performanceEnabled = config('securify-audit.analyzers.performance', true);
        $skipList           = config('securify-audit.skip', []);

        $securityAnalyzers = [
            \Skycoder\SecurifyAudit\Analyzers\Security\AppDebugAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\AppKeyAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\EnvExposureAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\CsrfAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\SqlInjectionAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\DependencyVulnerabilityAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\WeakPasswordAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\CookieSecurityAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\HttpsAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\RateLimitAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\FilePermissionAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\SessionSecurityAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\XssProtectionAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\CorsAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\SensitiveDataAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\AuthConfigAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\HeaderSecurityAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\MassAssignmentAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\FileUploadAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\CommandInjectionAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\OpenRedirectAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ErrorHandlingAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\DebugbarAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ValidationAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ApiTokenAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\BackupSecurityAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\TimingAttackAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\UnserializeAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\PathTraversalAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ClickjackingAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\HSTSAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\LogInjectionAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ModelScopeAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\MiddlewareOrderAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\PolicyAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Security\ServiceProviderAnalyzer::class,
        ];

        $performanceAnalyzers = [
            \Skycoder\SecurifyAudit\Analyzers\Performance\CacheConfigAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\RouteOptimizationAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\DatabaseIndexAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\NPlusOneAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\QueueConfigAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\LoggingAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\OpcacheAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\ComposerOptimizationAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\AssetOptimizationAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\ViewCacheAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\ConfigCacheAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\AutoloaderOptimizationAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\MemoryUsageAnalyzer::class,
            \Skycoder\SecurifyAudit\Analyzers\Performance\SessionDriverAnalyzer::class,
        ];

        // Filter skipped analyzers
        $filterSkipped = function ($analyzerClass) use ($skipList) {
            $shortName = class_basename($analyzerClass);
            return !in_array($shortName, $skipList);
        };

        if ($securityEnabled) {
            $this->analyzers = array_merge(
                $this->analyzers,
                array_values(array_filter($securityAnalyzers, $filterSkipped))
            );
        }

        if ($performanceEnabled) {
            $this->analyzers = array_merge(
                $this->analyzers,
                array_values(array_filter($performanceAnalyzers, $filterSkipped))
            );
        }
    }

    /**
     * Run all analyzers
     *
     * @return array
     */
    public function run()
    {
        $this->results = [];

        foreach ($this->analyzers as $analyzerClass) {
            try {
                $analyzer      = new $analyzerClass($this->app);
                $result        = $analyzer->analyze();
                $this->results[] = $result;
            } catch (\Exception $e) {
                $this->results[] = [
                    'analyzer'    => $analyzerClass,
                    'status'      => 'error',
                    'message'     => $e->getMessage(),
                    'severity'    => 'error',
                ];
            }
        }

        return $this->results;
    }

    /**
     * Get results
     *
     * @return array
     */
    public function getResults()
    {
        return $this->results;
    }

    /**
     * Get passed checks
     *
     * @return array
     */
    public function getPassed()
    {
        return array_filter($this->results, function ($result) {
            return isset($result['status']) && $result['status'] === 'passed';
        });
    }

    /**
     * Get failed checks
     *
     * @return array
     */
    public function getFailed()
    {
        return array_filter($this->results, function ($result) {
            return isset($result['status']) && $result['status'] === 'failed';
        });
    }

    /**
     * Get warnings
     *
     * @return array
     */
    public function getWarnings()
    {
        return array_filter($this->results, function ($result) {
            return isset($result['status']) && $result['status'] === 'warning';
        });
    }

    /**
     * Get results by severity
     *
     * @param string $severity
     * @return array
     */
    public function getBySeverity($severity)
    {
        return array_filter($this->results, function ($result) use ($severity) {
            return isset($result['severity']) &&
                strtolower($result['severity']) === strtolower($severity);
        });
    }

    /**
     * Calculate weighted score
     *
     * @return int
     */
    public function getScore()
    {
        $totalPenalty    = 0;
        $maxPenalty      = 0;

        foreach ($this->results as $result) {
            $status   = isset($result['status']) ? $result['status'] : 'error';
            $severity = isset($result['severity']) ? strtolower($result['severity']) : 'low';

            // Calculate max possible penalty (if everything failed)
            if (isset($this->weights['failed'][$severity])) {
                $maxPenalty += $this->weights['failed'][$severity];
            }

            // Calculate actual penalty
            if ($status === 'failed' && isset($this->weights['failed'][$severity])) {
                $totalPenalty += $this->weights['failed'][$severity];
            } elseif ($status === 'warning' && isset($this->weights['warning'][$severity])) {
                $totalPenalty += $this->weights['warning'][$severity];
            }
        }

        if ($maxPenalty === 0) {
            return 100;
        }

        $score = 100 - (int) round(($totalPenalty / $maxPenalty) * 100);

        return max(0, min(100, $score));
    }

    /**
     * Get score breakdown by severity
     *
     * @return array
     */
    public function getScoreBreakdown()
    {
        $breakdown = [
            'critical' => ['passed' => 0, 'failed' => 0, 'warning' => 0, 'penalty' => 0],
            'high'     => ['passed' => 0, 'failed' => 0, 'warning' => 0, 'penalty' => 0],
            'medium'   => ['passed' => 0, 'failed' => 0, 'warning' => 0, 'penalty' => 0],
            'low'      => ['passed' => 0, 'failed' => 0, 'warning' => 0, 'penalty' => 0],
        ];

        foreach ($this->results as $result) {
            $status   = isset($result['status']) ? $result['status'] : 'error';
            $severity = isset($result['severity']) ? strtolower($result['severity']) : 'low';

            if (!isset($breakdown[$severity])) {
                continue;
            }

            if ($status === 'passed') {
                $breakdown[$severity]['passed']++;
            } elseif ($status === 'failed') {
                $breakdown[$severity]['failed']++;
                $breakdown[$severity]['penalty'] += $this->weights['failed'][$severity] ?? 0;
            } elseif ($status === 'warning') {
                $breakdown[$severity]['warning']++;
                $breakdown[$severity]['penalty'] += $this->weights['warning'][$severity] ?? 0;
            }
        }

        return $breakdown;
    }

    /**
     * Get security grade
     *
     * @return string
     */
    public function getGrade()
    {
        $score = $this->getScore();

        if ($score >= 95) return 'A+';
        if ($score >= 90) return 'A';
        if ($score >= 85) return 'A-';
        if ($score >= 80) return 'B+';
        if ($score >= 75) return 'B';
        if ($score >= 70) return 'B-';
        if ($score >= 65) return 'C+';
        if ($score >= 60) return 'C';
        if ($score >= 55) return 'C-';
        if ($score >= 50) return 'D';

        return 'F';
    }

    /**
     * Get weights configuration
     *
     * @return array
     */
    public function getWeights()
    {
        return $this->weights;
    }
}
