<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class QueueConfigAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Queue Configuration';
    protected $description = 'Checks if queue is properly configured for production';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        $queueDriver = config('queue.default', 'sync');

        if ($queueDriver === 'sync' && $this->app->environment('production')) {
            $issues[] = 'Queue driver is set to "sync" in production. Jobs run synchronously and block requests.';
        }

        // Check failed jobs table
        $failedDriver = config('queue.failed.driver', null);
        if ($failedDriver === null) {
            $issues[] = 'Failed job handling is not configured.';
        }

        // Check if horizon is installed
        $horizonConfig = config_path('horizon.php');
        if (!file_exists($horizonConfig) && $queueDriver === 'redis') {
            $issues[] = 'Using Redis queue but Laravel Horizon is not installed.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Use redis or database queue driver in production. Install Horizon for Redis queues.'
            );
        }

        return $this->passed('Queue configuration looks good.');
    }
}
