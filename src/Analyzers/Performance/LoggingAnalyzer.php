<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class LoggingAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Logging Configuration';
    protected $description = 'Checks if logging is properly configured';
    protected $severity    = 'low';

    public function analyze()
    {
        $issues = [];

        $logChannel = config('logging.default', 'stack');
        $logLevel   = config('logging.channels.' . $logChannel . '.level', 'debug');

        // Check log level in production
        if ($logLevel === 'debug' && $this->app->environment('production')) {
            $issues[] = 'Log level is set to "debug" in production. This may expose sensitive data.';
        }

        // Check log channel
        if ($logChannel === 'single' && $this->app->environment('production')) {
            $issues[] = 'Using "single" log channel in production. Consider using "daily" to prevent large log files.';
        }

        // Check log file size
        $logFile = storage_path('logs/laravel.log');
        if (file_exists($logFile)) {
            $fileSizeMb = filesize($logFile) / (1024 * 1024);
            if ($fileSizeMb > 100) {
                $issues[] = 'Log file is very large (' . round($fileSizeMb, 2) . ' MB). Consider log rotation.';
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Set LOG_LEVEL=error in production .env and use "daily" channel.'
            );
        }

        return $this->passed('Logging configuration is properly set up.');
    }
}
