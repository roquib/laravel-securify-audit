<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class DebugbarAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Debugbar Security';
    protected $description = 'Checks if Laravel Debugbar is disabled in production';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check if debugbar is installed
        $debugbarInstalled = class_exists('\Barryvdh\Debugbar\ServiceProvider')
            || file_exists(base_path('vendor/barryvdh/laravel-debugbar'));

        if (!$debugbarInstalled) {
            return $this->passed('Laravel Debugbar is not installed.');
        }

        // Check if enabled in production
        $debugbarEnabled = config('debugbar.enabled', null);

        if ($debugbarEnabled === null) {
            // Default behavior: enabled when APP_DEBUG is true
            if (config('app.debug') && $this->app->environment('production')) {
                $issues[] = 'Debugbar may be enabled in production (follows APP_DEBUG=true).';
            }
        } elseif ($debugbarEnabled === true && $this->app->environment('production')) {
            $issues[] = 'Debugbar is explicitly enabled in production!';
        }

        // Check config file
        $debugbarConfig = config_path('debugbar.php');
        if (file_exists($debugbarConfig)) {
            $content = file_get_contents($debugbarConfig);
            if (preg_match("/'enabled'\s*=>\s*true/", $content)) {
                $issues[] = 'Debugbar enabled=true is hardcoded in config/debugbar.php.';
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Set DEBUGBAR_ENABLED=false in production .env or set enabled => env("DEBUGBAR_ENABLED", false) in config/debugbar.php.'
            );
        }

        return $this->passed('Debugbar is properly disabled.');
    }
}
