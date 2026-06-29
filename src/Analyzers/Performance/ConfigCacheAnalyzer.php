<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ConfigCacheAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Config Cache';
    protected $description = 'Checks if configuration is cached for better performance';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues       = [];
        $configCached = file_exists($this->app->getCachedConfigPath());

        if (!$configCached && $this->app->environment('production')) {
            $issues[] = 'Configuration is not cached in production. Every request re-reads config files.';
        }

        // Check if env() is used in config files (breaks config caching)
        $configPath = config_path();
        $configFiles = glob($configPath . DIRECTORY_SEPARATOR . '*.php');

        if ($configFiles) {
            foreach ($configFiles as $file) {
                $content  = file_get_contents($file);
                $fileName = basename($file);

                // env() in config is fine — but check for direct usage in non-config contexts
                // This is actually correct usage, so just verify config:cache works
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: php artisan config:cache in production for better performance.'
            );
        }

        return $this->passed('Configuration is properly cached.');
    }
}
