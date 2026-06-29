<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class CacheConfigAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Cache Configuration';
    protected $description = 'Checks if caching is properly configured for performance';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check cache driver
        $cacheDriver = config('cache.default', 'file');
        if ($cacheDriver === 'file' && $this->app->environment('production')) {
            $issues[] = 'File cache driver is used in production. Consider Redis or Memcached.';
        }

        // Check session driver
        $sessionDriver = config('session.driver', 'file');
        if ($sessionDriver === 'file' && $this->app->environment('production')) {
            $issues[] = 'File session driver is used in production. Consider Redis or Database.';
        }

        // Check if config is cached
        $configCached = file_exists($this->app->getCachedConfigPath());
        if (!$configCached && $this->app->environment('production')) {
            $issues[] = 'Config is not cached in production.';
        }

        // Check if routes are cached
        $routesCached = file_exists($this->app->getCachedRoutesPath());
        if (!$routesCached && $this->app->environment('production')) {
            $issues[] = 'Routes are not cached in production.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: php artisan config:cache && php artisan route:cache'
            );
        }

        return $this->passed('Cache configuration is properly set up.');
    }
}
