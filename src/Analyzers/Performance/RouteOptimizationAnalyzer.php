<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class RouteOptimizationAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Route Optimization';
    protected $description = 'Checks if routes are optimized for production';
    protected $severity    = 'low';

    public function analyze()
    {
        $issues = [];

        // Check route caching
        $routesCached = file_exists($this->app->getCachedRoutesPath());
        if (!$routesCached && $this->app->environment('production')) {
            $issues[] = 'Routes are not cached. This slows down every request.';
        }

        // Check for closure routes (not cacheable)
        $routeFiles = glob(base_path('routes') . DIRECTORY_SEPARATOR . '*.php');
        $closureCount = 0;

        if ($routeFiles) {
            foreach ($routeFiles as $file) {
                $content = file_get_contents($file);
                preg_match_all('/Route::(get|post|put|patch|delete|any)\s*\([^,]+,\s*function/', $content, $matches);
                $closureCount += count($matches[0]);
            }
        }

        if ($closureCount > 0) {
            $issues[] = $closureCount . ' closure route(s) found. Closure routes cannot be cached.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Replace closure routes with controller actions and run: php artisan route:cache'
            );
        }

        return $this->passed('Routes are properly optimized.');
    }
}
