<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class RateLimitAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Rate Limiting';
    protected $description = 'Checks if API and login rate limiting is configured';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check RouteServiceProvider for rate limiting
        $routeServiceProvider = $this->app->path('Providers/RouteServiceProvider.php');
        $rateLimitFound       = false;

        if (file_exists($routeServiceProvider)) {
            $content        = file_get_contents($routeServiceProvider);
            $rateLimitFound = strpos($content, 'RateLimiter') !== false
                || strpos($content, 'throttle') !== false;
        }

        // Check bootstrap/app.php for Laravel 11+
        $bootstrapApp = base_path('bootstrap/app.php');
        if (file_exists($bootstrapApp)) {
            $content        = file_get_contents($bootstrapApp);
            $rateLimitFound = $rateLimitFound
                || strpos($content, 'throttle') !== false;
        }

        // Check routes for throttle middleware
        $routeFiles  = glob(base_path('routes') . DIRECTORY_SEPARATOR . '*.php');
        $throttleFound = false;

        if ($routeFiles) {
            foreach ($routeFiles as $file) {
                $content = file_get_contents($file);
                if (strpos($content, 'throttle') !== false) {
                    $throttleFound = true;
                    break;
                }
            }
        }

        if (!$rateLimitFound && !$throttleFound) {
            $issues[] = 'No rate limiting configuration found.';
        }

        // Check login throttling
        $loginController = $this->app->path('Http/Controllers/Auth/LoginController.php');
        if (file_exists($loginController)) {
            $content = file_get_contents($loginController);
            if (strpos($content, 'ThrottlesLogins') === false) {
                $issues[] = 'Login throttling (ThrottlesLogins) not found.';
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Add throttle middleware to API routes and use RateLimiter facade in RouteServiceProvider.'
            );
        }

        return $this->passed('Rate limiting is properly configured.');
    }
}
