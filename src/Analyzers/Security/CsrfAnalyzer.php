<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class CsrfAnalyzer extends BaseAnalyzer
{
    protected $name = 'CSRF Protection';
    protected $description = 'Checks if CSRF protection middleware is enabled';
    protected $severity = 'high';

    // Known CSRF middleware class name fragments across Laravel versions
    private const CSRF_MIDDLEWARE_PATTERNS = [
        'VerifyCsrfToken',        // Laravel ≤10 (App\Http\Middleware or Illuminate)
        'ValidateCsrfToken',      // Laravel 11 transitional alias
        'PreventRequestForgery',  // Laravel 11+ canonical name
    ];

    public function analyze()
    {
        $kernel = $this->app->make(\Illuminate\Contracts\Http\Kernel::class);

        // Use the public API first (Laravel 11+), fall back to reflection (Laravel ≤10)
        if (method_exists($kernel, 'getMiddlewareGroups')) {
            $middlewareGroups = $kernel->getMiddlewareGroups();
        } else {
            $reflection = new \ReflectionClass($kernel);

            if (!$reflection->hasProperty('middlewareGroups')) {
                return $this->warning(
                    'Could not verify CSRF middleware configuration.',
                    'Manually check that a CSRF middleware is enabled in the web middleware group.'
                );
            }

            $property = $reflection->getProperty('middlewareGroups');
            $property->setAccessible(true);
            $middlewareGroups = $property->getValue($kernel);
        }

        $webMiddleware = $middlewareGroups['web'] ?? [];

        $csrfFound = false;
        foreach ($webMiddleware as $middleware) {
            foreach (self::CSRF_MIDDLEWARE_PATTERNS as $pattern) {
                if (strpos($middleware, $pattern) !== false) {
                    $csrfFound = true;
                    break 2;
                }
            }
        }

        if (!$csrfFound) {
            return $this->failed(
                'CSRF protection middleware is not found in web middleware group.',
                'Add \Illuminate\Foundation\Http\Middleware\PreventRequestForgery::class to web middleware group (Laravel 11+) or \App\Http\Middleware\VerifyCsrfToken::class (Laravel ≤10).'
            );
        }

        return $this->passed('CSRF protection is properly enabled.');
    }
}
