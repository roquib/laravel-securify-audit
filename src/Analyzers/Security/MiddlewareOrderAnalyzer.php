<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class MiddlewareOrderAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Middleware Order';
    protected $description = 'Checks if security middleware is in the correct order';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check Kernel.php for middleware order
        $kernelPath = $this->app->path('Http/Kernel.php');

        if (!file_exists($kernelPath)) {
            // Laravel 11+ - check bootstrap/app.php
            $bootstrapApp = base_path('bootstrap/app.php');
            if (!file_exists($bootstrapApp)) {
                return $this->warning(
                    'Could not find Kernel.php or bootstrap/app.php to check middleware order.',
                    'Manually verify middleware order in your application.'
                );
            }

            $content = file_get_contents($bootstrapApp);

            // Check auth before throttle
            $authPos     = strpos($content, 'auth');
            $throttlePos = strpos($content, 'throttle');

            if ($authPos !== false && $throttlePos !== false) {
                if ($authPos < $throttlePos) {
                    $issues[] = 'Auth middleware appears before throttle. Throttle should come first.';
                }
            }

            if (count($issues) > 0) {
                return $this->warning(
                    implode(' | ', $issues),
                    'Place throttle middleware before auth middleware for better security.'
                );
            }

            return $this->passed('Middleware order appears correct.');
        }

        $content = file_get_contents($kernelPath);

        // Check if auth comes before throttle in API middleware
        $apiSection = '';
        if (preg_match("/'api'\s*=>\s*\[(.*?)\]/s", $content, $matches)) {
            $apiSection = $matches[1];
        }

        if (!empty($apiSection)) {
            $authPos     = strpos($apiSection, 'auth');
            $throttlePos = strpos($apiSection, 'throttle');

            if ($authPos !== false && $throttlePos !== false) {
                if ($authPos < $throttlePos) {
                    $issues[] = 'In API middleware group: auth appears before throttle.';
                }
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Place throttle:api before auth:sanctum in API middleware group.'
            );
        }

        return $this->passed('Middleware order is properly configured.');
    }
}
