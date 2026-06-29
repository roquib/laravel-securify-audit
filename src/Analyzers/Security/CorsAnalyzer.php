<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class CorsAnalyzer extends BaseAnalyzer
{
    protected $name        = 'CORS Configuration';
    protected $description = 'Checks if CORS is properly configured';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check cors config
        $corsConfig = config('cors', null);

        if ($corsConfig === null) {
            return $this->warning(
                'CORS configuration not found.',
                'Run: php artisan config:publish --tag=cors'
            );
        }

        // Check allowed origins
        $allowedOrigins = config('cors.allowed_origins', []);
        if (in_array('*', $allowedOrigins) && $this->app->environment('production')) {
            $issues[] = 'CORS allowed_origins is set to wildcard (*) in production.';
        }

        // Check allowed methods
        $allowedMethods = config('cors.allowed_methods', []);
        if (in_array('*', $allowedMethods)) {
            $issues[] = 'CORS allowed_methods is set to wildcard (*). Restrict to needed methods only.';
        }

        // Check supports credentials with wildcard
        $supportsCredentials = config('cors.supports_credentials', false);
        if ($supportsCredentials && in_array('*', $allowedOrigins)) {
            $issues[] = 'CORS supports_credentials cannot be used with wildcard origin. Security risk!';
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Update config/cors.php: specify exact origins instead of wildcard.'
            );
        }

        return $this->passed('CORS is properly configured.');
    }
}
