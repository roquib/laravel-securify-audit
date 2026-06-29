<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class HeaderSecurityAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Security Headers';
    protected $description = 'Checks for important HTTP security headers configuration';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues   = [];
        $appPath  = $this->app->path();

        // Check middleware for security headers
        $middlewarePath = $appPath . '/Http/Middleware';
        $files          = glob($middlewarePath . DIRECTORY_SEPARATOR . '*.php');

        $headersFound = false;

        if ($files) {
            foreach ($files as $file) {
                $content = file_get_contents($file);
                if (
                    strpos($content, 'X-Frame-Options') !== false ||
                    strpos($content, 'X-Content-Type-Options') !== false ||
                    strpos($content, 'Content-Security-Policy') !== false
                ) {
                    $headersFound = true;
                    break;
                }
            }
        }

        // Check bootstrap/app.php for Laravel 11+
        $bootstrapApp = base_path('bootstrap/app.php');
        if (file_exists($bootstrapApp)) {
            $content      = file_get_contents($bootstrapApp);
            $headersFound = $headersFound ||
                strpos($content, 'X-Frame-Options') !== false ||
                strpos($content, 'secureHeaders') !== false;
        }

        if (!$headersFound) {
            $issues[] = 'Security headers middleware not found (X-Frame-Options, X-Content-Type-Options, CSP).';
        }

        // Check cors headers
        $xFrameOptions = config('cors.allowed_origins', []);
        if (empty($xFrameOptions)) {
            $issues[] = 'X-Frame-Options not configured. Vulnerable to clickjacking.';
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Create a SecurityHeaders middleware and add: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security headers.'
            );
        }

        return $this->passed('Security headers are properly configured.');
    }
}
