<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class HSTSAnalyzer extends BaseAnalyzer
{
    protected $name        = 'HSTS Configuration';
    protected $description = 'Checks if HTTP Strict Transport Security (HSTS) is configured';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues      = [];
        $appPath     = $this->app->path();
        $hstsFound   = false;

        // Check middleware
        $middlewarePath = $appPath . '/Http/Middleware';
        $files          = glob($middlewarePath . DIRECTORY_SEPARATOR . '*.php');

        if ($files) {
            foreach ($files as $file) {
                $content = file_get_contents($file);
                if (
                    strpos($content, 'Strict-Transport-Security') !== false ||
                    strpos($content, 'HSTS') !== false
                ) {
                    $hstsFound = true;
                    break;
                }
            }
        }

        // Check bootstrap/app.php
        $bootstrapApp = base_path('bootstrap/app.php');
        if (file_exists($bootstrapApp)) {
            $content   = file_get_contents($bootstrapApp);
            $hstsFound = $hstsFound ||
                strpos($content, 'Strict-Transport-Security') !== false;
        }

        // Only check in production
        if (!$hstsFound && $this->app->environment('production')) {
            $issues[] = 'HSTS (Strict-Transport-Security) header not configured in production.';
        }

        // Check APP_URL uses HTTPS
        $appUrl = config('app.url', '');
        if (strpos($appUrl, 'https') === false && $this->app->environment('production')) {
            $issues[] = 'APP_URL does not use HTTPS. HSTS requires HTTPS.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Add Strict-Transport-Security: max-age=31536000; includeSubDomains header in middleware.'
            );
        }

        return $this->passed('HSTS is properly configured.');
    }
}
