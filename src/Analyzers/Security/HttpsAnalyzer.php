<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class HttpsAnalyzer extends BaseAnalyzer
{
    protected $name        = 'HTTPS & SSL';
    protected $description = 'Checks if HTTPS is enforced in production';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues = [];

        // Check force HTTPS in AppServiceProvider or TrustProxies
        $appServiceProvider = $this->app->path('Providers/AppServiceProvider.php');
        $forceHttps         = false;

        if (file_exists($appServiceProvider)) {
            $content    = file_get_contents($appServiceProvider);
            $forceHttps = strpos($content, 'forceScheme') !== false
                || strpos($content, 'URL::forceScheme') !== false
                || strpos($content, 'https') !== false;
        }

        // Check TrustProxies middleware
        $trustProxies = $this->app->path('Http/Middleware/TrustProxies.php');
        if (file_exists($trustProxies)) {
            $content      = file_get_contents($trustProxies);
            $forceHttps   = $forceHttps || strpos($content, 'TRUSTED_PROXIES') !== false;
        }

        // Check APP_URL starts with https
        $appUrl = config('app.url', '');
        if (strpos($appUrl, 'https') === false && $this->app->environment('production')) {
            $issues[] = 'APP_URL is not using HTTPS in production.';
        }

        if (!$forceHttps && $this->app->environment('production')) {
            $issues[] = 'HTTPS is not being enforced in production.';
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Add URL::forceScheme("https") in AppServiceProvider boot() method.'
            );
        }

        return $this->passed('HTTPS is properly configured.');
    }
}
