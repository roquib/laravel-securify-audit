<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class AppDebugAnalyzer extends BaseAnalyzer
{
    protected $name = 'App Debug Mode';
    protected $description = 'Checks if APP_DEBUG is disabled in production';
    protected $severity = 'critical';

    public function analyze()
    {
        $isProduction = $this->app->environment('production');
        $isDebug      = config('app.debug', false);

        if ($isProduction && $isDebug) {
            return $this->failed(
                'APP_DEBUG is enabled in production! This exposes sensitive information.',
                'Set APP_DEBUG=false in your .env file for production.'
            );
        }

        if (!$isProduction && $isDebug) {
            return $this->warning(
                'APP_DEBUG is enabled. Make sure it is disabled in production.',
                'Set APP_DEBUG=false in your production .env file.'
            );
        }

        return $this->passed('APP_DEBUG is properly disabled.');
    }
}
