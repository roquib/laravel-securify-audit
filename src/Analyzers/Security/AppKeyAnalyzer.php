<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class AppKeyAnalyzer extends BaseAnalyzer
{
    protected $name = 'Application Key';
    protected $description = 'Checks if APP_KEY is set and has proper length';
    protected $severity = 'critical';

    public function analyze()
    {
        $appKey = config('app.key', '');

        if (empty($appKey)) {
            return $this->failed(
                'APP_KEY is not set! Your application is insecure.',
                'Run: php artisan key:generate'
            );
        }

        // Remove base64: prefix if exists
        $key = str_replace('base64:', '', $appKey);
        $decoded = base64_decode($key, true);

        if ($decoded === false || strlen($decoded) < 32) {
            return $this->failed(
                'APP_KEY appears to be invalid or too short.',
                'Run: php artisan key:generate to generate a new key.'
            );
        }

        return $this->passed('APP_KEY is properly set and valid.');
    }
}
