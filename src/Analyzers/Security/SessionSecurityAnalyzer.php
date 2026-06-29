<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class SessionSecurityAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Session Security';
    protected $description = 'Checks session configuration for security issues';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check session lifetime
        $lifetime = config('session.lifetime', 120);
        if ($lifetime > 1440) {
            $issues[] = 'Session lifetime is too long (' . $lifetime . ' minutes). Recommended max is 1440 (24 hours).';
        }

        // Check session driver
        $driver = config('session.driver', 'file');
        if ($driver === 'cookie') {
            $issues[] = 'Cookie session driver stores session data on client side. Use database or redis instead.';
        }

        // Check session encryption
        $encrypt = config('session.encrypt', false);
        if (!$encrypt) {
            $issues[] = 'Session data is not encrypted.';
        }

        // Check session cookie name (should not be default)
        $cookieName = config('session.cookie', 'laravel_session');
        if ($cookieName === 'laravel_session') {
            $issues[] = 'Session cookie name is set to default "laravel_session". Consider changing it.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Update config/session.php: set encrypt=true, use redis driver, change cookie name.'
            );
        }

        return $this->passed('Session security is properly configured.');
    }
}
