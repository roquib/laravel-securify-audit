<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ApiTokenAnalyzer extends BaseAnalyzer
{
    protected $name        = 'API Token Security';
    protected $description = 'Checks API token configuration and security';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check Sanctum configuration
        $sanctumInstalled = file_exists(config_path('sanctum.php'));
        if ($sanctumInstalled) {
            $expiration = config('sanctum.expiration', null);
            if ($expiration === null) {
                $issues[] = 'Sanctum token expiration is not set. Tokens never expire.';
            }

            // Check stateful domains
            $statefulDomains = config('sanctum.stateful', []);
            if (empty($statefulDomains)) {
                $issues[] = 'Sanctum stateful domains not configured.';
            }
        }

        // Check Passport configuration
        $passportInstalled = file_exists(config_path('passport.php'));
        if ($passportInstalled) {
            $tokensExpireIn        = config('passport.tokens_expire_in', null);
            $refreshTokensExpireIn = config('passport.refresh_tokens_expire_in', null);

            if ($tokensExpireIn === null) {
                $issues[] = 'Passport access token expiration not configured.';
            }

            if ($refreshTokensExpireIn === null) {
                $issues[] = 'Passport refresh token expiration not configured.';
            }
        }

        // Check JWT configuration
        $jwtInstalled = file_exists(config_path('jwt.php'));
        if ($jwtInstalled) {
            $secret = config('jwt.secret', null);
            if (empty($secret)) {
                $issues[] = 'JWT secret is not configured.';
            }

            $ttl = config('jwt.ttl', null);
            if ($ttl === null || $ttl > 1440) {
                $issues[] = 'JWT TTL is too long or not configured. Recommended max is 1440 minutes.';
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Configure token expiration times and ensure proper API authentication setup.'
            );
        }

        return $this->passed('API token security is properly configured.');
    }
}
