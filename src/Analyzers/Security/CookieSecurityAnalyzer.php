<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class CookieSecurityAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Cookie Security';
    protected $description = 'Checks if cookies are properly secured';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check if session cookie is secure
        $secure   = config('session.secure', false);
        $httpOnly = config('session.http_only', true);
        $sameSite = config('session.same_site', null);

        if (!$secure && $this->app->environment('production')) {
            $issues[] = 'Session cookie "secure" flag is disabled in production.';
        }

        if (!$httpOnly) {
            $issues[] = 'Session cookie "http_only" flag is disabled. Cookies accessible via JavaScript.';
        }

        if (empty($sameSite)) {
            $issues[] = 'Session cookie "same_site" is not configured. Vulnerable to CSRF attacks.';
        }

        // Check cookie encryption
        $kernel     = $this->app->make(\Illuminate\Contracts\Http\Kernel::class);
        $reflection = new \ReflectionClass($kernel);

        if ($reflection->hasProperty('middlewareGroups')) {
            $property = $reflection->getProperty('middlewareGroups');
            $property->setAccessible(true);
            $middlewareGroups = $property->getValue($kernel);

            $webMiddleware  = isset($middlewareGroups['web']) ? $middlewareGroups['web'] : [];
            $encryptFound   = false;

            foreach ($webMiddleware as $middleware) {
                if (strpos($middleware, 'EncryptCookies') !== false) {
                    $encryptFound = true;
                    break;
                }
            }

            if (!$encryptFound) {
                $issues[] = 'EncryptCookies middleware not found in web group.';
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Update config/session.php: set secure=true, http_only=true, same_site=lax'
            );
        }

        return $this->passed('Cookie security is properly configured.');
    }
}
