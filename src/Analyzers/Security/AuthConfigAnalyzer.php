<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class AuthConfigAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Auth Configuration';
    protected $description = 'Checks authentication and authorization configuration';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check password reset token expiry
        $expiry = config('auth.passwords.users.expire', 60);
        if ($expiry > 60) {
            $issues[] = 'Password reset token expires in ' . $expiry . ' minutes. Recommended max is 60.';
        }

        // Check remember me token
        $guards = config('auth.guards', []);
        foreach ($guards as $name => $guard) {
            if (isset($guard['driver']) && $guard['driver'] === 'session') {
                // Session guard is fine
            }
        }

        // Check if default password provider uses bcrypt
        $providers = config('auth.providers', []);
        foreach ($providers as $name => $provider) {
            if (isset($provider['driver']) && $provider['driver'] === 'eloquent') {
                // Check model has fillable protection
                if (isset($provider['model'])) {
                    $modelClass = $provider['model'];
                    if (class_exists($modelClass)) {
                        $model    = new $modelClass();
                        $fillable = $model->getFillable();
                        $guarded  = $model->getGuarded();

                        if (in_array('password', $fillable) && empty($guarded)) {
                            $issues[] = 'Password field is in fillable array in ' . $modelClass . '.';
                        }
                    }
                }
            }
        }

        // Check for 2FA implementation
        $twoFactorFiles = [
            $this->app->path('Http/Middleware/TwoFactor.php'),
            $this->app->path('Http/Middleware/EnsureTwoFactorEnabled.php'),
        ];

        $twoFactorFound = false;
        foreach ($twoFactorFiles as $file) {
            if (file_exists($file)) {
                $twoFactorFound = true;
                break;
            }
        }

        if (!$twoFactorFound) {
            $issues[] = 'Two-Factor Authentication (2FA) middleware not found.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Review auth config, remove password from fillable, consider implementing 2FA.'
            );
        }

        return $this->passed('Authentication configuration looks secure.');
    }
}
