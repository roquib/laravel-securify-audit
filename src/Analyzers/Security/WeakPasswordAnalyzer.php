<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class WeakPasswordAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Password Security';
    protected $description = 'Checks password hashing and validation rules';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check hashing algorithm
        $hashDriver = config('hashing.driver', 'bcrypt');
        if ($hashDriver === 'md5' || $hashDriver === 'sha1') {
            $issues[] = 'Weak hashing algorithm (' . $hashDriver . ') is configured.';
        }

        // Check bcrypt rounds
        if ($hashDriver === 'bcrypt') {
            $rounds = config('hashing.bcrypt.rounds', 10);
            if ($rounds < 10) {
                $issues[] = 'BCrypt rounds (' . $rounds . ') is too low. Minimum recommended is 10.';
            }
        }

        // Check if password validation exists in auth config
        $this->checkPasswordValidation($issues);

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Use bcrypt with at least 10 rounds. Add strong password validation rules.'
            );
        }

        return $this->passed('Password security configuration looks good.');
    }

    /**
     * Check password validation rules in codebase
     *
     * @param array $issues
     * @return void
     */
    protected function checkPasswordValidation(&$issues)
    {
        $appPath  = $this->app->path();
        $phpFiles = glob($appPath . '/Http/Requests/*.php');

        if (!$phpFiles) {
            return;
        }

        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);

            // Check for weak password rules
            if (
                strpos($content, "'password'") !== false &&
                strpos($content, 'min:') === false &&
                strpos($content, 'Password::') === false
            ) {
                $issues[] = 'Password validation may be missing minimum length in: ' . basename($file);
                break;
            }
        }
    }
}
