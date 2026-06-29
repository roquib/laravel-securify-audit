<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class TimingAttackAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Timing Attack Protection';
    protected $description = 'Checks for timing attack vulnerabilities in string comparisons';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check for == or === comparison with tokens/hashes
            $patterns = [
                '/\$token\s*==\s*\$/',
                '/\$hash\s*==\s*\$/',
                '/\$signature\s*==\s*\$/',
                '/\$hmac\s*==\s*\$/',
                '/\$secret\s*==\s*\$/',
                '/strcmp\s*\(.*token.*\)/',
                '/strcmp\s*\(.*hash.*\)/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential timing attack vulnerability in: {$fileName}";
                    break;
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                count($issues) . ' timing attack vulnerability(ies) found.',
                'Use hash_equals() instead of == or === for comparing tokens, hashes, and secrets.'
            );
        }

        return $this->passed('No timing attack vulnerabilities detected.');
    }

    protected function getPhpFiles($path)
    {
        $files = [];
        $items = glob($path . DIRECTORY_SEPARATOR . '*');

        if (!$items) {
            return $files;
        }

        foreach ($items as $item) {
            if (is_dir($item)) {
                $files = array_merge($files, $this->getPhpFiles($item));
            } elseif (substr($item, -4) === '.php') {
                $files[] = $item;
            }
        }

        return $files;
    }
}
