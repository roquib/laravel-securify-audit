<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class SqlInjectionAnalyzer extends BaseAnalyzer
{
    protected $name        = 'SQL Injection Protection';
    protected $description = 'Scans for potential SQL injection vulnerabilities in controllers';
    protected $severity    = 'critical';

    public function analyze()
    {
        $appPath     = $this->app->path();
        $vulnerable  = [];
        $phpFiles    = $this->getPhpFiles($appPath);

        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);
            if ($this->hasRawQueryWithInput($content)) {
                $vulnerable[] = str_replace($appPath, 'app', $file);
            }
        }

        if (count($vulnerable) > 0) {
            return $this->failed(
                'Potential SQL injection vulnerabilities found in ' . count($vulnerable) . ' file(s): ' . implode(', ', $vulnerable),
                'Use Eloquent ORM or PDO prepared statements instead of raw queries with user input.'
            );
        }

        return $this->passed('No obvious SQL injection vulnerabilities detected.');
    }

    /**
     * Get all PHP files recursively
     *
     * @param string $path
     * @return array
     */
    protected function getPhpFiles($path)
    {
        $files  = [];
        $items  = glob($path . DIRECTORY_SEPARATOR . '*');

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

    /**
     * Check for raw queries with user input
     *
     * @param string $content
     * @return bool
     */
    protected function hasRawQueryWithInput($content)
    {
        $dangerousPatterns = [
            '/DB::select\s*\(\s*["\'].*\$_(GET|POST|REQUEST)/',
            '/DB::statement\s*\(\s*["\'].*\$_(GET|POST|REQUEST)/',
            '/->whereRaw\s*\(\s*["\'].*\$_(GET|POST|REQUEST)/',
            '/->selectRaw\s*\(\s*["\'].*\$_(GET|POST|REQUEST)/',
            '/DB::select\s*\(.*\.\s*\$request->/',
            '/->whereRaw\s*\(.*\.\s*\$request->/',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }
}
