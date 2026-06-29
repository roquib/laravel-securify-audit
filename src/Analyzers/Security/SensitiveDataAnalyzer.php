<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class SensitiveDataAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Sensitive Data Exposure';
    protected $description = 'Checks for hardcoded sensitive data in codebase';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        $patterns = [
            'Hardcoded password'   => '/["\']password["\']\s*=>\s*["\'][^"\']+["\']/',
            'Hardcoded API key'    => '/(api_key|apikey|api_secret)\s*=\s*["\'][a-zA-Z0-9]{20,}["\']/',
            'Hardcoded AWS key'    => '/AKIA[0-9A-Z]{16}/',
            'Hardcoded JWT secret' => '/(jwt_secret|JWT_SECRET)\s*=\s*["\'][^"\']+["\']/',
        ];

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            foreach ($patterns as $label => $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = $label . ' found in: ' . $fileName;
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Move all sensitive data to .env file and use config() or env() to access them.'
            );
        }

        return $this->passed('No hardcoded sensitive data detected.');
    }

    /**
     * Get PHP files recursively
     *
     * @param string $path
     * @return array
     */
    protected function getPhpFiles($path)
    {
        $files = [];
        $items = glob($path . DIRECTORY_SEPARATOR . '*');

        if (!$items) {
            return $files;
        }

        // Skip Model files for password check
        $skipFiles = ['User.php'];

        foreach ($items as $item) {
            if (is_dir($item)) {
                $files = array_merge($files, $this->getPhpFiles($item));
            } elseif (substr($item, -4) === '.php') {
                if (!in_array(basename($item), $skipFiles)) {
                    $files[] = $item;
                }
            }
        }

        return $files;
    }
}
