<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class FilePermissionAnalyzer extends BaseAnalyzer
{
    protected $name        = 'File Permissions';
    protected $description = 'Checks critical file and directory permissions';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues = [];

        // Check storage directory is writable
        $storagePath = storage_path();
        if (!is_writable($storagePath)) {
            $issues[] = 'Storage directory is not writable.';
        }

        // Check bootstrap/cache is writable
        $cachePath = base_path('bootstrap/cache');
        if (file_exists($cachePath) && !is_writable($cachePath)) {
            $issues[] = 'bootstrap/cache directory is not writable.';
        }

        // Check .env file permissions (Linux only)
        if (PHP_OS_FAMILY !== 'Windows') {
            $envFile = base_path('.env');
            if (file_exists($envFile)) {
                $perms = fileperms($envFile);
                $octal = substr(sprintf('%o', $perms), -4);

                // Should not be world readable (others should not have read access)
                if ((int)substr($octal, -1) >= 4) {
                    $issues[] = '.env file is world-readable (permissions: ' . $octal . ').';
                }
            }
        }

        // Check public directory does not contain sensitive files
        $sensitiveFiles = [
            '.env',
            'composer.json',
            'composer.lock',
            'phpunit.xml',
            '.gitignore',
        ];

        $publicPath = $this->app->make('path.public');
        foreach ($sensitiveFiles as $file) {
            if (file_exists($publicPath . DIRECTORY_SEPARATOR . $file)) {
                $issues[] = "Sensitive file '{$file}' found in public directory.";
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Run: chmod -R 755 storage bootstrap/cache and remove sensitive files from public.'
            );
        }

        return $this->passed('File permissions are properly configured.');
    }
}
