<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class BackupSecurityAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Backup File Security';
    protected $description = 'Checks for sensitive backup files in public directory';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues     = [];
        $publicPath = $this->app->make('path.public');

        // Dangerous file extensions in public
        $dangerousExtensions = [
            '*.sql', '*.sql.gz', '*.sql.zip',
            '*.zip', '*.tar', '*.tar.gz', '*.tar.bz2',
            '*.bak', '*.backup',
            '*.log',
            '*.db', '*.sqlite',
            '*.pem', '*.key', '*.p12', '*.pfx',
        ];

        foreach ($dangerousExtensions as $pattern) {
            $files = glob($publicPath . DIRECTORY_SEPARATOR . $pattern);
            if ($files && count($files) > 0) {
                foreach ($files as $file) {
                    $issues[] = 'Sensitive file found in public: ' . basename($file);
                }
            }
        }

        // Check root directory too
        $rootDangerousFiles = [
            '.git',
            'phpinfo.php',
            'info.php',
            'test.php',
            'debug.php',
        ];

        foreach ($rootDangerousFiles as $file) {
            if (file_exists($publicPath . DIRECTORY_SEPARATOR . $file)) {
                $issues[] = "Dangerous file/directory found in public: {$file}";
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Remove all backup, database, and sensitive files from public directory immediately.'
            );
        }

        return $this->passed('No sensitive backup files found in public directory.');
    }
}
