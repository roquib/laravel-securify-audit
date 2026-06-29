<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class EnvExposureAnalyzer extends BaseAnalyzer
{
    protected $name = 'Env File Exposure';
    protected $description = 'Checks if .env file is publicly accessible';
    protected $severity = 'critical';

    public function analyze()
    {
        $publicPath = $this->app->make('path.public');
        $envInPublic = file_exists($publicPath . DIRECTORY_SEPARATOR . '.env');

        if ($envInPublic) {
            return $this->failed(
                '.env file is exposed in public directory!',
                'Remove .env from public folder immediately and add it to .gitignore.'
            );
        }

        // Check if .env is in .gitignore
        $gitignorePath = base_path('.gitignore');
        if (file_exists($gitignorePath)) {
            $gitignore = file_get_contents($gitignorePath);
            if (strpos($gitignore, '.env') === false) {
                return $this->warning(
                    '.env file is not listed in .gitignore.',
                    'Add .env to your .gitignore file to prevent accidental commits.'
                );
            }
        }

        return $this->passed('.env file is properly protected.');
    }
}
