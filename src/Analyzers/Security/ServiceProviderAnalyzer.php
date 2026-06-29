<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ServiceProviderAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Service Provider Security';
    protected $description = 'Checks service providers for security misconfigurations';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues           = [];
        $providersPath    = $this->app->path('Providers');

        if (!file_exists($providersPath)) {
            return $this->passed('No custom service providers found.');
        }

        $files = glob($providersPath . DIRECTORY_SEPARATOR . '*.php');

        if (!$files) {
            return $this->passed('No custom service providers found.');
        }

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = basename($file);

            // Check for hardcoded credentials in providers
            $patterns = [
                '/["\']password["\']\s*=>\s*["\'][^"\']+["\']/',
                '/["\']secret["\']\s*=>\s*["\'][^"\']+["\']/',
                '/["\']key["\']\s*=>\s*["\'][a-zA-Z0-9]{20,}["\']/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential hardcoded credentials in: {$fileName}";
                    break;
                }
            }

            // Check for dd() or var_dump() in providers
            if (
                strpos($content, 'dd(') !== false ||
                strpos($content, 'var_dump(') !== false
            ) {
                $issues[] = "Debug output found in provider: {$fileName}";
            }

            // Check Gate::before with always true
            if (preg_match('/Gate::before\s*\(.*return\s+true/', $content)) {
                $issues[] = "Gate::before() always returns true in: {$fileName}. This bypasses all authorization!";
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Remove hardcoded credentials and debug output from service providers. Review Gate::before() usage.'
            );
        }

        return $this->passed('Service providers look properly configured.');
    }
}
