<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class OpenRedirectAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Open Redirect';
    protected $description = 'Checks for potential open redirect vulnerabilities';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check redirect with user input directly
            $patterns = [
                '/redirect\(\s*\$request->/',
                '/redirect\(\s*\$_GET/',
                '/redirect\(\s*\$_POST/',
                '/return\s+redirect\(\s*request\(\)->/',
                '/Redirect::to\(\s*\$request->/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential open redirect with user input in: {$fileName}";
                    break;
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Validate redirect URLs against a whitelist. Never redirect to user-supplied URLs directly.'
            );
        }

        return $this->passed('No open redirect vulnerabilities detected.');
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
