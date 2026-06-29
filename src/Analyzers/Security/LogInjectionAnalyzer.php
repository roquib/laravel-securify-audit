<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class LogInjectionAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Log Injection';
    protected $description = 'Checks for log injection vulnerabilities';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check Log calls with user input directly
            $patterns = [
                '/Log::(info|error|warning|debug|critical)\s*\(\s*\$request->/',
                '/Log::(info|error|warning|debug|critical)\s*\(\s*\$_GET/',
                '/Log::(info|error|warning|debug|critical)\s*\(\s*\$_POST/',
                '/\$this->log\s*\(\s*\$request->/',
                '/logger\s*\(\s*\$request->/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential log injection with user input in: {$fileName}";
                    break;
                }
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                count($issues) . ' potential log injection issue(s) found.',
                'Sanitize user input before logging. Remove newlines: str_replace(["\n", "\r"], "", $input).'
            );
        }

        return $this->passed('No log injection vulnerabilities detected.');
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
