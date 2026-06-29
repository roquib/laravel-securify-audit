<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class CommandInjectionAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Command Injection';
    protected $description = 'Checks for potential command injection vulnerabilities';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        $dangerousFunctions = [
            'exec',
            'shell_exec',
            'system',
            'passthru',
            'popen',
            'proc_open',
        ];

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            foreach ($dangerousFunctions as $func) {
                // Check if function is used with user input
                $pattern = '/' . $func . '\s*\(\s*.*\$(request|_GET|_POST|_REQUEST)/';
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential command injection using {$func}() with user input in: {$fileName}";
                }

                // Check for concatenation with user input
                $pattern2 = '/' . $func . '\s*\([^)]*\.\s*\$(request|input)/';
                if (preg_match($pattern2, $content)) {
                    $issues[] = "Potential command injection using {$func}() with concatenated input in: {$fileName}";
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Never pass user input to exec/shell_exec/system. Use escapeshellarg() if unavoidable.'
            );
        }

        return $this->passed('No command injection vulnerabilities detected.');
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
