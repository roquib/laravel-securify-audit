<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class PathTraversalAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Path Traversal';
    protected $description = 'Checks for directory traversal vulnerabilities';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check file operations with user input
            $fileOps = [
                'file_get_contents',
                'file_put_contents',
                'fopen',
                'readfile',
                'include',
                'require',
                'Storage::get',
                'Storage::put',
            ];

            foreach ($fileOps as $op) {
                $pattern = '/' . preg_quote($op, '/') . '\s*\([^)]*\$request->/';
                if (preg_match($pattern, $content)) {
                    $issues[] = "Potential path traversal using {$op}() with user input in: {$fileName}";
                    break;
                }

                $pattern2 = '/' . preg_quote($op, '/') . '\s*\([^)]*\$_GET/';
                if (preg_match($pattern2, $content)) {
                    $issues[] = "Potential path traversal using {$op}() with GET input in: {$fileName}";
                    break;
                }
            }

            // Check for basename() missing (protection)
            if (
                strpos($content, 'file_get_contents') !== false &&
                strpos($content, '$request->') !== false &&
                strpos($content, 'basename(') === false &&
                strpos($content, 'realpath(') === false
            ) {
                $issues[] = "File operation without basename/realpath protection in: {$fileName}";
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                count($issues) . ' path traversal vulnerability(ies) found.',
                'Use basename() or realpath() when handling user-supplied file paths.'
            );
        }

        return $this->passed('No path traversal vulnerabilities detected.');
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
