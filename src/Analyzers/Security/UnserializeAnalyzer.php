<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class UnserializeAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Unsafe Unserialize';
    protected $description = 'Checks for dangerous unserialize() usage with user input';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check for unserialize with user input
            $patterns = [
                '/unserialize\s*\(\s*\$request->/',
                '/unserialize\s*\(\s*\$_GET/',
                '/unserialize\s*\(\s*\$_POST/',
                '/unserialize\s*\(\s*\$_COOKIE/',
                '/unserialize\s*\(\s*\$_REQUEST/',
                '/unserialize\s*\([^)]*->input\(/',
                '/unserialize\s*\([^)]*->get\(/',
            ];

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $issues[] = "Unsafe unserialize() with user input in: {$fileName}";
                    break;
                }
            }

            // Check for unserialize without allowed_classes
            if (
                preg_match('/unserialize\s*\(/', $content) &&
                strpos($content, 'allowed_classes') === false
            ) {
                // Only flag if user input is nearby
                if (
                    strpos($content, '$request') !== false ||
                    strpos($content, 'input(') !== false
                ) {
                    $issues[] = "unserialize() without allowed_classes restriction in: {$fileName}";
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Never unserialize user input. Use JSON instead. If unavoidable, use allowed_classes option.'
            );
        }

        return $this->passed('No unsafe unserialize() usage detected.');
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
