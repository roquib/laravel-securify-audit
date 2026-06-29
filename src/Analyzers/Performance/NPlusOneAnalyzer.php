<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class NPlusOneAnalyzer extends BaseAnalyzer
{
    protected $name        = 'N+1 Query Detection';
    protected $description = 'Checks for potential N+1 query issues in controllers and views';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues      = [];
        $appPath     = $this->app->path();
        $phpFiles    = $this->getPhpFiles($appPath);

        foreach ($phpFiles as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check for foreach with relationship access without eager loading
            if (
                preg_match('/foreach\s*\(.*->get\(\)/', $content) &&
                strpos($content, 'with(') === false &&
                strpos($content, 'load(') === false
            ) {
                $issues[] = 'Potential N+1 query in: ' . $fileName;
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                count($issues) . ' potential N+1 issue(s) detected.',
                'Use eager loading with ->with("relation") to avoid N+1 queries.'
            );
        }

        return $this->passed('No obvious N+1 query issues detected.');
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
