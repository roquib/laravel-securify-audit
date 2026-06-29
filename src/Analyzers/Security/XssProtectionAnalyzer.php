<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class XssProtectionAnalyzer extends BaseAnalyzer
{
    protected $name        = 'XSS Protection';
    protected $description = 'Checks for potential Cross-Site Scripting vulnerabilities';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues      = [];
        $viewsPath   = resource_path('views');
        $phpFiles    = $this->getBladeFiles($viewsPath);
        $rawOutputs  = 0;

        foreach ($phpFiles as $file) {
            $content = file_get_contents($file);

            // Check for unescaped output {!! !!}
            preg_match_all('/\{!!\s*\$[a-zA-Z_]+\s*!!\}/', $content, $matches);
            $rawOutputs += count($matches[0]);
        }

        if ($rawOutputs > 0) {
            $issues[] = $rawOutputs . ' unescaped output(s) found using {!! !!} syntax in Blade templates.';
        }

        // Check for innerHTML in JS files
        $jsPath    = public_path('js');
        $jsFiles   = file_exists($jsPath) ? glob($jsPath . DIRECTORY_SEPARATOR . '*.js') : [];
        $innerHtml = 0;

        if ($jsFiles) {
            foreach ($jsFiles as $file) {
                $content    = file_get_contents($file);
                preg_match_all('/innerHTML\s*=/', $content, $matches);
                $innerHtml += count($matches[0]);
            }
        }

        if ($innerHtml > 0) {
            $issues[] = $innerHtml . ' innerHTML assignment(s) found in JS files. Use textContent instead.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Use {{ }} instead of {!! !!} in Blade templates unless you trust the content.'
            );
        }

        return $this->passed('No obvious XSS vulnerabilities detected.');
    }

    /**
     * Get all Blade files recursively
     *
     * @param string $path
     * @return array
     */
    protected function getBladeFiles($path)
    {
        $files = [];

        if (!file_exists($path)) {
            return $files;
        }

        $items = glob($path . DIRECTORY_SEPARATOR . '*');

        if (!$items) {
            return $files;
        }

        foreach ($items as $item) {
            if (is_dir($item)) {
                $files = array_merge($files, $this->getBladeFiles($item));
            } elseif (substr($item, -10) === '.blade.php') {
                $files[] = $item;
            }
        }

        return $files;
    }
}
