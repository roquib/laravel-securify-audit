<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ClickjackingAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Clickjacking Protection';
    protected $description = 'Checks if X-Frame-Options header is set to prevent clickjacking';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues         = [];
        $appPath        = $this->app->path();
        $middlewarePath = $appPath . '/Http/Middleware';
        $xFrameFound    = false;

        // Check middleware files
        $files = glob($middlewarePath . DIRECTORY_SEPARATOR . '*.php');
        if ($files) {
            foreach ($files as $file) {
                $content = file_get_contents($file);
                if (
                    strpos($content, 'X-Frame-Options') !== false ||
                    strpos($content, 'x-frame-options') !== false
                ) {
                    $xFrameFound = true;
                    break;
                }
            }
        }

        // Check bootstrap/app.php
        $bootstrapApp = base_path('bootstrap/app.php');
        if (file_exists($bootstrapApp)) {
            $content     = file_get_contents($bootstrapApp);
            $xFrameFound = $xFrameFound ||
                strpos($content, 'X-Frame-Options') !== false;
        }

        // Check kernel.php
        $kernelPath = $appPath . '/Http/Kernel.php';
        if (file_exists($kernelPath)) {
            $content     = file_get_contents($kernelPath);
            $xFrameFound = $xFrameFound ||
                strpos($content, 'X-Frame-Options') !== false ||
                strpos($content, 'FrameGuard') !== false;
        }

        if (!$xFrameFound) {
            $issues[] = 'X-Frame-Options header not configured. Application vulnerable to clickjacking.';
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Add X-Frame-Options: SAMEORIGIN header in middleware or use Content-Security-Policy frame-ancestors directive.'
            );
        }

        return $this->passed('Clickjacking protection is properly configured.');
    }
}
