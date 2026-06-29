<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class AssetOptimizationAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Asset Optimization';
    protected $description = 'Checks if frontend assets are properly optimized';
    protected $severity    = 'low';

    public function analyze()
    {
        $issues     = [];
        $publicPath = $this->app->make('path.public');

        // Check if build directory exists (Vite)
        $viteBuild  = $publicPath . '/build';
        $mixPublic  = $publicPath . '/js/app.js';

        $hasBuild = file_exists($viteBuild) || file_exists($mixPublic);

        if (!$hasBuild && $this->app->environment('production')) {
            $issues[] = 'No compiled assets found. Run npm run build for production.';
        }

        // Check for unminified JS in production
        if (file_exists($mixPublic)) {
            $jsSize = filesize($mixPublic) / 1024; // KB
            if ($jsSize > 1000) {
                $issues[] = 'app.js is large (' . round($jsSize, 1) . ' KB). Consider code splitting.';
            }
        }

        // Check manifest file exists (versioning)
        $viteManifest = $publicPath . '/build/manifest.json';
        $mixManifest  = $publicPath . '/mix-manifest.json';

        $hasManifest = file_exists($viteManifest) || file_exists($mixManifest);

        if (!$hasManifest && $this->app->environment('production')) {
            $issues[] = 'Asset manifest not found. Assets may not be versioned/cache-busted.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: npm run build. Use Vite or Mix for asset compilation and versioning.'
            );
        }

        return $this->passed('Assets appear to be properly optimized.');
    }
}
