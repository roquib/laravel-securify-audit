<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ViewCacheAnalyzer extends BaseAnalyzer
{
    protected $name        = 'View Cache';
    protected $description = 'Checks if Blade views are cached for production';
    protected $severity    = 'low';

    public function analyze()
    {
        $issues        = [];
        $viewCachePath = $this->app->make('path.storage') . '/framework/views';

        if (!file_exists($viewCachePath)) {
            if ($this->app->environment('production')) {
                $issues[] = 'View cache directory does not exist in production.';
            }
        } else {
            $cachedFiles = glob($viewCachePath . DIRECTORY_SEPARATOR . '*.php');
            $cachedCount = $cachedFiles ? count($cachedFiles) : 0;

            // Get total blade files
            $viewsPath  = resource_path('views');
            $bladeFiles = $this->getBladeFiles($viewsPath);
            $totalViews = count($bladeFiles);

            if ($cachedCount === 0 && $this->app->environment('production')) {
                $issues[] = 'No cached views found in production. Run php artisan view:cache.';
            } elseif ($totalViews > 0 && $cachedCount < ($totalViews * 0.5)) {
                $issues[] = "Only {$cachedCount}/{$totalViews} views are cached.";
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: php artisan view:cache to pre-compile all Blade templates.'
            );
        }

        return $this->passed('View cache is properly configured.');
    }

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
