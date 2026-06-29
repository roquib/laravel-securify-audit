<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ComposerOptimizationAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Composer Optimization';
    protected $description = 'Checks if Composer autoloader is optimized';
    protected $severity    = 'low';

    public function analyze()
    {
        $issues = [];

        // Check autoload_classmap
        $classMapPath = base_path('vendor/composer/autoload_classmap.php');

        if (!file_exists($classMapPath)) {
            return $this->warning(
                'Composer classmap not found.',
                'Run: composer install --optimize-autoloader'
            );
        }

        $content    = file_get_contents($classMapPath);
        $classCount = substr_count($content, '=>');

        // If classmap is very small, it might not be optimized
        if ($classCount < 100 && $this->app->environment('production')) {
            $issues[] = 'Composer autoloader may not be optimized (only ' . $classCount . ' classes in classmap).';
        }

        // Check if --no-dev was used (vendor/autoload.php should not have dev packages)
        $installedPath = base_path('vendor/composer/installed.json');
        if (file_exists($installedPath)) {
            $installed   = json_decode(file_get_contents($installedPath), true);
            $packages    = isset($installed['packages']) ? $installed['packages'] : $installed;
            $devPackages = array_filter($packages, function ($pkg) {
                return isset($pkg['dev-requirements']) && !empty($pkg['dev-requirements']);
            });

            if (count($devPackages) > 0 && $this->app->environment('production')) {
                $issues[] = 'Dev packages may be installed in production. Use --no-dev flag.';
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: composer install --optimize-autoloader --no-dev in production.'
            );
        }

        return $this->passed('Composer autoloader is properly optimized.');
    }
}
