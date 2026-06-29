<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class AutoloaderOptimizationAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Autoloader Optimization';
    protected $description = 'Checks if Composer autoloader is optimized for production';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check autoload_classmap size
        $classMapPath = base_path('vendor/composer/autoload_classmap.php');

        if (!file_exists($classMapPath)) {
            return $this->warning(
                'Composer classmap file not found.',
                'Run: composer dump-autoload --optimize'
            );
        }

        $content    = file_get_contents($classMapPath);
        $classCount = substr_count($content, '=>');

        // Check autoload_psr4 - if large, classmap optimization helps
        $psr4Path = base_path('vendor/composer/autoload_psr4.php');
        if (file_exists($psr4Path)) {
            $psr4Content = file_get_contents($psr4Path);
            $psr4Count   = substr_count($psr4Content, '=>');

            if ($psr4Count > 50 && $classCount < 500 && $this->app->environment('production')) {
                $issues[] = 'Autoloader has ' . $psr4Count . ' PSR-4 namespaces but low classmap entries. Consider optimizing.';
            }
        }

        // Check for optimized autoloader flag
        $installedPath = base_path('vendor/composer/installed.php');
        if (!file_exists($installedPath) && $this->app->environment('production')) {
            $issues[] = 'Composer installed.php not found. Run composer install --optimize-autoloader.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Run: composer install --optimize-autoloader --classmap-authoritative in production.'
            );
        }

        return $this->passed('Autoloader is properly optimized.');
    }
}
