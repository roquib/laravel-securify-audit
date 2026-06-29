<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ModelScopeAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Model Scope Security';
    protected $description = 'Checks if SoftDelete models have proper global scopes';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues     = [];
        $modelsPath = $this->app->path('Models');

        if (!file_exists($modelsPath)) {
            $modelsPath = $this->app->path();
        }

        $files = $this->getPhpFiles($modelsPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = basename($file);

            // Skip non-model files
            if (
                strpos($content, 'extends Model') === false &&
                strpos($content, 'extends Authenticatable') === false
            ) {
                continue;
            }

            // Check SoftDeletes without proper scope
            $hasSoftDeletes = strpos($content, 'SoftDeletes') !== false;
            $hasGlobalScope = strpos($content, 'addGlobalScope') !== false;
            $hasWithTrashed = strpos($content, 'withTrashed') !== false;

            if ($hasSoftDeletes && $hasWithTrashed && !$hasGlobalScope) {
                $issues[] = "Model '{$fileName}' uses withTrashed() without a global scope restriction.";
            }

            // Check for missing deleted_at in casts
            if ($hasSoftDeletes && strpos($content, 'deleted_at') === false) {
                $issues[] = "Model '{$fileName}' uses SoftDeletes but deleted_at not in \$casts.";
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Add deleted_at to $casts as datetime and review withTrashed() usage in models.'
            );
        }

        return $this->passed('Model scopes are properly configured.');
    }

    protected function getPhpFiles($path)
    {
        $files = [];
        $items = glob($path . DIRECTORY_SEPARATOR . '*.php');

        if ($items) {
            $files = array_merge($files, $items);
        }

        $dirs = glob($path . DIRECTORY_SEPARATOR . '*', GLOB_ONLYDIR);
        if ($dirs) {
            foreach ($dirs as $dir) {
                $files = array_merge($files, $this->getPhpFiles($dir));
            }
        }

        return $files;
    }
}
