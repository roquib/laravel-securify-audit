<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class MassAssignmentAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Mass Assignment Protection';
    protected $description = 'Checks Eloquent models for mass assignment vulnerabilities';
    protected $severity    = 'critical';

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

            // Check for $guarded = []
            if (preg_match('/protected\s+\$guarded\s*=\s*\[\s*\]/', $content)) {
                $issues[] = "Model '{$fileName}' has \$guarded = [] (no protection).";
            }

            // Check for missing fillable AND guarded
            $hasFillable = strpos($content, '$fillable') !== false;
            $hasGuarded  = strpos($content, '$guarded') !== false;

            if (!$hasFillable && !$hasGuarded) {
                $issues[] = "Model '{$fileName}' has no \$fillable or \$guarded defined.";
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                implode(' | ', $issues),
                'Define $fillable with allowed fields OR use $guarded = ["id"] in your models.'
            );
        }

        return $this->passed('Mass assignment protection is properly configured.');
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
