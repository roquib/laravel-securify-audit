<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class PolicyAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Authorization Policy';
    protected $description = 'Checks if routes have proper authorization policies';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues          = [];
        $controllersPath = $this->app->path('Http/Controllers');
        $files           = $this->getPhpFiles($controllersPath);
        $policiesPath    = $this->app->path('Policies');
        $hasPolicies     = file_exists($policiesPath) &&
            count(glob($policiesPath . DIRECTORY_SEPARATOR . '*.php') ?: []) > 0;

        if (!$hasPolicies) {
            return $this->warning(
                'No Policy classes found in app/Policies.',
                'Create Policy classes using: php artisan make:policy ModelPolicy --model=Model'
            );
        }

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = basename($file);

            // Skip base controller
            if ($fileName === 'Controller.php') {
                continue;
            }

            // Check resource controllers without authorization
            $hasAuthorize = strpos($content, '$this->authorize') !== false
                || strpos($content, 'Gate::') !== false
                || strpos($content, 'can(') !== false
                || strpos($content, 'cannot(') !== false
                || strpos($content, 'authorizeResource') !== false
                || strpos($content, 'middleware(\'can') !== false;

            // Check if it's a resource controller
            $isResource = strpos($content, 'function index') !== false
                && strpos($content, 'function store') !== false
                && strpos($content, 'function update') !== false;

            if ($isResource && !$hasAuthorize) {
                $issues[] = "Resource controller '{$fileName}' may be missing authorization.";
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                count($issues) . ' controller(s) may be missing authorization.',
                'Use $this->authorize() or authorizeResource() in controllers.'
            );
        }

        return $this->passed('Authorization policies appear properly implemented.');
    }

    protected function getPhpFiles($path)
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
                $files = array_merge($files, $this->getPhpFiles($item));
            } elseif (substr($item, -4) === '.php') {
                $files[] = $item;
            }
        }

        return $files;
    }
}
