<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ValidationAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Request Validation';
    protected $description = 'Checks if controllers properly validate incoming requests';
    protected $severity    = 'high';

    public function analyze()
    {
        $issues          = [];
        $controllersPath = $this->app->path('Http/Controllers');
        $files           = $this->getPhpFiles($controllersPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = basename($file);

            // Skip base controller
            if ($fileName === 'Controller.php') {
                continue;
            }

            // Check for store/update methods without validation
            $methods = ['store', 'update', 'create'];

            foreach ($methods as $method) {
                $pattern = '/function\s+' . $method . '\s*\([^)]*\)/';
                if (preg_match($pattern, $content)) {
                    $hasValidation = strpos($content, 'validate(') !== false
                        || strpos($content, 'FormRequest') !== false
                        || strpos($content, 'Validator::') !== false
                        || strpos($content, '->validated()') !== false
                        || strpos($content, 'Request $request') !== false
                            && strpos($content, 'rules()') !== false;

                    if (!$hasValidation) {
                        $issues[] = "Method '{$method}' in {$fileName} may be missing input validation.";
                        break;
                    }
                }
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                count($issues) . ' controller method(s) may be missing validation.',
                'Use Form Request classes or $request->validate() in store/update methods.'
            );
        }

        return $this->passed('Request validation looks properly implemented.');
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
