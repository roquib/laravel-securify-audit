<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class ErrorHandlingAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Error Handling';
    protected $description = 'Checks if custom error pages and proper error handling is configured';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues    = [];
        $viewsPath = resource_path('views/errors');

        // Check custom error pages
        $errorPages = ['404', '500', '403', '419', '429'];
        $missing    = [];

        foreach ($errorPages as $code) {
            if (!file_exists($viewsPath . DIRECTORY_SEPARATOR . $code . '.blade.php')) {
                $missing[] = $code;
            }
        }

        if (count($missing) > 0) {
            $issues[] = 'Missing custom error pages: ' . implode(', ', $missing) . '.';
        }

        // Check exception handler
        $handlerPath = $this->app->path('Exceptions/Handler.php');
        if (file_exists($handlerPath)) {
            $content = file_get_contents($handlerPath);

            // Check if sensitive info is being logged
            if (strpos($content, 'dd(') !== false || strpos($content, 'var_dump(') !== false) {
                $issues[] = 'Debug output (dd/var_dump) found in Exception Handler.';
            }
        }

        // Check if APP_DEBUG false in production
        if (config('app.debug') && $this->app->environment('production')) {
            $issues[] = 'APP_DEBUG is true in production - error details exposed to users.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Create custom error pages in resources/views/errors/ and disable APP_DEBUG in production.'
            );
        }

        return $this->passed('Error handling is properly configured.');
    }
}
