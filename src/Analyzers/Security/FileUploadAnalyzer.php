<?php

namespace Skycoder\SecurifyAudit\Analyzers\Security;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class FileUploadAnalyzer extends BaseAnalyzer
{
    protected $name        = 'File Upload Security';
    protected $description = 'Checks for insecure file upload implementations';
    protected $severity    = 'critical';

    public function analyze()
    {
        $issues  = [];
        $appPath = $this->app->path();
        $files   = $this->getPhpFiles($appPath);

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = str_replace($appPath, 'app', $file);

            // Check for file upload without validation
            if (strpos($content, '->file(') !== false || strpos($content, 'hasFile(') !== false) {

                // Check if mime validation exists
                $hasMimeCheck = strpos($content, 'mimes:') !== false
                    || strpos($content, 'mimetypes:') !== false
                    || strpos($content, 'getMimeType') !== false;

                // Check if size validation exists
                $hasSizeCheck = strpos($content, 'max:') !== false
                    || strpos($content, 'size:') !== false;

                if (!$hasMimeCheck) {
                    $issues[] = "File upload without MIME type validation in: {$fileName}";
                }

                if (!$hasSizeCheck) {
                    $issues[] = "File upload without size validation in: {$fileName}";
                }

                // Check for dangerous extensions allowed
                if (preg_match('/mimes:.*\b(php|exe|sh|bat|cmd)\b/', $content)) {
                    $issues[] = "Dangerous file extension allowed in upload validation in: {$fileName}";
                }
            }
        }

        if (count($issues) > 0) {
            return $this->failed(
                count($issues) . ' file upload security issue(s) found.',
                'Always validate file MIME type, size, and extension. Never allow php, exe, sh extensions.'
            );
        }

        return $this->passed('No obvious file upload security issues detected.');
    }

    protected function getPhpFiles($path)
    {
        $files = [];
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
