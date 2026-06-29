<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class DatabaseIndexAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Database Index';
    protected $description = 'Checks migrations for missing indexes on foreign keys';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues         = [];
        $migrationPath  = database_path('migrations');
        $files          = glob($migrationPath . DIRECTORY_SEPARATOR . '*.php');

        if (!$files) {
            return $this->passed('No migrations found to analyze.');
        }

        foreach ($files as $file) {
            $content  = file_get_contents($file);
            $fileName = basename($file);

            // Find foreign keys without indexes
            preg_match_all('/->foreign\(["\']([^"\']+)["\']\)/', $content, $foreignKeys);
            preg_match_all('/->index\(["\']([^"\']+)["\']\)/', $content, $indexes);

            $foreignKeyColumns = $foreignKeys[1];
            $indexedColumns    = $indexes[1];

            foreach ($foreignKeyColumns as $fk) {
                if (!in_array($fk, $indexedColumns)) {
                    $issues[] = "Foreign key '{$fk}' missing index in: {$fileName}";
                }
            }
        }

        if (count($issues) > 5) {
            return $this->warning(
                count($issues) . ' foreign key(s) may be missing indexes.',
                'Add ->index() after ->foreign() calls in your migrations for better performance.'
            );
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', array_slice($issues, 0, 3)) . (count($issues) > 3 ? '...' : ''),
                'Add ->index() after ->foreign() calls in your migrations.'
            );
        }

        return $this->passed('Database indexes look properly configured.');
    }
}
