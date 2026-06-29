<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class MemoryUsageAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Memory Usage';
    protected $description = 'Checks PHP memory configuration and usage';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check PHP memory limit
        $memoryLimit = ini_get('memory_limit');
        $memoryBytes = $this->convertToBytes($memoryLimit);

        if ($memoryBytes < 128 * 1024 * 1024) { // Less than 128MB
            $issues[] = 'PHP memory_limit is too low (' . $memoryLimit . '). Recommended minimum is 128M.';
        }

        if ($memoryBytes > 512 * 1024 * 1024) { // More than 512MB
            $issues[] = 'PHP memory_limit is very high (' . $memoryLimit . '). Check for memory leaks.';
        }

        // Check current memory usage
        $currentUsage   = memory_get_usage(true);
        $currentUsageMb = round($currentUsage / 1024 / 1024, 2);

        if ($currentUsageMb > 64) {
            $issues[] = 'High memory usage at bootstrap: ' . $currentUsageMb . ' MB.';
        }

        // Check max memory peak
        $peakUsage   = memory_get_peak_usage(true);
        $peakUsageMb = round($peakUsage / 1024 / 1024, 2);

        if ($peakUsageMb > 100) {
            $issues[] = 'High peak memory usage: ' . $peakUsageMb . ' MB.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Optimize memory usage: use chunking for large datasets, increase memory_limit if needed.'
            );
        }

        return $this->passed('Memory usage is within acceptable limits (' . $currentUsageMb . ' MB).');
    }

    protected function convertToBytes($value)
    {
        $value = trim($value);
        $unit  = strtolower(substr($value, -1));
        $num   = (int) $value;

        switch ($unit) {
            case 'g':
                return $num * 1024 * 1024 * 1024;
            case 'm':
                return $num * 1024 * 1024;
            case 'k':
                return $num * 1024;
            default:
                return $num;
        }
    }
}
