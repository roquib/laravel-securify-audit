<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class OpcacheAnalyzer extends BaseAnalyzer
{
    protected $name        = 'PHP OPcache';
    protected $description = 'Checks if PHP OPcache is enabled for better performance';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues = [];

        // Check if OPcache is available
        if (!function_exists('opcache_get_status')) {
            return $this->warning(
                'PHP OPcache extension is not available.',
                'Enable OPcache in php.ini: opcache.enable=1'
            );
        }

        $status = opcache_get_status(false);

        if ($status === false || !isset($status['opcache_enabled'])) {
            return $this->warning(
                'Unable to get OPcache status.',
                'Check your PHP configuration for OPcache settings.'
            );
        }

        if (!$status['opcache_enabled']) {
            $issues[] = 'PHP OPcache is disabled.';
        }

        if (isset($status['memory_usage'])) {
            $usedMemory  = $status['memory_usage']['used_memory'];
            $freeMemory  = $status['memory_usage']['free_memory'];
            $totalMemory = $usedMemory + $freeMemory;
            $usagePercent = ($totalMemory > 0) ? ($usedMemory / $totalMemory) * 100 : 0;

            if ($usagePercent > 90) {
                $issues[] = 'OPcache memory usage is at ' . round($usagePercent, 1) . '%. Consider increasing opcache.memory_consumption.';
            }
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Enable OPcache in php.ini: opcache.enable=1, opcache.memory_consumption=256'
            );
        }

        return $this->passed('PHP OPcache is enabled and working properly.');
    }
}
