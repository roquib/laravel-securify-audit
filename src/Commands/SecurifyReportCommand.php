<?php

namespace Skycoder\SecurifyAudit\Commands;

use Illuminate\Console\Command;
use Skycoder\SecurifyAudit\SecurifyAudit;

class SecurifyReportCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'securify:report
                            {--type=security : Report type (security, performance, all)}';

    /**
     * @var string
     */
    protected $description = 'Generate a detailed Securify Audit report';

    /**
     * @return int
     */
    public function handle()
    {
        $this->info('📋 Generating Securify Report...');
        $this->newLine();

        $securify = new SecurifyAudit($this->laravel);
        $results  = $securify->run();
        $type     = $this->option('type');

        // Filter by type
        if ($type !== 'all') {
            $results = array_filter($results, function ($result) use ($type) {
                $analyzer = strtolower($result['analyzer']);
                return strpos($analyzer, $type) !== false;
            });
        }

        // Group by severity
        $grouped = $this->groupBySeverity($results);

        foreach (['critical', 'high', 'medium', 'low'] as $severity) {
            if (!isset($grouped[$severity]) || count($grouped[$severity]) === 0) {
                continue;
            }

            $this->line("<fg=white>═══ " . strtoupper($severity) . " (" . count($grouped[$severity]) . ") ═══</>");
            $this->newLine();

            foreach ($grouped[$severity] as $result) {
                $statusColor = $result['status'] === 'passed'
                    ? 'green'
                    : ($result['status'] === 'warning' ? 'yellow' : 'red');

                $this->line("  <fg={$statusColor}>[{$result['status']}]</> {$result['analyzer']}");
                $this->line("  <fg=gray>{$result['message']}</>");

                if (isset($result['fix']) && $result['fix']) {
                    $this->line("  <fg=yellow>Fix: {$result['fix']}</>");
                }

                $this->newLine();
            }
        }

        $this->line("🏆 Security Score: <fg=cyan>{$securify->getScore()}/100</>");
        $this->newLine();

        return 0;
    }

    /**
     * Group results by severity
     *
     * @param array $results
     * @return array
     */
    protected function groupBySeverity($results)
    {
        $grouped = [];

        foreach ($results as $result) {
            $severity = isset($result['severity'])
                ? $result['severity']
                : 'low';

            if (!isset($grouped[$severity])) {
                $grouped[$severity] = [];
            }

            $grouped[$severity][] = $result;
        }

        return $grouped;
    }
}
