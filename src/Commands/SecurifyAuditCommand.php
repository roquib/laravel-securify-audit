<?php

namespace Skycoder\SecurifyAudit\Commands;

use Illuminate\Console\Command;
use Skycoder\SecurifyAudit\SecurifyAudit;

class SecurifyAuditCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'securify:audit
                            {--format=cli : Output format (cli, json)}
                            {--only-failed : Show only failed checks}
                            {--only-warnings : Show only warnings}
                            {--severity= : Filter by severity (critical, high, medium, low)}
                            {--save : Save report to storage/logs/securify-audit.log}';

    /**
     * @var string
     */
    protected $description = 'Run Laravel Security & Audit Scanner by Skycoder';

    /**
     * @return int
     */
    public function handle()
    {
        $this->showBanner();

        try {
            $securify = new SecurifyAudit($this->laravel);

            $this->info('Running security audit...');
            $this->newLine();

            $results = $securify->run();
            $format  = $this->option('format');

            if ($format === 'json') {
                $this->outputJson($results, $securify);
                return 0;
            }

            $this->outputCli($results, $securify);

            if ($this->option('save')) {
                $this->saveReport($results, $securify);
            }

            return count($securify->getFailed()) > 0 ? 1 : 0;

        } catch (\Exception $e) {
            $this->error('Error: ' . $e->getMessage());
            $this->error('File: ' . $e->getFile() . ':' . $e->getLine());
            return 1;
        }
    }

    /**
     * Show banner
     *
     * @return void
     */
    protected function showBanner()
    {
        $this->newLine();
        $this->line('  <fg=cyan>  ██████╗ ██╗  ██╗██╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗ </>');
        $this->line('  <fg=cyan> ██╔════╝ ██║ ██╔╝╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗</>');
        $this->line('  <fg=cyan> ╚█████╗  █████╔╝  ╚████╔╝ ██║     ██║   ██║██║  ██║█████╗  ██████╔╝</>');
        $this->line('  <fg=cyan>  ╚═══██╗ ██╔═██╗   ╚██╔╝  ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗</>');
        $this->line('  <fg=cyan> ██████╔╝ ██║  ██╗   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║</>');
        $this->line('  <fg=cyan> ╚═════╝  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝</>');
        $this->newLine();
        $this->line('  <fg=yellow>           Laravel Securify Audit — Security & Performance Scanner</>');
        $this->line('  <fg=gray>                     by Skycoder | github.com/skycoder026</>');
        $this->newLine();
        $this->line('  <fg=cyan>' . str_repeat('─', 72) . '</>');
        $this->newLine();
    }

    /**
     * Output results in CLI format
     *
     * @param array $results
     * @param SecurifyAudit $securify
     * @return void
     */
    protected function outputCli($results, SecurifyAudit $securify)
    {
        $onlyFailed   = $this->option('only-failed');
        $onlyWarnings = $this->option('only-warnings');
        $severity     = $this->option('severity');

        foreach ($results as $result) {
            // Filter by status
            if ($onlyFailed && $result['status'] !== 'failed') {
                continue;
            }

            if ($onlyWarnings && $result['status'] !== 'warning') {
                continue;
            }

            // Filter by severity
            if (
                $severity &&
                strtolower($result['severity'] ?? '') !== strtolower($severity)
            ) {
                continue;
            }

            $this->printResult($result);
        }

        $this->newLine();
        $this->printSummary($securify);
    }

    /**
     * Print single result
     *
     * @param array $result
     * @return void
     */
    protected function printResult($result)
    {
        $status   = $result['status'];
        $analyzer = $result['analyzer'];
        $message  = $result['message'];
        $severity = isset($result['severity'])
            ? strtoupper($result['severity'])
            : 'INFO';

        switch ($status) {
            case 'passed':
                $statusText = '<fg=green>[PASS]</>';
                $sevColor   = '<fg=green>[' . $severity . ']</>';
                $nameColor  = '<fg=green>' . $analyzer . '</>';
                $msgColor   = '<fg=green>' . $message . '</>';
                break;
            case 'failed':
                $statusText = '<fg=red>[FAIL]</>';
                $sevColor   = '<fg=red>[' . $severity . ']</>';
                $nameColor  = '<fg=red>' . $analyzer . '</>';
                $msgColor   = '<fg=white>' . $message . '</>';
                break;
            case 'warning':
                $statusText = '<fg=yellow>[WARN]</>';
                $sevColor   = '<fg=yellow>[' . $severity . ']</>';
                $nameColor  = '<fg=yellow>' . $analyzer . '</>';
                $msgColor   = '<fg=white>' . $message . '</>';
                break;
            default:
                $statusText = '<fg=blue>[INFO]</>';
                $sevColor   = '<fg=blue>[' . $severity . ']</>';
                $nameColor  = '<fg=blue>' . $analyzer . '</>';
                $msgColor   = '<fg=white>' . $message . '</>';
        }

        $this->line("  {$statusText} {$sevColor} {$nameColor}");
        $this->line("       {$msgColor}");

        if (
            isset($result['fix']) &&
            $result['fix'] &&
            $status !== 'passed'
        ) {
            $this->line("       <fg=yellow>Fix: {$result['fix']}</>");
        }

        $this->newLine();
    }

    /**
     * Print summary with weighted score
     *
     * @param SecurifyAudit $securify
     * @return void
     */
    protected function printSummary(SecurifyAudit $securify)
    {
        $passed    = count($securify->getPassed());
        $failed    = count($securify->getFailed());
        $warnings  = count($securify->getWarnings());
        $score     = $securify->getScore();
        $grade     = $securify->getGrade();
        $total     = $passed + $failed + $warnings;
        $breakdown = $securify->getScoreBreakdown();

        $scoreColor = $score >= 80
            ? 'green'
            : ($score >= 60 ? 'yellow' : 'red');

        $gradeColor = in_array($grade, ['A+', 'A', 'A-'])
            ? 'green'
            : (in_array($grade, ['B+', 'B', 'B-'])
                ? 'cyan'
                : (in_array($grade, ['C+', 'C', 'C-'])
                    ? 'yellow'
                    : 'red'));

        $line = str_repeat('─', 72);

        $this->newLine();
        $this->line("  <fg=cyan>{$line}</>");
        $this->line("  <fg=white>  AUDIT SUMMARY</>");
        $this->line("  <fg=cyan>{$line}</>");
        $this->newLine();

        // Overall stats
        $this->line("  <fg=white>  OVERALL RESULTS</>");
        $this->newLine();
        $this->line("    Total Checks  :  <fg=white>{$total}</>");
        $this->line("    <fg=green>✔  Passed      :  {$passed}</>");
        $this->line("    <fg=red>✘  Failed      :  {$failed}</>");
        $this->line("    <fg=yellow>!  Warnings    :  {$warnings}</>");
        $this->newLine();

        // Severity breakdown table
        $this->line("  <fg=white>  SEVERITY BREAKDOWN</>");
        $this->newLine();
        $this->line(
            "    <fg=cyan>  Severity" .
            "    Failed" .
            "   Warned" .
            "   Passed" .
            "   Penalty</>"
        );
        $this->line(
            "    <fg=cyan>  " . str_repeat('·', 52) . "</>"
        );

        $this->line(
            "    <fg=red>  Critical" .
            "    ✘ " . str_pad($breakdown['critical']['failed'], 5) .
            "   ! " . str_pad($breakdown['critical']['warning'], 5) .
            "   ✔ " . str_pad($breakdown['critical']['passed'], 5) .
            "   -" . $breakdown['critical']['penalty'] . "</>"
        );

        $this->line(
            "    <fg=yellow>  High    " .
            "    ✘ " . str_pad($breakdown['high']['failed'], 5) .
            "   ! " . str_pad($breakdown['high']['warning'], 5) .
            "   ✔ " . str_pad($breakdown['high']['passed'], 5) .
            "   -" . $breakdown['high']['penalty'] . "</>"
        );

        $this->line(
            "    <fg=blue>  Medium  " .
            "    ✘ " . str_pad($breakdown['medium']['failed'], 5) .
            "   ! " . str_pad($breakdown['medium']['warning'], 5) .
            "   ✔ " . str_pad($breakdown['medium']['passed'], 5) .
            "   -" . $breakdown['medium']['penalty'] . "</>"
        );

        $this->line(
            "    <fg=gray>  Low     " .
            "    ✘ " . str_pad($breakdown['low']['failed'], 5) .
            "   ! " . str_pad($breakdown['low']['warning'], 5) .
            "   ✔ " . str_pad($breakdown['low']['passed'], 5) .
            "   -" . $breakdown['low']['penalty'] . "</>"
        );

        $this->line(
            "    <fg=cyan>  " . str_repeat('·', 52) . "</>"
        );
        $this->newLine();

        // Score & Grade
        $this->line("  <fg=white>  SECURITY SCORE</>");
        $this->newLine();

        // Score progress bar
        $filled = (int) round($score / 2);
        $empty  = 50 - $filled;
        $bar    = str_repeat('█', $filled) . str_repeat('░', $empty);

        $this->line(
            "    Score  :  <fg={$scoreColor}>{$score}/100</> " .
            "<fg={$gradeColor}>[Grade: {$grade}]</>"
        );
        $this->line("    <fg={$scoreColor}>[{$bar}]</>");
        $this->newLine();

        $this->line("  <fg=cyan>{$line}</>");
        $this->newLine();

        // Final message
        if ($grade === 'A+' || $grade === 'A') {
            $this->line(
                '  <fg=green>  ✔  EXCELLENT!' .
                '  Your application is highly secure!</>'
            );
        } elseif ($grade === 'A-' || $grade === 'B+') {
            $this->line(
                '  <fg=green>  ✔  GOOD!' .
                '  Minor improvements needed.</>'
            );
        } elseif ($grade === 'B' || $grade === 'B-') {
            $this->line(
                '  <fg=cyan>  !  FAIR.' .
                '  Please address the warnings.</>'
            );
        } elseif ($grade === 'C+' || $grade === 'C' || $grade === 'C-') {
            $this->line(
                '  <fg=yellow>  !  MODERATE.' .
                '  Fix failed checks urgently.</>'
            );
        } elseif ($grade === 'D') {
            $this->line(
                '  <fg=red>  ✘  POOR!' .
                '  Serious security issues found.</>'
            );
        } else {
            $this->line(
                '  <fg=red>  ✘  CRITICAL!' .
                '  Immediate action required!</>'
            );
        }

        $this->newLine();
        $this->line("  <fg=cyan>{$line}</>");
        $this->newLine();
    }

    /**
     * Output results in JSON format
     *
     * @param array $results
     * @param SecurifyAudit $securify
     * @return void
     */
    protected function outputJson($results, SecurifyAudit $securify)
    {
        $output = [
            'summary' => [
                'total'     => count($results),
                'passed'    => count($securify->getPassed()),
                'failed'    => count($securify->getFailed()),
                'warnings'  => count($securify->getWarnings()),
                'score'     => $securify->getScore(),
                'grade'     => $securify->getGrade(),
                'breakdown' => $securify->getScoreBreakdown(),
            ],
            'results' => $results,
        ];

        $this->line(json_encode($output, JSON_PRETTY_PRINT));
    }

    /**
     * Save report to file
     *
     * @param array $results
     * @param SecurifyAudit $securify
     * @return void
     */
    protected function saveReport($results, SecurifyAudit $securify)
    {
        $reportPath = config(
            'securify-audit.report_path',
            storage_path('logs/securify-audit.log')
        );

        $report = [
            'generated_at' => date('Y-m-d H:i:s'),
            'summary'      => [
                'total'     => count($results),
                'passed'    => count($securify->getPassed()),
                'failed'    => count($securify->getFailed()),
                'warnings'  => count($securify->getWarnings()),
                'score'     => $securify->getScore(),
                'grade'     => $securify->getGrade(),
                'breakdown' => $securify->getScoreBreakdown(),
            ],
            'results' => $results,
        ];

        file_put_contents(
            $reportPath,
            json_encode($report, JSON_PRETTY_PRINT)
        );

        $this->info("Report saved to: {$reportPath}");
    }
}
