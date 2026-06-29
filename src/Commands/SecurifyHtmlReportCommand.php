<?php

namespace Skycoder\SecurifyAudit\Commands;

use Illuminate\Console\Command;
use Skycoder\SecurifyAudit\SecurifyAudit;
use Skycoder\SecurifyAudit\Reports\HtmlReport;

class SecurifyHtmlReportCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'securify:html
                            {--output= : Output file path (default: storage/logs/securify-report.html)}
                            {--open : Open report in browser after generation}';

    /**
     * @var string
     */
    protected $description = 'Generate HTML Security Report by Skycoder Securify Audit';

    /**
     * @return int
     */
    public function handle()
    {
        $this->newLine();
        $this->line('  <fg=cyan>Generating HTML Security Report...</>');
        $this->newLine();

        try {
            // Run audit
            $securify = new SecurifyAudit($this->laravel);
            $results  = $securify->run();

            // Generate HTML
            $report     = new HtmlReport($securify, $results);
            $outputPath = $this->option('output')
                ?? storage_path('logs/securify-report.html');

            // Save report
            if ($report->save($outputPath)) {
                $this->line(
                    '  <fg=green>✔ Report generated successfully!</>'
                );
                $this->line(
                    "  <fg=white>  Path: <fg=cyan>{$outputPath}</></>"
                );
                $this->newLine();

                // Show summary
                $score = $securify->getScore();
                $grade = $securify->getGrade();

                $scoreColor = $score >= 80
                    ? 'green'
                    : ($score >= 60 ? 'yellow' : 'red');

                $this->line(
                    "  Score : <fg={$scoreColor}>{$score}/100</> " .
                    "[Grade: <fg={$scoreColor}>{$grade}</>]"
                );
                $this->line(
                    "  Passed  : <fg=green>" . count($securify->getPassed()) . "</>"
                );
                $this->line(
                    "  Failed  : <fg=red>" . count($securify->getFailed()) . "</>"
                );
                $this->line(
                    "  Warnings: <fg=yellow>" . count($securify->getWarnings()) . "</>"
                );
                $this->newLine();

                // Open in browser
                if ($this->option('open')) {
                    $this->openInBrowser($outputPath);
                } else {
                    $this->line(
                        '  <fg=gray>Tip: Use --open flag to open in browser automatically.</>'
                    );
                    $this->line(
                        '  <fg=gray>Or run: php artisan securify:html --open</>'
                    );
                }

                $this->newLine();
                return 0;
            }

            $this->error('Failed to save report. Check file permissions.');
            return 1;

        } catch (\Exception $e) {
            $this->error('Error: ' . $e->getMessage());
            $this->error('File: ' . $e->getFile() . ':' . $e->getLine());
            return 1;
        }
    }

    /**
     * Open report in browser
     *
     * @param string $path
     * @return void
     */
    protected function openInBrowser($path)
    {
        $this->line('  <fg=cyan>Opening in browser...</>');

        if (PHP_OS_FAMILY === 'Windows') {
            exec('start "" "' . $path . '"');
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            exec('open "' . $path . '"');
        } else {
            exec('xdg-open "' . $path . '" &');
        }
    }
}
