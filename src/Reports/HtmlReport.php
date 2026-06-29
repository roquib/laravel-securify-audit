<?php

namespace Skycoder\SecurifyAudit\Reports;

use Skycoder\SecurifyAudit\SecurifyAudit;

class HtmlReport
{
    /**
     * @var SecurifyAudit
     */
    protected $securify;

    /**
     * @var array
     */
    protected $results;

    /**
     * Constructor
     *
     * @param SecurifyAudit $securify
     * @param array $results
     */
    public function __construct(SecurifyAudit $securify, array $results)
    {
        $this->securify = $securify;
        $this->results  = $results;
    }

    /**
     * Generate HTML report
     *
     * @return string
     */
    public function generate()
    {
        $score     = $this->securify->getScore();
        $grade     = $this->securify->getGrade();
        $passed    = count($this->securify->getPassed());
        $failed    = count($this->securify->getFailed());
        $warnings  = count($this->securify->getWarnings());
        $total     = $passed + $failed + $warnings;
        $breakdown = $this->securify->getScoreBreakdown();
        $date      = date('Y-m-d H:i:s');

        $scoreColor = $score >= 80 ? '#22c55e' : ($score >= 60 ? '#f59e0b' : '#ef4444');
        $gradeColor = in_array($grade, ['A+', 'A', 'A-'])
            ? '#22c55e'
            : (in_array($grade, ['B+', 'B', 'B-'])
                ? '#06b6d4'
                : (in_array($grade, ['C+', 'C', 'C-'])
                    ? '#f59e0b'
                    : '#ef4444'));

        $resultsHtml = $this->generateResultsHtml();
        $chartData   = $this->generateChartData($breakdown);

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Skycoder Laravel Securify Audit Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-bottom: 1px solid #334155;
            padding: 30px 40px;
        }

        .header-inner {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .brand-logo {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: 900;
            color: white;
        }

        .brand-name {
            font-size: 22px;
            font-weight: 700;
            color: #06b6d4;
            letter-spacing: 1px;
        }

        .brand-sub {
            font-size: 13px;
            color: #64748b;
            margin-top: 2px;
        }

        .header-meta {
            text-align: right;
            font-size: 13px;
            color: #64748b;
        }

        .header-meta strong {
            color: #94a3b8;
            display: block;
            margin-bottom: 4px;
        }

        /* Main */
        .main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }

        /* Score Hero */
        .score-hero {
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid #334155;
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 30px;
            align-items: center;
        }

        .score-circle-wrapper {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 15px;
        }

        .score-circle {
            position: relative;
            width: 180px;
            height: 180px;
        }

        .score-circle canvas {
            position: absolute;
            top: 0;
            left: 0;
        }

        .score-circle-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .score-number {
            font-size: 42px;
            font-weight: 800;
            color: {$scoreColor};
            line-height: 1;
        }

        .score-label {
            font-size: 13px;
            color: #64748b;
            margin-top: 4px;
        }

        .grade-badge {
            display: inline-block;
            background: {$gradeColor}22;
            border: 2px solid {$gradeColor};
            color: {$gradeColor};
            font-size: 28px;
            font-weight: 800;
            padding: 8px 24px;
            border-radius: 12px;
            letter-spacing: 2px;
        }

        /* Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }

        .stat-card {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }

        .stat-number {
            font-size: 36px;
            font-weight: 800;
            line-height: 1;
        }

        .stat-number.green { color: #22c55e; }
        .stat-number.red { color: #ef4444; }
        .stat-number.yellow { color: #f59e0b; }
        .stat-number.blue { color: #06b6d4; }

        .stat-label {
            font-size: 13px;
            color: #64748b;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 25px;
        }

        .chart-title {
            font-size: 16px;
            font-weight: 600;
            color: #94a3b8;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .chart-wrapper {
            position: relative;
            height: 250px;
        }

        /* Breakdown Table */
        .breakdown-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
        }

        .section-title {
            font-size: 18px;
            font-weight: 700;
            color: #e2e8f0;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-title::after {
            content: '';
            flex: 1;
            height: 1px;
            background: #334155;
        }

        .breakdown-table {
            width: 100%;
            border-collapse: collapse;
        }

        .breakdown-table th {
            text-align: left;
            padding: 12px 16px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #64748b;
            border-bottom: 1px solid #334155;
        }

        .breakdown-table td {
            padding: 14px 16px;
            border-bottom: 1px solid #1e293b;
            font-size: 14px;
        }

        .breakdown-table tr:last-child td {
            border-bottom: none;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .severity-critical {
            background: #ef444422;
            color: #ef4444;
            border: 1px solid #ef444444;
        }

        .severity-high {
            background: #f59e0b22;
            color: #f59e0b;
            border: 1px solid #f59e0b44;
        }

        .severity-medium {
            background: #3b82f622;
            color: #3b82f6;
            border: 1px solid #3b82f644;
        }

        .severity-low {
            background: #64748b22;
            color: #94a3b8;
            border: 1px solid #64748b44;
        }

        .penalty-bar {
            width: 100%;
            height: 6px;
            background: #0f172a;
            border-radius: 3px;
            overflow: hidden;
        }

        .penalty-fill {
            height: 100%;
            border-radius: 3px;
        }

        /* Results */
        .results-section {
            margin-bottom: 30px;
        }

        .filter-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .filter-tab {
            padding: 8px 20px;
            border-radius: 8px;
            border: 1px solid #334155;
            background: transparent;
            color: #64748b;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
        }

        .filter-tab:hover,
        .filter-tab.active {
            background: #06b6d4;
            border-color: #06b6d4;
            color: white;
        }

        .result-item {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 12px;
            transition: all 0.2s;
        }

        .result-item:hover {
            border-color: #475569;
            transform: translateY(-1px);
        }

        .result-item.passed {
            border-left: 4px solid #22c55e;
        }

        .result-item.failed {
            border-left: 4px solid #ef4444;
        }

        .result-item.warning {
            border-left: 4px solid #f59e0b;
        }

        .result-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
        }

        .result-title {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status-icon {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 700;
            flex-shrink: 0;
        }

        .status-icon.passed {
            background: #22c55e22;
            color: #22c55e;
            border: 1px solid #22c55e44;
        }

        .status-icon.failed {
            background: #ef444422;
            color: #ef4444;
            border: 1px solid #ef444444;
        }

        .status-icon.warning {
            background: #f59e0b22;
            color: #f59e0b;
            border: 1px solid #f59e0b44;
        }

        .result-name {
            font-size: 15px;
            font-weight: 600;
            color: #e2e8f0;
        }

        .result-message {
            font-size: 13px;
            color: #94a3b8;
            margin-left: 40px;
            line-height: 1.6;
        }

        .result-fix {
            margin-left: 40px;
            margin-top: 10px;
            padding: 10px 14px;
            background: #f59e0b11;
            border: 1px solid #f59e0b33;
            border-radius: 8px;
            font-size: 12px;
            color: #f59e0b;
            display: flex;
            align-items: flex-start;
            gap: 8px;
        }

        .result-fix-icon {
            flex-shrink: 0;
            margin-top: 1px;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            border-top: 1px solid #1e293b;
            color: #475569;
            font-size: 13px;
        }

        .footer a {
            color: #06b6d4;
            text-decoration: none;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .score-hero {
                grid-template-columns: 1fr;
            }
            .charts-grid {
                grid-template-columns: 1fr;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .main {
                padding: 20px;
            }
        }

        /* Hidden class */
        .hidden { display: none !important; }
    </style>
</head>
<body>

<!-- Header -->
<div class="header">
    <div class="header-inner">
        <div class="brand">
            <div class="brand-logo">S</div>
            <div>
                <div class="brand-name">SKYCODER</div>
                <div class="brand-sub">Laravel Securify Audit</div>
            </div>
        </div>
        <div class="header-meta">
            <strong>Security & Performance Report</strong>
            Generated: {$date}
        </div>
    </div>
</div>

<!-- Main -->
<div class="main">

    <!-- Score Hero -->
    <div class="score-hero">

        <!-- Score Circle -->
        <div class="score-circle-wrapper">
            <div class="score-circle">
                <canvas id="scoreChart" width="180" height="180"></canvas>
                <div class="score-circle-text">
                    <div class="score-number">{$score}</div>
                    <div class="score-label">/ 100</div>
                </div>
            </div>
            <div class="grade-badge">{$grade}</div>
        </div>

        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number blue">{$total}</div>
                <div class="stat-label">Total Checks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number green">{$passed}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number red">{$failed}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number yellow">{$warnings}</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:{$scoreColor}">{$score}%</div>
                <div class="stat-label">Security Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color:{$gradeColor}">{$grade}</div>
                <div class="stat-label">Grade</div>
            </div>
        </div>

        <!-- Donut Chart -->
        <div class="chart-card" style="border:none;background:transparent;padding:0">
            <div class="chart-title" style="text-align:center">Results Overview</div>
            <div class="chart-wrapper">
                <canvas id="donutChart"></canvas>
            </div>
        </div>

    </div>

    <!-- Charts Grid -->
    <div class="charts-grid">
        <div class="chart-card">
            <div class="chart-title">Severity Breakdown</div>
            <div class="chart-wrapper">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        <div class="chart-card">
            <div class="chart-title">Failed vs Warnings by Severity</div>
            <div class="chart-wrapper">
                <canvas id="barChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Breakdown Table -->
    <div class="breakdown-card">
        <div class="section-title">Severity Breakdown</div>
        <table class="breakdown-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Failed</th>
                    <th>Warnings</th>
                    <th>Passed</th>
                    <th>Penalty</th>
                    <th>Impact</th>
                </tr>
            </thead>
            <tbody>
                {$this->generateBreakdownRows($breakdown)}
            </tbody>
        </table>
    </div>

    <!-- Results -->
    <div class="results-section">
        <div class="section-title">Detailed Results</div>

        <!-- Filter Tabs -->
        <div class="filter-tabs">
            <button class="filter-tab active" onclick="filterResults('all')">All ({$total})</button>
            <button class="filter-tab" onclick="filterResults('failed')">Failed ({$failed})</button>
            <button class="filter-tab" onclick="filterResults('warning')">Warnings ({$warnings})</button>
            <button class="filter-tab" onclick="filterResults('passed')">Passed ({$passed})</button>
        </div>

        <!-- Results List -->
        <div id="results-list">
            {$resultsHtml}
        </div>
    </div>

</div>

<!-- Footer -->
<div class="footer">
    <p>
        Generated by
        <a href="https://github.com/skycoder026/laravel-securify-audit" target="_blank">
            Skycoder Laravel Securify Audit
        </a>
        — Security & Performance Scanner for Laravel
    </p>
</div>

<script>
    // Score data
    const scoreData = {$chartData};

    // Score Circle Chart
    const scoreCtx = document.getElementById('scoreChart').getContext('2d');
    new Chart(scoreCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [scoreData.score, 100 - scoreData.score],
                backgroundColor: [scoreData.scoreColor, '#1e293b'],
                borderWidth: 0,
                circumference: 360,
            }]
        },
        options: {
            responsive: false,
            cutout: '75%',
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            animation: { duration: 1500, easing: 'easeInOutQuart' }
        }
    });

    // Donut Chart
    const donutCtx = document.getElementById('donutChart').getContext('2d');
    new Chart(donutCtx, {
        type: 'doughnut',
        data: {
            labels: ['Passed', 'Failed', 'Warnings'],
            datasets: [{
                data: [scoreData.passed, scoreData.failed, scoreData.warnings],
                backgroundColor: ['#22c55e', '#ef4444', '#f59e0b'],
                borderColor: '#0f172a',
                borderWidth: 3,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', padding: 15, font: { size: 12 } }
                }
            },
            animation: { duration: 1500 }
        }
    });

    // Severity Chart
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(severityCtx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [
                {
                    label: 'Passed',
                    data: scoreData.breakdown.map(b => b.passed),
                    backgroundColor: '#22c55e88',
                    borderColor: '#22c55e',
                    borderWidth: 1,
                    borderRadius: 4,
                },
                {
                    label: 'Failed',
                    data: scoreData.breakdown.map(b => b.failed),
                    backgroundColor: '#ef444488',
                    borderColor: '#ef4444',
                    borderWidth: 1,
                    borderRadius: 4,
                },
                {
                    label: 'Warnings',
                    data: scoreData.breakdown.map(b => b.warning),
                    backgroundColor: '#f59e0b88',
                    borderColor: '#f59e0b',
                    borderWidth: 1,
                    borderRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
                y: {
                    ticks: { color: '#64748b', stepSize: 1 },
                    grid: { color: '#1e293b' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { size: 12 } }
                }
            },
            animation: { duration: 1500 }
        }
    });

    // Bar Chart - Penalty
    const barCtx = document.getElementById('barChart').getContext('2d');
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [
                {
                    label: 'Penalty Points',
                    data: scoreData.breakdown.map(b => b.penalty),
                    backgroundColor: [
                        '#ef444488',
                        '#f59e0b88',
                        '#3b82f688',
                        '#64748b88',
                    ],
                    borderColor: [
                        '#ef4444',
                        '#f59e0b',
                        '#3b82f6',
                        '#64748b',
                    ],
                    borderWidth: 1,
                    borderRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
                y: {
                    ticks: { color: '#64748b' },
                    grid: { color: '#1e293b' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { size: 12 } }
                }
            },
            animation: { duration: 1500 }
        }
    });

    // Filter Results
    function filterResults(status) {
        // Update tabs
        document.querySelectorAll('.filter-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        event.target.classList.add('active');

        // Filter items
        document.querySelectorAll('.result-item').forEach(item => {
            if (status === 'all' || item.dataset.status === status) {
                item.classList.remove('hidden');
            } else {
                item.classList.add('hidden');
            }
        });
    }
</script>

</body>
</html>
HTML;
    }

    /**
     * Generate results HTML
     *
     * @return string
     */
    protected function generateResultsHtml()
    {
        $html = '';

        foreach ($this->results as $result) {
            $status   = $result['status'];
            $analyzer = htmlspecialchars($result['analyzer']);
            $message  = htmlspecialchars($result['message']);
            $severity = isset($result['severity'])
                ? strtolower($result['severity'])
                : 'low';

            $icon = $status === 'passed' ? '✔' : ($status === 'failed' ? '✘' : '!');
            $fix  = isset($result['fix']) && $result['fix']
                ? '<div class="result-fix">
                    <span class="result-fix-icon">💡</span>
                    <span>' . htmlspecialchars($result['fix']) . '</span>
                   </div>'
                : '';

            $html .= <<<ITEM
<div class="result-item {$status}" data-status="{$status}">
    <div class="result-header">
        <div class="result-title">
            <div class="status-icon {$status}">{$icon}</div>
            <div class="result-name">{$analyzer}</div>
        </div>
        <span class="severity-badge severity-{$severity}">{$severity}</span>
    </div>
    <div class="result-message">{$message}</div>
    {$fix}
</div>
ITEM;
        }

        return $html;
    }

    /**
     * Generate breakdown table rows
     *
     * @param array $breakdown
     * @return string
     */
    protected function generateBreakdownRows($breakdown)
    {
        $html       = '';
        $severities = [
            'critical' => ['color' => '#ef4444', 'max' => 20],
            'high'     => ['color' => '#f59e0b', 'max' => 10],
            'medium'   => ['color' => '#3b82f6', 'max' => 5],
            'low'      => ['color' => '#64748b', 'max' => 2],
        ];

        foreach ($severities as $severity => $config) {
            $data        = $breakdown[$severity];
            $penaltyPct  = $config['max'] > 0
                ? min(100, ($data['penalty'] / ($config['max'] * 10)) * 100)
                : 0;

            $html .= <<<ROW
<tr>
    <td>
        <span class="severity-badge severity-{$severity}">{$severity}</span>
    </td>
    <td style="color:#ef4444;font-weight:600">{$data['failed']}</td>
    <td style="color:#f59e0b;font-weight:600">{$data['warning']}</td>
    <td style="color:#22c55e;font-weight:600">{$data['passed']}</td>
    <td style="color:{$config['color']};font-weight:700">-{$data['penalty']}</td>
    <td style="width:120px">
        <div class="penalty-bar">
            <div class="penalty-fill" style="width:{$penaltyPct}%;background:{$config['color']}"></div>
        </div>
    </td>
</tr>
ROW;
        }

        return $html;
    }

    /**
     * Generate chart data JSON
     *
     * @param array $breakdown
     * @return string
     */
    protected function generateChartData($breakdown)
    {
        $score      = $this->securify->getScore();
        $scoreColor = $score >= 80 ? '#22c55e' : ($score >= 60 ? '#f59e0b' : '#ef4444');

        $data = [
            'score'      => $score,
            'scoreColor' => $scoreColor,
            'passed'     => count($this->securify->getPassed()),
            'failed'     => count($this->securify->getFailed()),
            'warnings'   => count($this->securify->getWarnings()),
            'breakdown'  => [
                [
                    'severity' => 'critical',
                    'passed'   => $breakdown['critical']['passed'],
                    'failed'   => $breakdown['critical']['failed'],
                    'warning'  => $breakdown['critical']['warning'],
                    'penalty'  => $breakdown['critical']['penalty'],
                ],
                [
                    'severity' => 'high',
                    'passed'   => $breakdown['high']['passed'],
                    'failed'   => $breakdown['high']['failed'],
                    'warning'  => $breakdown['high']['warning'],
                    'penalty'  => $breakdown['high']['penalty'],
                ],
                [
                    'severity' => 'medium',
                    'passed'   => $breakdown['medium']['passed'],
                    'failed'   => $breakdown['medium']['failed'],
                    'warning'  => $breakdown['medium']['warning'],
                    'penalty'  => $breakdown['medium']['penalty'],
                ],
                [
                    'severity' => 'low',
                    'passed'   => $breakdown['low']['passed'],
                    'failed'   => $breakdown['low']['failed'],
                    'warning'  => $breakdown['low']['warning'],
                    'penalty'  => $breakdown['low']['penalty'],
                ],
            ],
        ];

        return json_encode($data);
    }

    /**
     * Save report to file
     *
     * @param string $path
     * @return bool
     */
    public function save($path)
    {
        $html = $this->generate();
        return file_put_contents($path, $html) !== false;
    }
}
