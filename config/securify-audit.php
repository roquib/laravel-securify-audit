<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Securify Audit Configuration
    |--------------------------------------------------------------------------
    | Skycoder/laravel-securify-audit
    */

    // Enable or disable the package
    'enabled' => env('SECURIFY_ENABLED', true),

    // Which analyzers to run
    'analyzers' => [
        'security'    => true,
        'performance' => true,
    ],

    // Severity levels to report
    'report_levels' => ['critical', 'high', 'medium', 'low'],

    // Output format: cli, json, html
    'output_format' => env('SECURIFY_OUTPUT', 'cli'),

    // Save report to file
    'save_report' => env('SECURIFY_SAVE_REPORT', false),

    // Report file path
    'report_path' => storage_path('logs/securify-audit.log'),

    // Notification settings
    'notify' => [
        'enabled' => env('SECURIFY_NOTIFY', false),
        'email'   => env('SECURIFY_NOTIFY_EMAIL', null),
    ],

    // Checks to skip
    'skip' => [
        // 'AppDebugAnalyzer',
        // 'CsrfAnalyzer',
    ],
];
