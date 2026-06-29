<?php

namespace Skycoder\SecurifyAudit;

use Illuminate\Support\ServiceProvider;
use Skycoder\SecurifyAudit\Commands\SecurifyAuditCommand;
use Skycoder\SecurifyAudit\Commands\SecurifyReportCommand;
use Skycoder\SecurifyAudit\Commands\SecurifyHtmlReportCommand;

class SecurifyAuditServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {

            // Publish config
            $this->publishes([
                __DIR__ . '/../config/securify-audit.php' => config_path('securify-audit.php'),
            ], 'securify-config');

            // Register commands
            $this->commands([
                SecurifyAuditCommand::class,
                SecurifyReportCommand::class,
                SecurifyHtmlReportCommand::class,
            ]);
        }
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        // Merge config
        $this->mergeConfigFrom(
            __DIR__ . '/../config/securify-audit.php',
            'securify-audit'
        );

        // Bind to container
        $this->app->singleton('securify-audit', function ($app) {
            return new SecurifyAudit($app);
        });
    }

    /**
     * @return array
     */
    public function provides()
    {
        return ['securify-audit'];
    }
}
