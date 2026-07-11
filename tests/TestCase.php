<?php

namespace Skycoder\SecurifyAudit\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Skycoder\SecurifyAudit\SecurifyAuditServiceProvider;

abstract class TestCase extends OrchestraTestCase
{
    /**
     * Get package service providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            SecurifyAuditServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment($app)
    {
        $app['config']->set('securify-audit.enabled', true);
        $app['config']->set('securify-audit.analyzers.security', true);
        $app['config']->set('securify-audit.skip', []);
    }

    /**
     * Create a mock SecurifyAudit instance with controlled results.
     *
     * @param  array  $results
     * @return \Skycoder\SecurifyAudit\SecurifyAudit
     */
    protected function createAuditWithResults(array $results)
    {
        $audit = new \Skycoder\SecurifyAudit\SecurifyAudit($this->app);

        $reflection = new \ReflectionClass($audit);

        $resultsProperty = $reflection->getProperty('results');
        $resultsProperty->setAccessible(true);
        $resultsProperty->setValue($audit, $results);

        return $audit;
    }
}
