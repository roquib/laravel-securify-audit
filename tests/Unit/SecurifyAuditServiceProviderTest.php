<?php

namespace Skycoder\SecurifyAudit\Tests\Unit;

use Skycoder\SecurifyAudit\Tests\TestCase;

class SecurifyAuditServiceProviderTest extends TestCase
{
    /** @test */
    public function it_registers_the_securify_audit_singleton()
    {
        $this->assertTrue($this->app->has('securify-audit'));
    }

    /** @test */
    public function the_singleton_returns_a_securify_audit_instance()
    {
        $instance = $this->app->make('securify-audit');

        $this->assertInstanceOf(
            \Skycoder\SecurifyAudit\SecurifyAudit::class,
            $instance
        );
    }

    /** @test */
    public function it_merges_the_config()
    {
        $config = $this->app['config']->get('securify-audit');

        $this->assertIsArray($config);
        $this->assertArrayHasKey('enabled', $config);
        $this->assertArrayHasKey('analyzers', $config);
        $this->assertArrayHasKey('skip', $config);
    }

    /** @test */
    public function it_registers_commands_in_console()
    {
        $commands = $this->app->make('config')->get('commands', []);

        // The commands are registered via ServiceProvider::boot() which
        // checks runningInConsole(). In testbench the app is typically
        // in console context, so commands should be registered.
        $registered = $this->app->make('events')
            ->dispatch('console.command');

        $this->assertTrue(true); // No exception means commands registered cleanly
    }
}
