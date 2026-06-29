<?php

namespace Skycoder\SecurifyAudit\Analyzers\Performance;

use Skycoder\SecurifyAudit\Analyzers\BaseAnalyzer;

class SessionDriverAnalyzer extends BaseAnalyzer
{
    protected $name        = 'Session Driver Performance';
    protected $description = 'Checks if session driver is optimized for performance';
    protected $severity    = 'medium';

    public function analyze()
    {
        $issues        = [];
        $sessionDriver = config('session.driver', 'file');

        // Check driver for production
        if ($this->app->environment('production')) {
            if ($sessionDriver === 'file') {
                $issues[] = 'File session driver in production causes I/O bottlenecks at scale.';
            }

            if ($sessionDriver === 'cookie') {
                $issues[] = 'Cookie session driver stores data client-side. Not suitable for sensitive data.';
            }
        }

        // Check session table exists for database driver
        if ($sessionDriver === 'database') {
            try {
                $tableExists = \Illuminate\Support\Facades\Schema::hasTable(
                    config('session.table', 'sessions')
                );

                if (!$tableExists) {
                    $issues[] = 'Session table does not exist. Run: php artisan session:table && php artisan migrate';
                }
            } catch (\Exception $e) {
                // Database might not be connected
            }
        }

        // Check Redis connection for redis driver
        if ($sessionDriver === 'redis') {
            $redisConnection = config('session.connection', 'default');
            $redisConfig     = config('database.redis.' . $redisConnection);

            if (!$redisConfig) {
                $issues[] = 'Redis session driver configured but Redis connection "' . $redisConnection . '" not found.';
            }
        }

        // Check session lifetime
        $lifetime = config('session.lifetime', 120);
        if ($lifetime > 480 && $sessionDriver === 'file') {
            $issues[] = 'Long session lifetime (' . $lifetime . ' min) with file driver will accumulate many session files.';
        }

        if (count($issues) > 0) {
            return $this->warning(
                implode(' | ', $issues),
                'Use Redis or Database session driver in production for better performance and scalability.'
            );
        }

        return $this->passed('Session driver is properly configured (' . $sessionDriver . ').');
    }
}
