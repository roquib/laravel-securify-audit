<?php

namespace Skycoder\SecurifyAudit;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array run()
 * @method static array getResults()
 * @method static array getPassed()
 * @method static array getFailed()
 * @method static array getWarnings()
 * @method static array getBySeverity(string $severity)
 * @method static int getScore()
 * @method static array getScoreBreakdown()
 * @method static string getGrade()
 * @method static array getWeights()
 *
 * @see \Skycoder\SecurifyAudit\SecurifyAudit
 */
class SecurifyAuditFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'securify-audit';
    }
}
