<?php

namespace Skycoder\SecurifyAudit\Analyzers;

use Illuminate\Contracts\Foundation\Application;

abstract class BaseAnalyzer
{
    /**
     * @var Application
     */
    protected $app;

    /**
     * Analyzer name
     *
     * @var string
     */
    protected $name = '';

    /**
     * Analyzer description
     *
     * @var string
     */
    protected $description = '';

    /**
     * Severity: critical, high, medium, low
     *
     * @var string
     */
    protected $severity = 'medium';

    /**
     * Constructor
     *
     * @param Application $app
     */
    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * Run the analyzer
     * Must be implemented by each analyzer
     *
     * @return array
     */
    abstract public function analyze();

    /**
     * Return passed result
     *
     * @param string $message
     * @return array
     */
    protected function passed($message = '')
    {
        return [
            'analyzer'    => $this->name,
            'description' => $this->description,
            'status'      => 'passed',
            'severity'    => $this->severity,
            'message'     => $message ?: $this->name . ' check passed.',
        ];
    }

    /**
     * Return failed result
     *
     * @param string $message
     * @param string|null $fix
     * @return array
     */
    protected function failed($message = '', $fix = null)
    {
        return [
            'analyzer'    => $this->name,
            'description' => $this->description,
            'status'      => 'failed',
            'severity'    => $this->severity,
            'message'     => $message,
            'fix'         => $fix,
        ];
    }

    /**
     * Return warning result
     *
     * @param string $message
     * @param string|null $fix
     * @return array
     */
    protected function warning($message = '', $fix = null)
    {
        return [
            'analyzer'    => $this->name,
            'description' => $this->description,
            'status'      => 'warning',
            'severity'    => $this->severity,
            'message'     => $message,
            'fix'         => $fix,
        ];
    }

    /**
     * Get analyzer name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Get analyzer severity
     *
     * @return string
     */
    public function getSeverity()
    {
        return $this->severity;
    }
}
