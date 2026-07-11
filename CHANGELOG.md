# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-06-30

Initial release of Laravel Securify Audit.

### Added
- 50 security and performance checks (36 security + 14 performance)
- Weighted scoring system with grades (A+ to F)
- CLI audit command with colored output
- JSON output format for CI/CD integration
- HTML report generation with interactive Chart.js visualizations
- Published config file (`config/securify-audit.php`)
- Laravel 6.x through 12.x support
- PHP 7.4 through 8.3 support
- Filter by severity, status, and output format
- Fix suggestions for every failed check
- Severity levels: Critical, High, Medium, Low
