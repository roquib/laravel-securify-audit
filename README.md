# 🔐 Laravel Securify Audit

<p align="center">
  <img src="https://img.shields.io/packagist/v/skycoder/laravel-securify-audit?style=flat-square&color=06b6d4" alt="Latest Version">
  <img src="https://img.shields.io/packagist/php-v/skycoder/laravel-securify-audit?style=flat-square&color=777BB4" alt="PHP Version">
  <img src="https://img.shields.io/packagist/l/skycoder/laravel-securify-audit?style=flat-square&color=22c55e" alt="License">
  <img src="https://img.shields.io/packagist/dt/skycoder/laravel-securify-audit?style=flat-square&color=f59e0b" alt="Downloads">
</p>

<p align="center">
  <strong>A powerful Laravel Security & Performance Scanner Package by Skycoder</strong><br>
  Scan your Laravel application for security vulnerabilities and performance issues with a single command.
</p>

---

## ✨ Features

- 🔒 **50+ Security & Performance Checks**
- 📊 **Weighted Scoring System** with Grade (A+ to F)
- 🎨 **Beautiful CLI Output** with colored results
- 🌐 **HTML Report Generator** with interactive charts
- ⚡ **Performance Analysis** for production optimization
- 🔧 **Fix Suggestions** for every failed check
- 🎯 **Severity Levels**: Critical, High, Medium, Low
- 🔌 **Laravel 6.x to 12.x** support
- 🐘 **PHP 7.4+** compatible
- ⚙️ **Highly Configurable** via config file

---

## 📋 What It Checks

### 🔴 Security Checks (36)

| Check | Severity | Description |
|-------|----------|-------------|
| App Debug Mode | Critical | Detects APP_DEBUG=true in production |
| Application Key | Critical | Validates APP_KEY is set and secure |
| Env File Exposure | Critical | Checks .env is not publicly accessible |
| SQL Injection | Critical | Scans for raw queries with user input |
| Sensitive Data Exposure | Critical | Detects hardcoded credentials |
| Mass Assignment | Critical | Checks Eloquent model protection |
| Command Injection | Critical | Detects exec/shell_exec with user input |
| Path Traversal | Critical | Checks file operations with user input |
| Unsafe Unserialize | Critical | Detects unsafe unserialize() usage |
| Backup File Security | Critical | Checks for sensitive files in public |
| CSRF Protection | High | Validates CSRF middleware is enabled |
| Dependency Vulnerability | High | Scans packages for known CVEs |
| Cookie Security | High | Checks secure/httpOnly cookie flags |
| HTTPS Configuration | High | Verifies HTTPS enforcement |
| Rate Limiting | High | Checks throttle middleware |
| File Permission | High | Validates directory permissions |
| XSS Protection | High | Scans Blade templates for raw output |
| Auth Configuration | High | Reviews authentication setup |
| Header Security | High | Checks security headers |
| Open Redirect | High | Detects redirect with user input |
| Clickjacking Protection | High | Checks X-Frame-Options header |
| HSTS Configuration | High | Validates HSTS setup |
| API Token Security | High | Reviews token expiration config |
| Timing Attack | High | Detects unsafe string comparisons |
| Validation | High | Checks controller input validation |
| Policy Authorization | High | Reviews route authorization |
| Password Security | High | Validates hashing configuration |
| File Upload Security | Critical | Checks upload validation rules |
| CORS Configuration | Medium | Reviews CORS settings |
| Session Security | High | Validates session configuration |
| Weak Password | High | Checks password validation rules |
| Error Handling | Medium | Validates custom error pages |
| Debugbar Security | High | Checks Debugbar in production |
| Log Injection | Medium | Detects user input in log calls |
| Model Scope | Medium | Reviews SoftDelete scope usage |
| Middleware Order | Medium | Checks middleware ordering |
| Service Provider | Medium | Reviews service provider security |

### ⚡ Performance Checks (14)

| Check | Severity | Description |
|-------|----------|-------------|
| Cache Configuration | Medium | Reviews cache driver setup |
| Route Optimization | Low | Checks route caching |
| Database Index | Medium | Detects missing foreign key indexes |
| N+1 Query Detection | Medium | Scans for N+1 query patterns |
| Queue Configuration | Medium | Reviews queue driver setup |
| Logging Configuration | Low | Checks log level and rotation |
| PHP OPcache | Medium | Validates OPcache configuration |
| Composer Optimization | Low | Checks autoloader optimization |
| Asset Optimization | Low | Validates compiled assets |
| View Cache | Low | Checks Blade template caching |
| Config Cache | Medium | Validates config caching |
| Autoloader Optimization | Medium | Reviews PSR-4 optimization |
| Memory Usage | Medium | Monitors PHP memory consumption |
| Session Driver | Medium | Reviews session driver for scale |

---

## 📦 Installation

```bash
composer require skycoder/laravel-securify-audit
```

> **Note:** The package auto-discovers the service provider. No manual registration needed for Laravel 5.5+.

### Publish Config (Optional)

```bash
php artisan vendor:publish --tag=securify-config
```

---

## 🚀 Usage

### Basic Scan

```bash
php artisan securify:audit
```

### Show Only Failed Checks

```bash
php artisan securify:audit --only-failed
```

### Show Only Warnings

```bash
php artisan securify:audit --only-warnings
```

### Filter by Severity

```bash
php artisan securify:audit --severity=critical
php artisan securify:audit --severity=high
php artisan securify:audit --severity=medium
php artisan securify:audit --severity=low
```

### JSON Output

```bash
php artisan securify:audit --format=json
```

### Save Report to File

```bash
php artisan securify:audit --save
```

### Generate HTML Report

```bash
php artisan securify:html
```

### Generate & Open HTML Report in Browser

```bash
php artisan securify:html --open
```

### Custom Output Path

```bash
php artisan securify:html --output=/path/to/report.html
```

### Detailed Report by Type

```bash
php artisan securify:report
php artisan securify:report --type=security
php artisan securify:report --type=performance
```

---

## 📊 Scoring System

The package uses a **weighted scoring system** based on severity:

| Status | Critical | High | Medium | Low |
|--------|----------|------|--------|-----|
| ❌ Failed | -20 pts | -10 pts | -5 pts | -2 pts |
| ⚠️ Warning | -10 pts | -5 pts | -2 pts | -1 pt |
| ✅ Passed | 0 pts | 0 pts | 0 pts | 0 pts |

### Grades

| Score | Grade | Status |
|-------|-------|--------|
| 95-100 | A+ | Excellent |
| 90-94 | A | Excellent |
| 85-89 | A- | Good |
| 80-84 | B+ | Good |
| 75-79 | B | Fair |
| 70-74 | B- | Fair |
| 65-69 | C+ | Moderate |
| 60-64 | C | Moderate |
| 55-59 | C- | Moderate |
| 50-54 | D | Poor |
| 0-49 | F | Critical |

---

## ⚙️ Configuration

After publishing, edit `config/securify-audit.php`:

```php
return [
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
```

### Skip Specific Checks

```php
'skip' => [
    'DebugbarAnalyzer',
    'HSTSAnalyzer',
    'TwoFactorAnalyzer',
],
```

### Environment Variables

Add to your `.env` file:

```env
SECURIFY_ENABLED=true
SECURIFY_OUTPUT=cli
SECURIFY_SAVE_REPORT=false
SECURIFY_NOTIFY=false
SECURIFY_NOTIFY_EMAIL=admin@example.com
```

---

## 🖥️ CLI Output

```
  ██████╗ ██╗  ██╗██╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
 ██╔════╝ ██║ ██╔╝╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
 ╚█████╗  █████╔╝  ╚████╔╝ ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
  ╚═══██╗ ██╔═██╗   ╚██╔╝  ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
 ██████╔╝ ██║  ██╗   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

         Laravel Securify Audit — Security & Performance Scanner
                   by Skycoder | github.com/skycoder026

  ────────────────────────────────────────────────────────────────────────

  [PASS] [CRITICAL] App Debug Mode
       APP_DEBUG is properly disabled.

  [FAIL] [HIGH] CSRF Protection
       CSRF protection middleware is not found in web middleware group.
       Fix: Add \App\Http\Middleware\VerifyCsrfToken to web middleware.

  ────────────────────────────────────────────────────────────────────────
  AUDIT SUMMARY
  ────────────────────────────────────────────────────────────────────────

  Total Checks  :  50
  ✔  Passed     :  37
  ✘  Failed     :  3
  !  Warnings   :  10

  SEVERITY BREAKDOWN
    Severity    Failed   Warned   Passed   Penalty
    ····················································
    Critical    ✘ 1      ! 0      ✔ 11     -20
    High        ✘ 2      ! 5      ✔ 11     -45
    Medium      ✘ 0      ! 4      ✔ 11     -8
    Low         ✘ 0      ! 1      ✔ 4      -1

  Score  :  85/100 [Grade: A-]
  [█████████████████████████████████████████░░░░░░░░░]

  ────────────────────────────────────────────────────────────────────────
  ✔  GOOD!  Minor improvements needed.
  ────────────────────────────────────────────────────────────────────────
```

---

## 🌐 HTML Report

Generate a beautiful interactive HTML report:

```bash
php artisan securify:html --open
```

Features:
- 📊 Interactive charts (Score circle, Donut, Bar charts)
- 🎨 Dark theme professional design
- 🔍 Filter results by status
- 📋 Severity breakdown table
- 💡 Fix suggestions for each issue
- 📱 Responsive layout

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Laravel Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'

      - name: Install Dependencies
        run: composer install --no-dev --optimize-autoloader

      - name: Run Securify Audit
        run: php artisan securify:audit --only-failed
        env:
          APP_KEY: ${{ secrets.APP_KEY }}
          DB_CONNECTION: sqlite
          DB_DATABASE: ':memory:'
```

### Fail on Critical Issues Only

```yaml
- name: Security Audit
  run: |
    php artisan securify:audit --severity=critical
  continue-on-error: false
```

---

## 🔧 Laravel Version Compatibility

| Laravel | PHP | Status |
|---------|-----|--------|
| 6.x | 7.4+ | ✅ Supported |
| 7.x | 7.4+ | ✅ Supported |
| 8.x | 7.4 / 8.0+ | ✅ Supported |
| 9.x | 8.0+ | ✅ Supported |
| 10.x | 8.1+ | ✅ Supported |
| 11.x | 8.2+ | ✅ Supported |
| 12.x | 8.2+ | ✅ Supported |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-analyzer`)
3. Commit your changes (`git commit -m 'Add new analyzer'`)
4. Push to the branch (`git push origin feature/new-analyzer`)
5. Open a Pull Request

---

## 📝 Changelog

### v1.0.0 (2026-06-30)
- 🎉 Initial release
- ✅ 50 Security & Performance checks
- 📊 Weighted scoring system with grades
- 🌐 HTML report generator with charts
- 🎨 Beautiful CLI output with ASCII banner
- ⚙️ Configurable via config file
- 🔌 Laravel 6.x - 12.x support

---

## 🛡️ Security

If you discover any security vulnerabilities, please send an email to
[akashcseuu026@gmail.com](mailto:akashcseuu026@gmail.com).

---

## 📄 License

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.

---

## 👨‍💻 Author

**Al Kazi** — Full Stack Software Engineer

- GitHub: [@skycoder026](https://github.com/skycoder026)
- Email: [akashcseuu026@gmail.com](mailto:akashcseuu026@gmail.com)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/skycoder026">Skycoder</a>
</p>
