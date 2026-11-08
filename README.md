<!-- header:start -->
<div align="center">

<img src="./assets/banner.svg" alt="PHP Fossil" width="100%">

<a href="#-quick-start"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1000&color=daa520&center=true&vCenter=true&width=640&lines=Uncover+end-of-life+PHP+sites;Map+CVEs%2C+exposed+dumps+%26+schemas;Build+actionable+legacy+lists+fast" alt="Uncover end-of-life PHP sites · Map CVEs, exposed dumps &amp; schemas · Build actionable legacy lists fast"></a>

<a href="LICENSE"><img src="https://img.shields.io/github/license/ajendras/php-fossil?style=for-the-badge&color=2e8b57" alt="License"></a>
<img src="https://img.shields.io/badge/Python-2e8b57?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<a href="https://github.com/ajendras/php-fossil/stargazers"><img src="https://img.shields.io/github/stars/ajendras/php-fossil?style=for-the-badge&logo=github&color=daa520" alt="Stars"></a>
<a href="https://github.com/ajendras/php-fossil/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ajendras/php-fossil/ci.yml?style=for-the-badge&label=CI" alt="CI"></a>
<img src="https://img.shields.io/github/last-commit/ajendras/php-fossil?style=for-the-badge&color=2e8b57" alt="Last commit">
<a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-22c55e?style=for-the-badge" alt="PRs welcome"></a>

**Discovers legacy PHP sites via search dorks, fingerprints old versions, maps vulns, extracts schemas and builds prioritized security lists.**

[✨ Features](#-features) • [⚡ Quick start](#-quick-start) • [🧰 Usage](#-usage) • [🧩 Architecture](#-architecture) • [📍 Roadmap](#-roadmap) • [🤝 Contributing](#-contributing)

</div>
<!-- header:end -->

## ✨ Why PHP Fossil?

Countless sites still run unsupported PHP versions (pre-8.1) riddled with known CVEs, yet lack a focused open-source tool. Existing scanners are either too generic or ignore search-driven discovery and schema leakage. PHP Fossil is built for authorized pentesters, bug-bounty hunters and security teams that maintain large site inventories.

- **Targeted discovery** — `generate_dorks()` produces precise Google/Bing/Shodan dorks for specific PHP versions and signatures
- **Accurate fingerprinting** — Multi-vector detection via `detect_from_headers()`, `detect_from_body()`, `detect_from_phpinfo()` and error-page fallbacks
- **Built-in intelligence** — Embedded VulnDB with 180+ CVEs, severity ratings, fix versions and references via `get_vulns_for_version()`
- **Actionable output** — `ScanResult` objects feed rich terminal tables, interactive HTML reports, JSON exports and prioritized at-risk lists

## 🎬 Demo

<p align="center"><img src="./assets/demo.svg" alt="PHP Fossil demo" width="760"></p>

## 🚀 Features

<table>
<tr>
<td>
🔎 <b>Dork Generator</b><br>
Produces ready-to-use Google/Bing/Shodan dorks for any PHP version
</td>
<td>
🕵️ <b>Version Fingerprint</b><br>
Detects exact version from headers, body, phpinfo() and error pages
</td>
<td>
🛡️ <b>Vuln Database</b><br>
Maps versions to embedded CVEs with severity and exploit links
</td>
</tr>
<tr>
<td>
📊 <b>Schema Extractor</b><br>
Locates exposed .sql files and parses tables/columns with `parse_sql_dump()`
</td>
<td>
📋 <b>List Manager</b><br>
Saves, filters and exports at-risk domains via the `list` CLI command
</td>
<td>
📑 <b>Rich Reports</b><br>
Terminal tables and beautiful HTML reports via `ReportGenerator`
</td>
</tr>
<tr>
<td>
⚡ <b>Async Scanner</b><br>
Concurrent, rate-limited scans with `scan_targets()` and configurable limits
</td>
<td>
🧩 <b>Extensible Core</b><br>
Clean module API for new fingerprint methods or data sources
</td>
<td>
🔀 <b>Proxy Rotation</b><br>
Optional proxy list for rotating outbound requests, supporting residential proxies
</td>
</tr>
</table>

**Persistent History** — Every scan is automatically saved to a local SQLite database (`~/.phpfossil/history.db`). Review and query past results with the `history` CLI command or `get_historical_results()`.

## 📦 Installation

Requires **Python 3.11+**. All dependencies are declared in `pyproject.toml`.

```bash
pip install php-fossil
```

Or install from source:

```bash
git clone https://github.com/ajendras/php-fossil.git
cd php-fossil
pip install -e ".[dev]"
```

The CLI is automatically installed as the `php-fossil` command.

## ⚡ Quick start

```python
from phpfossil import scan_targets, generate_report, store_results, get_historical_results

results = scan_targets(
    ["https://httpbin.org", "http://example.com"],
    config={"max_concurrency": 10, "timeout": 15}
)

# results are automatically persisted to SQLite
store_results(results)

generate_report(results, output_format="terminal")
generate_report(results, output_format="html", output_path="report.html")

# retrieve historical scans
history = get_historical_results(limit=5)
```

## 🧰 Usage

**Generate dorks for a specific version:**

```bash
php-fossil dorks --version 7.4 --count 20 --save dorks.txt
```

**Scan targets from a file with custom limits:**

```bash
php-fossil scan -f targets.txt --concurrency 25 --timeout 10 --html report.html
```

**View historical scans from the persistent store:**

```bash
php-fossil history --limit 20
php-fossil history --url example.com
php-fossil history --db /path/to/custom.db
```

**Re-generate reports from saved JSON:**

```bash
php-fossil report phpfossil-results.json --html latest.html
```

**Manage an at-risk list:**

```bash
php-fossil list add --url https://legacy.example.com --version 5.6.40
php-fossil list show
```

<details><summary>Library API usage (advanced)</summary>

```python
from phpfossil import generate_dorks, scan_targets, generate_report, get_historical_results
from phpfossil.models import ScanResult

# Custom dork generation
dorks = generate_dorks("8.0", count=12)
print(dorks[0])  # e.g. intitle:"phpinfo()" "PHP Version 8.0"

# Direct scan with full result inspection
results: list[ScanResult] = scan_targets(["https://httpbin.org"])
for r in results:
    if r.is_vulnerable():
        print(f"{r.url} → {r.php_version} ({len(r.vulns)} vulns)")
        for v in r.vulns:
            print(f"  • {v.cve} ({v.severity})")

# Query persistent history
history = get_historical_results(limit=10, url_filter="example")
```

</details>

<details><summary>Extending the fingerprinter</summary>

```python
from phpfossil.fingerprinter import detect_php_version

# Combine multiple sources
version = detect_php_version(
    headers={"X-Powered-By": "PHP/7.4.33"},
    body="<h1>PHP Version 7.4.33</h1>",
    phpinfo_content="PHP Version 7.4.33"
)
print(version)  # 7.4.33
```

</details>

## 🔧 Configuration

| Option            | Default | Description                                      |
|-------------------|---------|--------------------------------------------------|
| max_concurrency   | 20      | Maximum simultaneous HTTP requests (capped at 50) |
| timeout           | 12      | HTTP request timeout in seconds                  |
| proxies           | []      | Optional list of proxy URLs for rotating requests |
| db_path           | ~/.phpfossil/history.db | Path to persistent SQLite database for scan history |

These are passed via the `config` dict to `scan_targets()` or via CLI flags `--concurrency` and `--timeout`. Proxy rotation is currently only available through the library API; future CLI enhancements will expose it. The SQLite store is used automatically by `scan` and `history` commands.

## 🧩 Architecture

```mermaid
flowchart TD
    CLI[cli.py] --> API[__init__.py]
    API --> Scanner[scanner.py]
    Scanner --> Fingerprinter[fingerprinter.py]
    Scanner --> VulnDB[vulndb.py]
    Scanner --> Schema[schema.py]
    API --> Search[search.py]
    API --> Reporter[reporter.py]
    API --> Store[store.py]
    Reporter --> HTML[Jinja2]
    Scanner --> Models[models.py]
    Models --> Pydantic[Validation]
```

PHP Fossil follows a clean, modular architecture. The public API in `__init__.py` (`scan_targets`, `generate_dorks`, `generate_report`, `store_results`, `get_historical_results`) orchestrates everything. `AsyncScanner` uses a rate-limited `httpx.AsyncClient` and delegates to specialized modules for fingerprinting, vulnerability lookup, schema extraction and reporting. All data flows through validated Pydantic models (`ScanResult`, `Vulnerability`, `SchemaResult`, `ExposedFile`). Scans are automatically persisted to SQLite via the `Store`.

## 📁 Project structure

```text
src/phpfossil/
├── __init__.py          # Public API, models, scan_targets, generate_dorks, generate_report
├── cli.py               # Typer commands: scan, dorks, report, list, history
├── models.py            # Pydantic models (ScanResult, Vulnerability, SchemaResult, ExposedFile)
├── scanner.py           # Async scanning, _probe_target, rate limiting, proxy rotation
├── fingerprinter.py     # detect_from_headers, detect_from_body, detect_from_phpinfo, detect_from_error_page
├── vulndb.py            # _get_embedded_vulndb, get_vulns_for_version
├── schema.py            # parse_sql_dump, locate_sql_urls
├── search.py            # DorkGenerator with 18 templates
├── reporter.py          # ReportGenerator.to_terminal, to_html + default Jinja template
├── store.py             # Persistent SQLite store with automatic history tracking
└── pyproject.toml       # Dependencies, console script entrypoint

examples/
├── scan_targets.py      # Runnable library API demo
└── custom_dorks.py      # Extending DorkGenerator

tests/
├── test_scanner.py      # Tests for fingerprinting, async mocks, exposed files, Store
├── test_vulndb.py       # CVE mapping, severity, EOL checks
├── test_fingerprinter_cms.py  # New tests for CMS version detection
```

## 🧪 Testing

First install with test dependencies:

```bash
pip install -e ".[dev]"
pytest
```

Tests cover `detect_php_version` accuracy, `scan_targets` with `pytest-httpx` mocks, `parse_sql_dump`, VulnDB lookup, CLI commands, JSON serialization of `ScanResult` objects and the new persistent `Store`.

## 📍 Roadmap

<!-- roadmap:start -->
- [x] **v0.1.0** — first release: Dork Generator, Version Fingerprint, Vuln Database, Schema Extractor
- [x] Add proxy rotation and residential proxy support
- [x] Persistent SQLite store for historical scan results
- [x] WordPress/Joomla/Laravel specific version fingerprinting
- [ ] Integration with Nuclei for deeper exploit validation
- [ ] Local LLM (Ollama) summaries of discovered issues
- [ ] Interactive terminal TUI with textual for live scanning
- [ ] GitHub Action for scheduled scans of your own domains
- [ ] CSV export compatible with bug-bounty platforms
- [ ] Shodan and Censys API modules for passive discovery
- [ ] Community fingerprint repository loader
- [ ] Severity scoring that factors in exposed schema sensitivity
- [ ] Dark-mode HTML report with sortable vulnerability table

> 🤖 This roadmap is worked through continuously — ideas and PRs welcome!
<!-- roadmap:end -->

## 🤝 Contributing

We love community contributions! Whether it's a new fingerprint technique, additional CVE data, improved HTML templates, or better dork templates — every PR helps.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and follow our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Issues labeled **good first issue** are perfect for your first PR. Join us in making legacy PHP discovery faster and safer.

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

<!-- footer:start -->
<div align="center">

### ⭐ Star history

<a href="https://star-history.com/#ajendras/php-fossil&Date"><img src="https://api.star-history.com/svg?repos=ajendras/php-fossil&type=Date" alt="Star history" width="600"></a>

If **PHP Fossil** saves you time, a ⭐ helps others find it.

Made with ❤️ by [Ajendra](https://ajendra.info)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2e8b57,100:daa520&height=120&section=footer" width="100%" alt="">

</div>
<!-- footer:end -->
