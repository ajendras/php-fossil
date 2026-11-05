# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-05

### Added

- Dork Generator — Produces ready-to-use Google/Bing/Shodan dorks targeting specific PHP versions and signatures
- Version Fingerprint — Detects exact PHP version from headers, X-Powered-By, error pages and phpinfo()
- Vuln Database — Matches versions against 180+ embedded CVEs with severity and exploit links
- Schema Extractor — Locates and parses exposed .sql files to list tables, columns and sample data
- List Manager — Saves, filters and exports curated lists of at-risk domains with metadata
- Rich Reports — Terminal tables plus interactive HTML reports with severity coloring
- Async Scanner — Concurrent HTTP checks with configurable rate limits and retries
- Extensible Core — Clean module API for adding new fingerprint methods or data sources
