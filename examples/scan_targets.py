#!/usr/bin/env python3
"""Runnable example using the PHP Fossil library API directly.

Demonstrates:
- Direct use of scan_targets() with custom concurrency/timeout settings
- Processing ScanResult objects
- Generating both terminal and HTML reports
- Accessing rich metadata (version, vulns, exposed files, schema)

Run with: python examples/scan_targets.py
"""

from pathlib import Path
from typing import Any

from phpfossil import (
    ScanResult,
    generate_report,
    generate_dorks,
    scan_targets,
)


def main() -> None:
    """Run a demonstration scan using the public library API."""
    print("PHP Fossil — Library API Example")
    print("=" * 55)

    # Safe demonstration targets (no real production systems)
    targets = [
        "https://httpbin.org",
        "https://example.com",
        "http://neverssl.com",
    ]

    # Custom configuration passed to the async scanner
    config: dict[str, Any] = {
        "max_concurrency": 8,
        "timeout": 10,
        "retries": 2,
    }

    print(f"Scanning {len(targets)} targets with concurrency={config['max_concurrency']}...\n")

    # Core API call — fully async under the hood with rate limiting
    results: list[ScanResult] = scan_targets(targets, config=config)

    # Print summary before rich output
    php_detected = sum(1 for r in results if r.php_version is not None)
    vulnerable = sum(1 for r in results if r.is_vulnerable())
    exposed = sum(len(r.exposed_files) for r in results)

    print(f"Scan complete — {php_detected} PHP instances detected.")
    print(f"  • {vulnerable} targets with known vulnerabilities")
    print(f"  • {exposed} exposed sensitive files discovered\n")

    # Terminal report (rich tables with color)
    generate_report(results, output_format="terminal")

    # Generate a polished standalone HTML report
    report_path = Path("example_phpfossil_report.html")
    html_content = generate_report(
        results,
        output_format="html",
        output_path=report_path,
    )

    if html_content and report_path.exists():
        print(f"\n[green]Interactive HTML report written to[/] {report_path.resolve()}")
        print("   Open the file in your browser for severity-colored findings.")

    # Demonstrate direct data access for custom workflows
    print("\nDetailed findings from first result:")
    if results:
        first = results[0]
        print(f"  URL: {first.url}")
        print(f"  Detected version: {first.php_version or 'None'}")
        print(f"  Detected via: {', '.join(first.detected_from) or 'N/A'}")
        print(f"  Vulnerabilities: {len(first.vulns)}")
        if first.exposed_files:
            print("  Exposed files:")
            for ef in first.exposed_files:
                print(f"    • {ef.file_type} → {ef.url}")
        if first.schema and first.schema.tables:
            print(f"  Schema extracted: {len(first.schema.tables)} tables")

    # Show how dorks can be generated for the discovered version
    if any(r.php_version for r in results):
        version = next((r.php_version for r in results if r.php_version), "7.4.33")
        print(f"\nGenerated dorks for discovered version {version}:")
        dorks = generate_dorks(version, count=5)
        for i, dork in enumerate(dorks, 1):
            print(f"  {i}. {dork}")


if __name__ == "__main__":
    main()
