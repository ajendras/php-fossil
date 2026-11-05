#!/usr/bin/env python3
"""Example: Extending DorkGenerator with user-defined templates.

Demonstrates:
- Subclassing DorkGenerator to add specialized search patterns
- Dynamic template injection for bug-bounty or region-specific hunting
- Simulated integration with external search APIs (Google, Shodan, Bing)
- Runnable without external credentials — prints ready-to-use dorks

Run with: python examples/custom_dorks.py
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from phpfossil.search import DorkGenerator


class CustomDorkGenerator(DorkGenerator):
    """Extended dork generator with specialized templates.

    Adds patterns useful for:
      - Bug bounty programs
      - Government / education targets
      - Exposed admin panels and SQL dumps
      - Version-specific error messages
    """

    # Additional high-signal templates
    EXTRA_TEMPLATES = [
        'intitle:"phpinfo()" "PHP Version {version}" inurl:(admin|login|dashboard)',
        'inurl:(backup|dump|export) ext:sql "{version}"',
        '"X-Powered-By: PHP/{version}" (site:.gov OR site:.edu)',
        'intext:"PHP Parse error" "{version}" -inurl:(github.com|gitlab.com)',
        'intitle:"index of" "php {version}" "parent directory"',
        '"mysql_connect" "{version}" filetype:php inurl:(wp-admin|administrator)',
        'inurl:phpmyadmin "Version {version}"',
        '"Deprecated: preg_replace()" "{version}"',
    ]

    def generate(
        self,
        version: str,
        count: int = 12,
        include_custom: bool = True,
        extra_prefixes: List[str] | None = None,
    ) -> List[str]:
        """Generate dorks using both base and custom templates.

        Args:
            version: PHP version string (e.g. '7.4.33')
            count: Maximum number of dorks to return
            include_custom: Whether to mix in the EXTRA_TEMPLATES
            extra_prefixes: Optional additional operators (e.g. 'site:example.com')

        Returns:
            List of unique, ready-to-paste dorks.
        """
        if extra_prefixes is None:
            extra_prefixes = ["", "inurl:admin", "intitle:index.of"]

        # Start with the parent's generation logic
        base_dorks = super().generate(version, count=count // 2)

        dorks: List[str] = list(base_dorks)

        if include_custom:
            version_templates = [
                t.format(version=version) for t in self.EXTRA_TEMPLATES
            ]
            for prefix in extra_prefixes:
                for template in version_templates:
                    candidate = f"{prefix} {template}".strip()
                    if candidate not in dorks:
                        dorks.append(candidate)
                    if len(dorks) >= count:
                        break
                if len(dorks) >= count:
                    break

        return dorks[:count]


def simulate_search_api(dorks: List[str], engine: str = "shodan", limit: int = 3) -> List[Dict[str, Any]]:
    """Simulate calling an external search engine API.

    In a real integration you would replace this with:
        - google-api-python-client or serpapi for Google
        - shodan python library for Shodan
        - bing-web-search for Microsoft Cognitive Services
    """
    print(f"\n[bold]Simulating {engine.upper()} search for first {limit} dorks:[/]")

    simulated_results = []
    for dork in dorks[:limit]:
        print(f"  Query → {dork}")
        # Fake result payload
        simulated_results.append(
            {
                "dork": dork,
                "engine": engine,
                "estimated_hits": 1240 if "phpinfo" in dork else 340,
                "sample_url": "https://legacy.example.com/info.php",
                "notes": "Contains X-Powered-By header with target version",
            }
        )

    # Optionally persist results for later triage
    out_path = Path(f"custom_dorks_{engine}.json")
    out_path.write_text(
        json.dumps(simulated_results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"  Saved simulated results to {out_path.name}")

    return simulated_results


def main() -> None:
    """Demonstrate custom dork generation and search integration."""
    print("PHP Fossil — Custom DorkGenerator Example")
    print("=" * 55)

    generator = CustomDorkGenerator()

    # Generate extended dorks for a legacy version commonly seen in the wild
    version = "7.4.33"
    dorks = generator.generate(
        version=version,
        count=15,
        include_custom=True,
        extra_prefixes=["site:.gov", "inurl:wp-content", ""],
    )

    print(f"\nGenerated {len(dorks)} dorks targeting PHP {version}:\n")
    for i, dork in enumerate(dorks, 1):
        print(f"  {i:2d}. [cyan]{dork}[/]")

    # Demonstrate integration with external search engines
    simulate_search_api(dorks, engine="shodan")
    simulate_search_api(dorks, engine="google", limit=2)

    print("\n[bold green]Next steps:[/]")
    print("  • Replace simulate_search_api() with real API clients")
    print("  • Feed discovered hosts into php-fossil scan --file results.txt")
    print("  • Extend EXTRA_TEMPLATES with new vectors (e.g. CVE-specific signatures)")


if __name__ == "__main__":
    main()
