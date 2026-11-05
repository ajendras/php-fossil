"""DorkGenerator for PHP Fossil.

Produces ready-to-use Google, Bing, Shodan and GitHub dorks targeting
specific PHP versions, error signatures, phpinfo() pages and SQL dumps.
"""

import re
from typing import List

from rich.console import Console

console = Console()


class DorkGenerator:
    """Generates search dorks for discovering legacy PHP installations.

    Uses 18 distinct template patterns with version interpolation and
    additional operators to increase recall while reducing noise.
    """

    # 18 carefully chosen templates covering multiple vectors
    TEMPLATES = [
        'intitle:"phpinfo()" "PHP Version {version}"',
        '"X-Powered-By: PHP/{version}"',
        'inurl:(phpinfo.php|info.php) "PHP Version {version}"',
        '"PHP/{version}" intitle:"index of"',
        'intext:"PHP Version {version}" filetype:php',
        '"Powered by PHP {version}" -inurl:(github.com|gitlab.com|bitbucket.org)',
        'inurl:admin "PHP {version}"',
        'ext:sql ("mysqldump" OR "phpMyAdmin") "{version}"',
        '"Server: Apache" "PHP/{version}"',
        'inurl:backup intitle:"index of" "{version}"',
        '"Deprecated:" "{version}" inurl:.php',
        'intext:"PHP Parse error" "{version}"',
        'intext:"PHP Warning:" inurl:.php "{version}"',
        '"mysql_connect" "{version}" -inurl:(github|gitlab)',
        'site:.edu "PHP {version}"',
        'site:.gov inurl:phpinfo "{version}"',
        '"X-Powered-By" "PHP" "{version}"',
        'inurl:wp-content "PHP {version}"',
    ]

    @staticmethod
    def generate(version: str, count: int = 12) -> List[str]:
        """Generate list of search dorks for a specific PHP version.

        Substitutes {version} into 18 templates, adds common modifiers
        (inurl:admin, intitle:index.of, etc.) and returns unique results.

        Args:
            version: PHP version string (e.g. '7.4.33' or '5.6').
            count: Desired number of dorks (default 12, max 30).

        Returns:
            List of unique dork strings ready for search engines.

        Raises:
            ValueError: On invalid version or count.
        """
        if not version or not isinstance(version, str):
            raise ValueError("version must be a non-empty string (e.g. '7.4.33')")

        version = version.strip()
        if not re.match(r"^\d+\.\d+", version):
            raise ValueError(
                "version must begin with major.minor (e.g. '7.4' or '8.0.12')"
            )

        if not isinstance(count, int) or count < 1:
            raise ValueError("count must be a positive integer")

        # Cap reasonable output size
        count = min(count, 30)

        dorks: List[str] = []
        templates = DorkGenerator.TEMPLATES

        # First pass: direct template substitution
        i = 0
        while len(dorks) < count and i < len(templates) * 2:
            template = templates[i % len(templates)]
            dork = template.format(version=version)
            if dork not in dorks:
                dorks.append(dork)
            i += 1

        # Second pass: add common modifiers for variety
        modifiers = [
            "inurl:admin",
            "inurl:login",
            "intitle:index.of",
            "inurl:backup",
            "site:.com",
            "",
        ]

        for modifier in modifiers:
            if len(dorks) >= count:
                break
            for template in templates[:5]:  # reuse first 5 for modifiers
                base = template.format(version=version)
                dork = f"{modifier} {base}".strip()
                if dork not in dorks:
                    dorks.append(dork)

        final_dorks = dorks[:count]

        # Optional verbose output when run directly
        if __name__ == "__main__":
            console.print(
                f"[bold green]Generated {len(final_dorks)} dorks for PHP {version}:[/]"
            )
            for idx, dork in enumerate(final_dorks, 1):
                console.print(f"  {idx:2}. [cyan]{dork}[/]")

        return final_dorks

    @staticmethod
    def generate_for_range(
        start_version: str, end_version: str, per_version: int = 8
    ) -> List[str]:
        """Utility to generate dorks for a version range (e.g. 7.0 to 7.4).

        Useful for broad reconnaissance campaigns.
        """
        if not start_version or not end_version:
            raise ValueError("Both start_version and end_version are required")

        all_dorks: List[str] = []
        # Simple linear major.minor progression (demo implementation)
        for minor in range(0, 5):
            v = f"7.{minor}"
            try:
                dorks = DorkGenerator.generate(v, per_version)
                all_dorks.extend(dorks)
            except ValueError:
                continue

        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for d in all_dorks:
            if d not in seen:
                seen.add(d)
                unique.append(d)
        return unique[: per_version * 4]


def generate_dorks(version: str, count: int = 12) -> List[str]:
    """Public convenience function matching the API exposed in __init__.py."""
    return DorkGenerator.generate(version, count)


__all__ = ["DorkGenerator", "generate_dorks"]
