"""Nuclei integration for PHP Fossil.

Provides functions to run Nuclei templates for deeper exploit validation
of discovered vulnerabilities. Requires the nuclei binary to be installed
and available in PATH (https://nuclei.projectdiscovery.io).

Uses CVE-based template IDs where possible and falls back to generic PHP
templates. Output is parsed into NucleiFinding Pydantic models.
"""

import json
import subprocess
from typing import Any, Dict, List, Optional

from .models import NucleiFinding, Vulnerability


def get_nuclei_templates_for_vulns(vulns: List[Vulnerability]) -> List[str]:
    """Map CVEs to Nuclei template IDs.

    Many Nuclei templates are named after their CVE (e.g. cve-2019-11043).
    Additional generic PHP templates are appended for broader coverage.

    Args:
        vulns: List of Vulnerability objects.

    Returns:
        List of unique template IDs suitable for nuclei -id.
    """
    templates: List[str] = []
    for v in vulns:
        if v.cve and v.cve.upper().startswith("CVE-"):
            templates.append(v.cve.lower().replace("cve-", "cve-"))

    # Generic high-value PHP templates
    generic = [
        "phpinfo-detect",
        "exposed-debug-page",
        "php-cgi-arg-injection",
        "laravel-debug-mode",
        "phpmyadmin-setup",
        "wordpress-old-version",
        "joomla-rce",
        "drupal-rce",
    ]
    templates.extend(generic)
    # deduplicate while preserving order
    return list(dict.fromkeys(templates))


def validate_with_nuclei(
    target: str, vulns: List[Vulnerability], timeout: int = 30
) -> List[NucleiFinding]:
    """Run Nuclei against the target using templates derived from the vulns.

    Returns list of NucleiFinding objects parsed from JSONL output.
    Gracefully handles missing binary, timeouts, and parsing errors.
    """
    templates = get_nuclei_templates_for_vulns(vulns)
    if not templates:
        return []

    cmd = [
        "nuclei",
        "-target",
        target,
        "-id",
        ",".join(templates),
        "-jsonl",
        "-silent",
        "-timeout",
        str(timeout),
        "-no-color",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            check=False,
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    findings.append(NucleiFinding.model_validate(data))
                except json.JSONDecodeError:
                    continue
        return findings
    except subprocess.TimeoutExpired:
        return [
            NucleiFinding(
                template="timeout",
                name="Nuclei scan timeout",
                severity="medium",
                description="Nuclei scan timed out",
            )
        ]
    except FileNotFoundError:
        return [
            NucleiFinding(
                template="nuclei-not-found",
                name="Nuclei not installed",
                severity="info",
                description="Install nuclei to enable deep exploit validation",
            )
        ]
    except Exception as exc:  # noqa: BLE001
        return [
            NucleiFinding(
                template="error",
                name="Nuclei error",
                severity="low",
                description=str(exc),
            )
        ]


class NucleiValidator:
    """Wrapper class mirroring style of CommunityFingerprinter / OllamaSummarizer."""

    @staticmethod
    def validate(target: str, vulns: List[Vulnerability]) -> List[NucleiFinding]:
        """Run validation (static helper)."""
        return validate_with_nuclei(target, vulns)


__all__ = [
    "validate_with_nuclei",
    "NucleiValidator",
    "get_nuclei_templates_for_vulns",
]
