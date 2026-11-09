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
        "wordpress-file-inclusion",
        "php-rce-generic",
    ]
    templates.extend(generic)
    # Deduplicate while preserving order
    seen = dict.fromkeys(templates)
    return list(seen)[:15]  # reasonable limit


def parse_nuclei_output(output: str) -> List[NucleiFinding]:
    """Parse JSON-lines output from Nuclei into NucleiFinding models.

    Handles both single JSON objects and JSON-lines format.
    """
    findings: List[NucleiFinding] = []
    lines = output.strip().splitlines()
    for line in lines:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            finding = NucleiFinding.model_validate(data)
            findings.append(finding)
        except (json.JSONDecodeError, ValueError):
            # Try to build manually if the structure differs slightly
            try:
                info = data.get("info", {}) if isinstance(data, dict) else {}
                finding = NucleiFinding(
                    template=data.get("template-id", "") if isinstance(data, dict) else "",
                    name=info.get("name", "Unknown") if isinstance(info, dict) else "Unknown",
                    severity=info.get("severity", "medium") if isinstance(info, dict) else "medium",
                    matched_at=data.get("matched-at") if isinstance(data, dict) else None,
                    description=info.get("description") if isinstance(info, dict) else None,
                )
                findings.append(finding)
            except Exception:  # noqa: BLE001
                continue
    return findings


def validate_with_nuclei(
    url: str,
    vulns: List[Vulnerability],
    timeout: int = 15,
    extra_templates: Optional[List[str]] = None,
) -> List[NucleiFinding]:
    """Run Nuclei against a target to validate discovered vulnerabilities.

    Uses templates derived from the supplied CVEs plus generic PHP templates.
    Returns a list of NucleiFinding objects (empty on error).

    Args:
        url: Target URL to scan.
        vulns: Vulnerabilities to map into templates.
        timeout: Per-request timeout for Nuclei.
        extra_templates: Additional template IDs to include.

    Returns:
        List of confirmed Nuclei findings.
    """
    if not url or not isinstance(url, str):
        return [NucleiFinding(template="error", name="Invalid URL", severity="low")]

    if not vulns:
        return []

    templates = get_nuclei_templates_for_vulns(vulns)
    if extra_templates:
        templates = list(dict.fromkeys(templates + extra_templates))

    cmd = [
        "nuclei",
        "-target", url,
        "-id", ",".join(templates),
        "-json",
        "-silent",
        "-timeout", str(timeout),
        "-no-color",
        "-disable-update-check",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

        if proc.returncode not in (0, 1):
            stderr = proc.stderr.strip()
            if "command not found" in stderr.lower() or "no such file" in stderr.lower():
                return [
                    NucleiFinding(
                        template="error",
                        name="Nuclei binary not found",
                        severity="low",
                        description="Install from https://nuclei.projectdiscovery.io",
                    )
                ]
            return [
                NucleiFinding(
                    template="error",
                    name="Nuclei execution error",
                    severity="low",
                    description=stderr or "Unknown error",
                )
            ]

        return parse_nuclei_output(proc.stdout)

    except subprocess.TimeoutExpired:
        return [
            NucleiFinding(
                template="error",
                name="Nuclei timeout",
                severity="low",
                description="Scan exceeded timeout",
            )
        ]
    except FileNotFoundError:
        return [
            NucleiFinding(
                template="error",
                name="Nuclei not installed",
                severity="low",
                description="nuclei binary must be in PATH",
            )
        ]
    except Exception as exc:  # noqa: BLE001
        return [
            NucleiFinding(
                template="error",
                name="Unexpected error",
                severity="low",
                description=str(exc),
            )
        ]


class NucleiValidator:
    """Object-oriented wrapper for Nuclei validation (for extensibility)."""

    @staticmethod
    def validate(
        target_url: str, vulns: List[Vulnerability], timeout: int = 15
    ) -> List[NucleiFinding]:
        """Run validation and return findings."""
        return validate_with_nuclei(target_url, vulns, timeout=timeout)


__all__ = [
    "validate_with_nuclei",
    "get_nuclei_templates_for_vulns",
    "parse_nuclei_output",
    "NucleiValidator",
]
