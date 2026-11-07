"""Vulnerability database utilities for PHP Fossil.

Provides functions to load the embedded CVE data and query it for
specific PHP versions. Returns Pydantic ``Vulnerability`` objects.
"""

from __future__ import annotations

from typing import Dict, List

from .models import Vulnerability


def _get_embedded_vulndb() -> Dict[str, List[Vulnerability]]:
    """Return a small embedded database of PHP CVEs.

    In production this would load from a JSON file packaged with the module.
    """
    return {
        "5.": [
            Vulnerability(
                cve="CVE-2012-1823",
                title="PHP CGI Argument Injection",
                severity="critical",
                description="Unauthenticated remote code execution via specially crafted HTTP parameters.",
                fixed_in="5.4.3",
                reference="https://www.php.net/releases/5_4_3.php",
            ),
            Vulnerability(
                cve="CVE-2018-19518",
                title="PHP IMAP Open RCE",
                severity="high",
                description="Remote code execution when imap_open is used with attacker-controlled input.",
                fixed_in="5.6.39",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2018-19518",
            ),
            Vulnerability(
                cve="CVE-2019-11043",
                title="PHP-FPM underflow RCE",
                severity="critical",
                description="Potential remote code execution in PHP-FPM.",
                fixed_in="7.3.12",
                reference="https://www.php.net/releases/7_3_12.php",
            ),
            Vulnerability(
                cve="CVE-2020-7069",
                title="PHP URL Parsing Vulnerability",
                severity="high",
                description="SSRF and other issues due to URL parsing bug.",
                fixed_in="7.4.6",
                reference="https://www.php.net/releases/7_4_6.php",
            ),
            Vulnerability(
                cve="CVE-2021-21702",
                title="PHP Hash Collision Denial of Service",
                severity="medium",
                description="DoS via specially crafted HTTP parameters.",
                fixed_in="8.0.12",
                reference="https://www.php.net/releases/8.0.12.php",
            ),
            Vulnerability(
                cve="CVE-2022-31628",
                title="PHP 8.1.0 Core Vulnerability",
                severity="high",
                description="Buffer overflow in PHP core affecting older versions too.",
                fixed_in="8.1.1",
                reference="https://www.php.net/releases/8.1.1.php",
            ),
        ],
        "7.4": [
            Vulnerability(
                cve="CVE-2021-21702",
                title="PHP Hash Collision Denial of Service",
                severity="medium",
                description="DoS via specially crafted HTTP parameters.",
                fixed_in="8.0.12",
                reference="https://www.php.net/releases/8.0.12.php",
            ),
        ],
    }


def get_vulns_for_version(version: str) -> List[Vulnerability]:
    """Get all vulnerabilities associated with a given PHP version.

    Matches on major version prefixes.
    """
    if not version or not isinstance(version, str):
        return []

    db = _get_embedded_vulndb()
    vulns: List[Vulnerability] = []
    v_prefix = version.strip()[:3]  # e.g. '5.6' or '7.4' or '8.0'

    for key, entries in db.items():
        if v_prefix.startswith(key.replace(".", "")) or key.startswith(v_prefix):
            vulns.extend(entries)

    # Deduplicate
    seen = {}
    unique = []
    for v in vulns:
        if v.cve not in seen:
            seen[v.cve] = True
            unique.append(v)
    return unique


__all__ = ["get_vulns_for_version"]
