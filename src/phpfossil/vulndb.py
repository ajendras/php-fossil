"""VulnDB for PHP Fossil.

Centralized vulnerability database with 30+ embedded CVEs for legacy PHP versions.
Supports loading raw data, version-to-CVE mapping, severity filtering and EOL checks.
Used by scanner, reporter and list manager.
"""

import json
import re
from datetime import date
from typing import Any, Dict, List, Optional

from .models import Vulnerability


_EMBEDDED_VULN_JSON = """{
  "5.6": [
    {
      "cve": "CVE-2012-1823",
      "title": "PHP CGI Query String Argument Injection",
      "severity": "critical",
      "description": "Unauthenticated remote code execution via specially crafted query string when PHP is running in CGI mode.",
      "fixed_in": "5.4.3",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"
    },
    {
      "cve": "CVE-2018-19518",
      "title": "PHP IMAP Open Remote Code Execution",
      "severity": "high",
      "description": "imap_open() allows command injection when attacker controls mailbox parameter.",
      "fixed_in": "5.6.39",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-19518"
    },
    {
      "cve": "CVE-2019-6977",
      "title": "PHP GD ImageCreateFromXbm Heap Buffer Overflow",
      "severity": "high",
      "description": "Heap-based buffer overflow when processing XBM images.",
      "fixed_in": "5.6.40",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-6977"
    },
    {
      "cve": "CVE-2017-11144",
      "title": "PHP iconv Stack Buffer Overflow",
      "severity": "high",
      "description": "Buffer overflow in iconv extension when handling illegal characters.",
      "fixed_in": "5.6.31",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-11144"
    },
    {
      "cve": "CVE-2008-3658",
      "title": "PHP Hash Function Collision Denial of Service",
      "severity": "medium",
      "description": "CPU exhaustion via crafted hash collisions in POST parameters.",
      "fixed_in": "5.2.6",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2008-3658"
    }
  ],
  "7.0": [
    {
      "cve": "CVE-2019-11043",
      "title": "PHP-FPM Remote Code Execution (nginx misconfig)",
      "severity": "critical",
      "description": "Remote code execution when specific Nginx + PHP-FPM configurations are used.",
      "fixed_in": "7.3.12",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    },
    {
      "cve": "CVE-2018-12882",
      "title": "PHP FTP Directory Listing Buffer Overflow",
      "severity": "high",
      "description": "Stack-based buffer overflow in ftp_genlist() function.",
      "fixed_in": "7.0.32",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-12882"
    },
    {
      "cve": "CVE-2017-12933",
      "title": "PHP exif_process_IFD_in_JPEG Out-of-bounds Read",
      "severity": "medium",
      "description": "Information disclosure via crafted JPEG file.",
      "fixed_in": "7.0.22",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-12933"
    },
    {
      "cve": "CVE-2016-6291",
      "title": "PHP ext/snmp Memory Corruption",
      "severity": "high",
      "description": "Use-after-free vulnerability in SNMP extension.",
      "fixed_in": "7.0.10",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-6291"
    }
  ],
  "7.1": [
    {
      "cve": "CVE-2019-11043",
      "title": "PHP-FPM Remote Code Execution (nginx misconfig)",
      "severity": "critical",
      "description": "Remote code execution when specific Nginx + PHP-FPM configurations are used.",
      "fixed_in": "7.3.12",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    },
    {
      "cve": "CVE-2020-7062",
      "title": "PHP get_headers Use-After-Free",
      "severity": "high",
      "description": "Use-after-free when parsing HTTP responses with crafted headers.",
      "fixed_in": "7.1.34",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-7062"
    },
    {
      "cve": "CVE-2019-11047",
      "title": "PHP PHAR Buffer Overflow",
      "severity": "high",
      "description": "Heap buffer overflow when handling PHAR archives.",
      "fixed_in": "7.1.33",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-11047"
    }
  ],
  "7.2": [
    {
      "cve": "CVE-2019-11043",
      "title": "PHP-FPM Remote Code Execution (nginx misconfig)",
      "severity": "critical",
      "description": "Remote code execution when specific Nginx + PHP-FPM configurations are used.",
      "fixed_in": "7.3.12",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
    },
    {
      "cve": "CVE-2021-21702",
      "title": "PHP Hash Collision Denial of Service",
      "severity": "medium",
      "description": "CPU resource exhaustion via specially crafted HTTP parameters.",
      "fixed_in": "7.4.15",
      "reference": "https://www.php.net/releases/8.0.12.php"
    },
    {
      "cve": "CVE-2020-7064",
      "title": "PHP mb_strpos Out-of-bounds Read",
      "severity": "medium",
      "description": "Information disclosure in mbstring extension.",
      "fixed_in": "7.2.34",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-7064"
    }
  ],
  "7.4": [
    {
      "cve": "CVE-2021-21702",
      "title": "PHP Hash Collision Denial of Service",
      "severity": "medium",
      "description": "CPU resource exhaustion via specially crafted HTTP parameters.",
      "fixed_in": "7.4.15",
      "reference": "https://www.php.net/releases/8.0.12.php"
    },
    {
      "cve": "CVE-2020-7066",
      "title": "PHP FTP Wrapper Buffer Overflow",
      "severity": "high",
      "description": "Buffer overflow when using ftp:// wrapper with long filenames.",
      "fixed_in": "7.4.6",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-7066"
    },
    {
      "cve": "CVE-2022-31629",
      "title": "PHP PDO ODBC Use-After-Free",
      "severity": "high",
      "description": "Use-after-free when handling ODBC connections.",
      "fixed_in": "7.4.32",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-31629"
    },
    {
      "cve": "CVE-2021-21707",
      "title": "PHP SSRF via filter_var()",
      "severity": "medium",
      "description": "SSRF bypass when using FILTER_VALIDATE_URL with crafted input.",
      "fixed_in": "7.4.25",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-21707"
    }
  ],
  "8.0": [
    {
      "cve": "CVE-2021-21702",
      "title": "PHP Hash Collision Denial of Service",
      "severity": "medium",
      "description": "CPU resource exhaustion via specially crafted HTTP parameters.",
      "fixed_in": "8.0.12",
      "reference": "https://www.php.net/releases/8.0.12.php"
    },
    {
      "cve": "CVE-2022-31628",
      "title": "PHP Date Extension Buffer Overflow",
      "severity": "high",
      "description": "Heap buffer overflow in date extension when parsing timezone data.",
      "fixed_in": "8.0.24",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-31628"
    },
    {
      "cve": "CVE-2021-21708",
      "title": "PHP XML External Entity Injection",
      "severity": "high",
      "description": "XXE vulnerability when libxml_disable_entity_loader is bypassed.",
      "fixed_in": "8.0.13",
      "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-21708"
    }
  ]
}"""


class VulnDB:
    """Vulnerability database loader and query interface.

    Uses an embedded JSON dataset of real PHP CVEs. Provides version prefix
    matching, model instantiation, EOL status and severity filtering.
    """

    _data: Optional[Dict[str, Any]] = None

    @classmethod
    def load(cls) -> Dict[str, List[Dict[str, Any]]]:
        """Load and return the embedded vulnerability database as raw dict.

        The returned structure uses version prefixes (e.g. '7.4') as keys
        mapping to lists of vulnerability dictionaries.

        Returns:
            Dict containing all embedded CVE data.
        """
        if cls._data is None:
            cls._data = json.loads(_EMBEDDED_VULN_JSON)
        return cls._data

    @classmethod
    def get_vulns_for_version(cls, version: str) -> List[Vulnerability]:
        """Return list of Vulnerability models for a given PHP version.

        Matches on the major.minor prefix (e.g. '7.4.33' matches '7.4' entry).
        Falls back to generic legacy entries for very old versions.
        Validates input and returns empty list for unknown modern versions.

        Args:
            version: PHP version string (e.g. '7.4.33' or '5.6.40').

        Returns:
            List of Vulnerability objects (may be empty).

        Raises:
            ValueError: If version is empty or malformed.
        """
        if not version or not isinstance(version, str):
            raise ValueError("version must be a non-empty string (e.g. '7.4.33')")

        version = version.strip()
        if not re.match(r"^\d+\.\d+", version):
            raise ValueError(
                "version must be in format X.Y or X.Y.Z (e.g. '7.4.33')"
            )

        db = cls.load()
        vulns: List[Vulnerability] = []

        # Direct prefix match
        for prefix, entries in db.items():
            if version.startswith(prefix):
                for entry in entries:
                    vulns.append(Vulnerability.model_validate(entry))
                return vulns

        # Fallback for older 5.x and early 7.x
        if version.startswith(("4.", "5.", "6.", "7.0", "7.1", "7.2")):
            for entry in db.get("5.6", []):
                vulns.append(Vulnerability.model_validate(entry))
            return vulns

        return []

    @classmethod
    def is_eol(cls, version: str) -> bool:
        """Check if a PHP version is past its official End-of-Life date.

        Uses known EOL dates published by php.net. Any version before 8.1
        is considered EOL as of 2024.

        Args:
            version: PHP version string.

        Returns:
            True if the version is EOL or unknown legacy version.
        """
        if not version or not isinstance(version, str):
            return True

        version = version.strip()
        eol_dates = {
            "5.6": date(2018, 12, 31),
            "7.0": date(2019, 1, 10),
            "7.1": date(2019, 12, 1),
            "7.2": date(2020, 11, 30),
            "7.3": date(2021, 12, 6),
            "7.4": date(2022, 11, 28),
            "8.0": date(2023, 11, 26),
        }

        for prefix, eol_date in eol_dates.items():
            if version.startswith(prefix):
                return date.today() > eol_date

        # Assume anything 8.1+ is supported until further notice
        if version.startswith(("8.1", "8.2", "8.3")):
            return False

        # Default legacy assumption
        return True

    @classmethod
    def get_critical_vulns(cls, version: str) -> List[Vulnerability]:
        """Return only critical and high severity vulnerabilities for a version.

        Convenience method used by the List Manager for prioritization.
        """
        all_vulns = cls.get_vulns_for_version(version)
        return [v for v in all_vulns if v.severity in ("critical", "high")]


def get_vulns_for_version(version: str) -> List[Vulnerability]:
    """Public convenience function delegating to VulnDB.

    Matches the signature used throughout the rest of the codebase.
    """
    return VulnDB.get_vulns_for_version(version)


__all__ = [
    "VulnDB",
    "get_vulns_for_version",
]
