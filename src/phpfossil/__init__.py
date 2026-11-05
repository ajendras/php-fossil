"""PHP Fossil — discovers legacy PHP sites via search dorks, fingerprints old versions,
maps vulns, extracts schemas and builds prioritized security lists.

Public API:
    scan_targets, generate_dorks, generate_report, ScanResult, Vulnerability
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from bs4 import BeautifulSoup
from jinja2 import Template
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

__version__ = "0.1.0"

console = Console()


class Vulnerability(BaseModel):
    """Represent a known vulnerability tied to a PHP version."""

    cve: str
    title: str
    severity: str
    description: str
    fixed_in: Optional[str] = None
    reference: Optional[str] = None


class ExposedFile(BaseModel):
    """Represent a sensitive file discovered on a target (phpinfo, SQL dump, etc)."""

    url: str
    file_type: str
    content_preview: Optional[str] = None


class SchemaResult(BaseModel):
    """Parsed information from an exposed SQL dump."""

    tables: List[str] = Field(default_factory=list)
    columns: Dict[str, List[str]] = Field(default_factory=dict)
    row_counts: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of scanning one target."""

    url: str
    php_version: Optional[str] = Field(None, description="Detected PHP version string")
    detected_from: List[str] = Field(default_factory=list)
    vulns: List[Vulnerability] = Field(default_factory=list)
    exposed_files: List[ExposedFile] = Field(default_factory=list)
    schema: Optional[SchemaResult] = None
    errors: List[str] = Field(default_factory=list)
    scan_time: datetime = Field(default_factory=datetime.utcnow)

    def is_vulnerable(self) -> bool:
        """Return True if any vulnerabilities were found."""
        return len(self.vulns) > 0


def _get_embedded_vulndb() -> Dict[str, List[Vulnerability]]:
    """Return a small embedded database of PHP CVEs."""
    return {
        "5.": [
            Vulnerability(
                cve="CVE-2012-1823",
                title="PHP CGI Argument Injection",
                severity="critical",
                description="Unauthenticated remote code execution via query string.",
                fixed_in="5.4.3",
                reference="https://www.php.net/ChangeLog-5.php#5.4.3",
            ),
            Vulnerability(
                cve="CVE-2018-19518",
                title="PHP IMAP Open RCE",
                severity="high",
                description="Remote code execution when imap_open is used with attacker-controlled input.",
                fixed_in="5.6.39",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2018-19518",
            ),
        ],
        "7.0": [
            Vulnerability(
                cve="CV-2019-11043",
                title="PHP-FPM Remote Code Execution",
                severity="critical",
                description="RCE when Nginx and PHP-FPM are misconfigured.",
                fixed_in="7.3.12",
                reference="https://www.rapid7.com/db/vulnerabilities/php-cve-2019-11043/",
            ),
        ],
        "8.0": [
            Vulnerability(
                cve="CVE-2021-21702",
                title="Hash ...",
                severity="medium",
                description="CPU exhaustion via specially crafted HTTP...",
                fixed_in="8.0.12",
                reference="https://www.php.net/releases/8.0.12.php",
            ),
        ],
    }


def get_vulns_for_version(version: str) -> List[Vulnerability]:
    """Return ... (same as before, omitted for brevity)"""
    if not version:
        return []
    db = _get_embedded_vulndb()
    for prefix, entries in db.items():
        if version.startswith(prefix):
            return entries
    if version.startswith(("4.", "5.", "6.", "7.0", "7.1", "7.2")):
        return db.get("5.", [])
    return []


def parse_sql_dump(content: str) -> SchemaResult:
    """Simple regex-based parser for SQL dumps. Extracts table names and columns."""
    tables: List[str] = re.findall(r"(?i)CREATE TABLE\s+[`']?(\w+)[`']?", content)
    unique_tables = list(dict.fromkeys(tables))

    columns: Dict[str, List[str]] = {}
    for table in unique_tables:
        match = re.search(
            rf"(?i)CREATE TABLE[^`]*[`']?{re.escape(table)}[`']?\s*\((.+?)\)[^;]*;",
            content,
            re.DOTALL,
        )
        if match:
            col_defs = match.group(1)
            col_names = re.findall(r"[`']?(\w+)[`']?\s+\w+", col_defs)
            columns[table] = col_names

    return SchemaResult(tables=unique_tables, columns=columns)


# Public API functions (scan_targets, generate_dorks, generate_report) remain unchanged.
# ... (rest of the file unchanged)
