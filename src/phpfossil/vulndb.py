"""Vulnerability database utilities for PHP Fossil.

Provides functions to load the embedded CVE data and query it for
specific PHP versions. Returns Pydantic ``Vulnerability`` objects.
"""

from __future__ import annotations

from typing import Dict, List

from .models import Vulnerability
from .scanner import _get_embedded_vulndb  # Reuse the scanner's embedded DB


def load() -> List[Vulnerability]:
    """Load all vulnerability entries from the embedded database.

    Returns a list of :class:`~phpfossil.models.Vulnerability` objects.
    """
    db = _get_embedded_vulndb()
    # Flatten all entries into a single list
    all_vulns: List[Vulnerability] = []
    for entries in db.values():
        all_vulns.extend(entries)
    return all_vulns


def get_vulns_for_version(version: str) -> List[Vulnerability]:
    """Return known vulnerabilities for a given PHP version string.

    The lookup matches the longest prefix present in the embedded DB.
    """
    if not version:
        return []
    db = _get_embedded_vulndb()
    # Find the longest matching prefix (e.g., "5." matches "5.6.0" etc.)
    matching_prefix = ""
    for prefix in db.keys():
        if version.startswith(prefix) and len(prefix) > len(matching_prefix):
            matching_prefix = prefix
    if matching_prefix:
        return db[matching_prefix]
    # Fallback for legacy versions not explicitly listed
    if version.startswith(("4.", "5.", "6.", "7.0", "7.1", "7.2")):
        return db.get("5.", [])
    return []


__all__ = ["load", "get_vulns_for_version"]
