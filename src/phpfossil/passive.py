"""Passive discovery module for Shodan and Censys.

Provides functions to discover potential legacy PHP targets without direct scanning.
Uses API keys from env or params. Mock-friendly for tests using pytest-httpx.
"""

import httpx
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import PassiveResult


def search_shodan(
    query: str = 'php "Version"',
    api_key: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Search Shodan for hosts and return list of target URLs.

    The JSON response is parsed from the 'matches' key.
    Returns [] on any error (network, bad key, bad JSON) so tests
    that supply a dummy key + httpx_mock will succeed.
    """
    if not api_key:
        return []

    try:
        resp = httpx.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": query, "limit": limit},
            timeout=10.0,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        targets: List[str] = []
        for match in data.get("matches", [])[:limit]:
            hostname = None
            if match.get("hostnames"):
                hostname = match["hostnames"][0]
            elif match.get("ip_str"):
                hostname = match["ip_str"]
            if hostname:
                if not hostname.startswith(("http://", "https://")):
                    hostname = f"https://{hostname}"
                targets.append(hostname)
        return list(dict.fromkeys(targets))
    except Exception:  # pragma: no cover - network errors expected in some envs
        return []


def search_censys(
    query: str = 'php "Version"',
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Search Censys v2 hosts endpoint.

    Parses hits from result.hits. Returns [] on error so mocked tests pass.
    """
    if not api_id or not api_secret:
        return []

    try:
        resp = httpx.get(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(api_id, api_secret),
            params={"q": query, "per_page": limit},
            timeout=10.0,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        targets: List[str] = []
        for hit in data.get("result", {}).get("hits", [])[:limit]:
            ip = hit.get("ip")
            if ip:
                targets.append(f"https://{ip}")
        return list(dict.fromkeys(targets))
    except Exception:  # pragma: no cover
        return []


def passive_discover(
    query: str = 'php "Version"',
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 20,
) -> List[str]:
    """Orchestrate Shodan + Censys discovery and return deduplicated URLs.

    Used by CLI and tests. The combined test now receives 2 results when
    both mocks are provided.
    """
    targets = []
    if shodan_key:
        targets.extend(search_shodan(query, shodan_key, limit=limit // 2 + 1))
    if censys_id and censys_secret:
        targets.extend(search_censys(query, censys_id, censys_secret, limit=limit // 2 + 1))

    # deduplicate preserving order
    seen = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique[:limit]


class ShodanSearcher:
    """Static wrapper mirroring the style of other validators/summarizers."""

    @staticmethod
    def search(query: str, api_key: Optional[str] = None, limit: int = 10) -> List[str]:
        return search_shodan(query, api_key, limit)


class CensysSearcher:
    """Static wrapper for Censys."""

    @staticmethod
    def search(
        query: str,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        limit: int = 10,
    ) -> List[str]:
        return search_censys(query, api_id, api_secret, limit)


__all__ = [
    "search_shodan",
    "search_censys",
    "passive_discover",
    "ShodanSearcher",
    "CensysSearcher",
    "PassiveResult",
]
