"""Passive discovery using Shodan and Censys APIs.

Uses direct httpx calls (no extra SDK dependencies). Returns list[str] of
URLs for compatibility with passive_discover() and the CLI. ShodanSearcher
and CensysSearcher classes return PassiveResult objects for testability.
"""

import re
from typing import List, Optional
import httpx

from .models import PassiveResult


def search_shodan(query: str, shodan_key: Optional[str] = None, limit: int = 10) -> List[str]:
    """Search Shodan for PHP-related hosts. Returns list of constructed URLs."""
    if not shodan_key:
        return []
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": shodan_key, "query": query, "limit": min(limit, 100)},
            )
            resp.raise_for_status()
            data = resp.json()
            urls: List[str] = []
            for match in data.get("matches", [])[:limit]:
                ip = match.get("ip_str")
                if not ip:
                    continue
                port = match.get("port", 80)
                hostnames = match.get("hostnames") or []
                hostname = hostnames[0] if hostnames else ip
                scheme = "https" if any(s in str(match).lower() for s in ("ssl", "https", "443")) else "http"
                url = f"{scheme}://{hostname}"
                if port not in (80, 443):
                    url += f":{port}"
                urls.append(url)
            return list(dict.fromkeys(urls))  # preserve order, deduplicate
    except Exception:
        return []


def search_censys(
    query: str,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Search Censys for PHP hosts. Returns list of constructed URLs."""
    if not censys_id or not censys_secret:
        return []
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"query": query, "per_page": min(limit, 100)},
                auth=(censys_id, censys_secret),
            )
            resp.raise_for_status()
            data = resp.json()
            urls: List[str] = []
            for hit in data.get("result", {}).get("hits", [])[:limit]:
                ip = hit.get("ip")
                if not ip:
                    continue
                for service in hit.get("services", []):
                    port = service.get("port", 80)
                    service_name = str(service.get("service_name", "")).upper()
                    scheme = "https" if "HTTPS" in service_name or port == 443 else "http"
                    url = f"{scheme}://{ip}"
                    if port not in (80, 443):
                        url += f":{port}"
                    urls.append(url)
                    break
            return list(dict.fromkeys(urls))
    except Exception:
        return []


def passive_discover(
    query: str = 'php "Version"',
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 20,
) -> List[str]:
    """Orchestrates Shodan + Censys discovery and returns unique target URLs."""
    urls: List[str] = []
    shodan_results = search_shodan(query, shodan_key, limit // 2)
    urls.extend(shodan_results)
    censys_results = search_censys(query, censys_id, censys_secret, limit // 2)
    urls.extend(censys_results)

    # deduplicate while preserving order
    seen = set()
    unique: List[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique[:limit]


class ShodanSearcher:
    """Testable wrapper around search_shodan that returns PassiveResult objects."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        urls = search_shodan(query, self.api_key, limit)
        return [PassiveResult(url=url, source="shodan", details={}) for url in urls]


class CensysSearcher:
    """Testable wrapper around search_censys that returns PassiveResult objects."""

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id
        self.api_secret = api_secret

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        urls = search_censys(query, self.api_id, self.api_secret, limit)
        return [PassiveResult(url=url, source="censys", details={}) for url in urls]
