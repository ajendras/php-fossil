"""Passive OSINT modules for discovering PHP hosts via Shodan and Censys without direct probing.

Normalizes results into PassiveResult objects for use with the active scanner.
"""

import httpx
from typing import List, Optional
from urllib.parse import urlencode

from .models import PassiveResult


def search_shodan(
    query: str, api_key: Optional[str] = None, limit: int = 10
) -> List[PassiveResult]:
    """Query Shodan API for hosts matching a dork/query."""
    if not api_key:
        return []

    try:
        params = {"query": query, "key": api_key, "limit": str(limit)}
        url = f"https://api.shodan.io/shodan/host/search?{urlencode(params)}"

        with httpx.Client(timeout=12.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()

        results = []
        for match in data.get("matches", [])[:limit]:
            ip = match.get("ip_str")
            if not ip:
                continue
            port = match.get("port", 80)
            transport = match.get("_shodan", {}).get("module", "http")
            scheme = "https" if port == 443 or "https" in transport else "http"
            host = f"{scheme}://{ip}"
            if port not in (80, 443):
                host += f":{port}"
            results.append(
                PassiveResult(
                    source="shodan",
                    url=host,
                    ip=ip,
                    port=port,
                    banner=match.get("data") or match.get("product"),
                )
            )
        return results
    except Exception:  # network, rate limit, invalid key etc.
        return []


def search_censys(
    query: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    limit: int = 10,
) -> List[PassiveResult]:
    """Query Censys v2 API."""
    if not api_id or not api_secret:
        return []

    try:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": query, "per_page": min(limit, 100)}
        auth = (api_id, api_secret)

        with httpx.Client(timeout=12.0) as client:
            resp = client.get(url, params=params, auth=auth)
            resp.raise_for_status()
            data = resp.json()

        results = []
        for hit in data.get("result", {}).get("hits", [])[:limit]:
            ip = hit.get("ip")
            if not ip:
                continue
            services = hit.get("services", [])
            port = services[0].get("port", 80) if services else 80
            # simplistic scheme detection
            scheme = "https" if any(
                s.get("service_name", "").upper() in ("HTTPS", "HTTP2") for s in services
            ) else "http"
            host = f"{scheme}://{ip}"
            if port not in (80, 443):
                host += f":{port}"
            results.append(
                PassiveResult(
                    source="censys",
                    url=host,
                    ip=ip,
                    port=port,
                    banner=hit.get("location", {}).get("country") or "",
                )
            )
        return results
    except Exception:
        return []


def passive_discover(
    query: str = 'php "Version"',
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 20,
) -> List[str]:
    """Orchestrates passive searches and returns deduplicated list of target URLs."""
    discovered: List[PassiveResult] = []
    if shodan_key:
        discovered.extend(search_shodan(query, shodan_key, limit // 2 + 1))
    if censys_id and censys_secret:
        discovered.extend(search_censys(query, censys_id, censys_secret, limit // 2 + 1))

    # deduplicate preserving order
    seen = {}
    unique = []
    for item in discovered:
        if item.url not in seen:
            seen[item.url] = True
            unique.append(item.url)

    return unique[:limit]


class ShodanSearcher:
    """Convenience class for repeated Shodan queries."""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        return search_shodan(query, self.api_key, limit)


class CensysSearcher:
    """Convenience class for repeated Censys queries."""

    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        return search_censys(query, self.api_id, self.api_secret, limit)


__all__ = [
    "passive_discover",
    "search_shodan",
    "search_censys",
    "ShodanSearcher",
    "CensysSearcher",
]
