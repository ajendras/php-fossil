"""Passive reconnaissance using Shodan and Censys for discovering PHP hosts."""

from typing import List, Optional, Dict, Any

import httpx

from .models import PassiveResult


def search_shodan(
    query: str, api_key: Optional[str] = None, limit: int = 10
) -> List[str]:
    """Search Shodan for hosts matching query. Returns list of URLs."""
    if not api_key:
        return []

    try:
        url = "https://api.shodan.io/shodan/host/search"
        params = {"query": query, "key": api_key, "limit": str(limit)}
        with httpx.Client(timeout=10) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data: Dict[str, Any] = response.json()
            results: List[str] = []
            for match in data.get("matches", [])[:limit]:
                if match.get("hostnames"):
                    hostname = match["hostnames"][0]
                    results.append(f"https://{hostname}")
                elif match.get("ip_str"):
                    results.append(f"http://{match['ip_str']}")
            return results
    except Exception:
        return []


def search_censys(
    query: str,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Search Censys for hosts. Returns list of URLs."""
    if not api_id or not api_secret:
        return []

    try:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"query": query, "per_page": limit}
        with httpx.Client(timeout=10) as client:
            response = client.get(url, params=params, auth=(api_id, api_secret))
            response.raise_for_status()
            data = response.json()
            results: List[str] = []
            for hit in data.get("result", {}).get("hits", [])[:limit]:
                ip = hit.get("ip")
                if ip:
                    results.append(f"http://{ip}")
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
    """Discover targets using Shodan and/or Censys."""
    results: List[str] = []
    shodan_limit = limit // 2 + limit % 2
    censys_limit = limit // 2

    if shodan_key:
        results.extend(search_shodan(query, shodan_key, shodan_limit))
    if censys_id and censys_secret:
        results.extend(search_censys(query, censys_id, censys_secret, censys_limit))

    # Remove duplicates while preserving order
    seen = set()
    unique_results = []
    for r in results:
        if r not in seen:
            seen.add(r)
            unique_results.append(r)
    return unique_results[:limit]


class ShodanSearcher:
    """Class-based Shodan searcher for consistency with other components."""

    def search(
        self, query: str, api_key: Optional[str] = None, limit: int = 10
    ) -> List[str]:
        return search_shodan(query, api_key, limit)


class CensysSearcher:
    """Class-based Censys searcher."""

    def search(
        self,
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
