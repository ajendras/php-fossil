"""Passive discovery using Shodan and Censys APIs."""

from typing import List, Optional

import httpx

from .models import PassiveResult


class ShodanSearcher:
    """Shodan API client for passive PHP host discovery."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        """Search Shodan and return PassiveResult objects."""
        if not self.api_key:
            return []
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.api_key, "query": query, "limit": limit},
                )
                resp.raise_for_status()
                data = resp.json()
                results: List[PassiveResult] = []
                for match in data.get("matches", [])[:limit]:
                    hostname = (
                        match.get("hostnames", [match.get("ip_str", "")])[0]
                        if match.get("hostnames")
                        else match.get("ip_str", "")
                    )
                    if hostname:
                        url = f"http://{hostname}"
                        results.append(
                            PassiveResult(
                                url=url, source="shodan", port=match.get("port", 80), raw=match
                            )
                        )
                return results
        except Exception:  # graceful degradation
            return []


class CensysSearcher:
    """Censys API client for passive PHP host discovery."""

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id
        self.api_secret = api_secret

    def search(self, query: str, limit: int = 10) -> List[PassiveResult]:
        """Search Censys and return PassiveResult objects."""
        if not self.api_id or not self.api_secret:
            return []
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://search.censys.io/api/v2/hosts/search",
                    params={"q": query, "per_page": min(limit, 100)},
                    auth=(self.api_id, self.api_secret),
                )
                resp.raise_for_status()
                data = resp.json()
                results: List[PassiveResult] = []
                for hit in data.get("result", {}).get("hits", [])[:limit]:
                    ip = hit.get("ip")
                    if ip:
                        url = f"http://{ip}"
                        results.append(
                            PassiveResult(url=url, source="censys", raw=hit)
                        )
                return results
        except Exception:  # graceful degradation
            return []


def search_shodan(
    query: str, shodan_key: Optional[str] = None, limit: int = 10
) -> List[str]:
    """Convenience wrapper returning list of URLs from Shodan."""
    searcher = ShodanSearcher(shodan_key)
    results = searcher.search(query, limit)
    return [r.url for r in results]


def search_censys(
    query: str,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Convenience wrapper returning list of URLs from Censys."""
    searcher = CensysSearcher(censys_id, censys_secret)
    results = searcher.search(query, limit)
    return [r.url for r in results]


def passive_discover(
    query: str = 'php "Version"',
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 20,
) -> List[str]:
    """Unified passive discovery from Shodan and/or Censys (deduplicated)."""
    urls: List[str] = []
    if shodan_key:
        urls.extend(search_shodan(query, shodan_key, limit))
    if censys_id and censys_secret:
        urls.extend(search_censys(query, censys_id, censys_secret, limit))
    # simple deduplication preserving order
    seen = dict.fromkeys(urls)
    return list(seen)[:limit]


__all__ = [
    "passive_discover",
    "search_shodan",
    "search_censys",
    "ShodanSearcher",
    "CensysSearcher",
    "PassiveResult",
]
