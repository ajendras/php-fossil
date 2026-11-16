"""Shodan and Censys API modules for passive discovery.

Provides functions and wrapper classes to query Shodan and Censys for
hosts that may be running legacy PHP. Results are normalized into
PassiveResult Pydantic models that can be fed directly into scan_targets().

Uses only httpx (already a dependency). API credentials are accepted as
parameters or read from standard environment variables:
    SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET.

Consistent style with nuclei.py and ollama.py. Graceful error handling
and deduplication of discovered URLs.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

import httpx

from .models import PassiveResult


def search_shodan(
    query: str = 'php "Version"',
    api_key: Optional[str] = None,
    limit: int = 20,
) -> List[PassiveResult]:
    """Search Shodan for hosts matching a query.

    If api_key is not supplied the SHODAN_API_KEY environment variable
    is used. Returns PassiveResult objects with constructed URLs.
    """
    if not api_key:
        api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return [
            PassiveResult(
                source="shodan",
                url="",
                banner="No Shodan API key provided",
            )
        ]

    results: List[PassiveResult] = []
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}",
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            matches = data.get("matches", [])[:limit]

            for match in matches:
                ip = match.get("ip_str")
                port = match.get("port", 80)
                hostnames = match.get("hostnames") or []
                hostname = hostnames[0] if hostnames else ip
                # prefer https when ssl data or port 443 is present
                protocol = "https" if match.get("ssl") or port == 443 else "http"
                if port not in (80, 443):
                    url = f"{protocol}://{hostname}:{port}"
                else:
                    url = f"{protocol}://{hostname}"

                banner = match.get("data", "")[:200]
                results.append(
                    PassiveResult(
                        source="shodan",
                        url=url,
                        ip=ip,
                        port=port,
                        banner=banner or None,
                    )
                )
        return results
    except Exception as exc:  # noqa: BLE001
        return [
            PassiveResult(
                source="shodan",
                url="",
                banner=f"Error querying Shodan: {exc}",
            )
        ]


def search_censys(
    query: str = 'services.http.response.headers.server: "php"',
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    limit: int = 20,
) -> List[PassiveResult]:
    """Search Censys v2 for hosts matching a query.

    Uses HTTP basic auth with the supplied id/secret (or environment
    variables CENSYS_API_ID / CENSYS_API_SECRET). Returns PassiveResult
    objects.
    """
    if not api_id:
        api_id = os.getenv("CENSYS_API_ID")
    if not api_secret:
        api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return [
            PassiveResult(
                source="censys",
                url="",
                banner="No Censys credentials provided",
            )
        ]

    results: List[PassiveResult] = []
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": query, "per_page": min(limit, 100)},
                auth=(api_id, api_secret),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])[:limit]

            for hit in hits:
                ip = hit.get("ip")
                services = hit.get("services", [])
                for svc in services:
                    port = svc.get("port")
                    if not port:
                        continue
                    svc_name = (svc.get("service_name") or "").lower()
                    protocol = "https" if "https" in svc_name or port == 443 else "http"
                    if port not in (80, 443):
                        url = f"{protocol}://{ip}:{port}"
                    else:
                        url = f"{protocol}://{ip}"
                    # extract a short banner
                    banner_parts = []
                    if "http" in svc:
                        banner_parts.append(str(svc.get("http", {}).get("response", {})).strip()[:80])
                    banner = " | ".join(banner_parts) or json.dumps(svc)[:120]

                    results.append(
                        PassiveResult(
                            source="censys",
                            url=url,
                            ip=ip,
                            port=port,
                            banner=banner,
                        )
                    )
                    break  # one URL per host is enough
        return results
    except Exception as exc:  # noqa: BLE001
        return [
            PassiveResult(
                source="censys",
                url="",
                banner=f"Error querying Censys: {exc}",
            )
        ]


def passive_discover(
    query: str = 'php "Version"',
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    limit: int = 30,
) -> List[str]:
    """High-level passive discovery combining Shodan and Censys.

    Returns a deduplicated list of URLs (strings) that can be passed
    directly to scan_targets(). Credentials may be passed or read from
    environment variables.
    """
    urls: List[str] = []
    seen = set()

    if shodan_key or os.getenv("SHODAN_API_KEY"):
        for res in search_shodan(query, shodan_key, limit // 2 + 5):
            if res.url and res.url not in seen and "Error" not in (res.banner or ""):
                seen.add(res.url)
                urls.append(res.url)

    if (censys_id and censys_secret) or (
        os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET")
    ):
        for res in search_censys(query, censys_id, censys_secret, limit // 2 + 5):
            if res.url and res.url not in seen and "Error" not in (res.banner or ""):
                seen.add(res.url)
                urls.append(res.url)

    return urls[:limit]


class ShodanSearcher:
    """Object-oriented wrapper mirroring NucleiValidator / OllamaSummarizer."""

    @staticmethod
    def search(
        query: str = 'php "Version"', api_key: Optional[str] = None, limit: int = 20
    ) -> List[PassiveResult]:
        """Perform a Shodan search and return normalized results."""
        return search_shodan(query, api_key, limit)


class CensysSearcher:
    """Object-oriented wrapper for Censys searches."""

    @staticmethod
    def search(
        query: str = 'services.http.response.headers.server: "php"',
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        limit: int = 20,
    ) -> List[PassiveResult]:
        """Perform a Censys search and return normalized results."""
        return search_censys(query, api_id, api_secret, limit)


__all__ = [
    "search_shodan",
    "search_censys",
    "passive_discover",
    "ShodanSearcher",
    "CensysSearcher",
]
