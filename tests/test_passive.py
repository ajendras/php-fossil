"""Tests for passive discovery (Shodan/Censys). Uses pytest-httpx mocks."""

import pytest

from phpfossil.passive import (
    search_shodan,
    search_censys,
    passive_discover,
    ShodanSearcher,
    CensysSearcher,
)


def test_shodan_searcher(httpx_mock):
    """Mock Shodan API response; expect at least one URL."""
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={
            "matches": [
                {
                    "ip_str": "192.0.2.1",
                    "port": 80,
                    "hostnames": ["example.com"],
                }
            ]
        },
    )
    results = search_shodan('php "Version 7.4"', "fake-shodan-key", 1)
    assert len(results) == 1
    assert "example.com" in results[0]


def test_censys_searcher(httpx_mock):
    """Mock Censys API response."""
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={
            "result": {
                "hits": [
                    {
                        "ip": "192.0.2.2",
                        "services": [{"port": 80, "service_name": "HTTP"}],
                    }
                ]
            }
        },
    )
    results = search_censys('php "Version"', "fake-id", "fake-secret", 1)
    assert len(results) >= 1


def test_passive_discover(httpx_mock):
    """End-to-end passive discovery returns list of str URLs (no .url attribute error)."""
    httpx_mock.add_response(
        url=re.compile(r"https://api\.shodan\.io.*"),
        json={"matches": [{"ip_str": "192.0.2.1", "port": 80, "hostnames": ["test.com"]}]},
    )
    httpx_mock.add_response(
        url=re.compile(r"https://search\.censys\.io.*"),
        json={"result": {"hits": []}},
    )
    targets = passive_discover(
        query='php "Version 7.4"',
        shodan_key="fake-key",
        limit=5,
    )
    assert len(targets) >= 1
    assert any("test.com" in t for t in targets)


def test_searcher_classes():
    """Test the wrapper classes that return PassiveResult objects."""
    shodan = ShodanSearcher("fake-key")
    censys = CensysSearcher("fake-id", "fake-secret")
    with patch("phpfossil.passive.search_shodan", return_value=["https://example.com"]):
        results = shodan.search("php", 1)
        assert len(results) == 1
        assert results[0].url == "https://example.com"
        assert results[0].source == "shodan"
