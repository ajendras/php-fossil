"""Tests for passive.py using mocked HTTP responses via pytest-httpx."""

import pytest
from phpfossil.passive import (
    passive_discover,
    search_shodan,
    search_censys,
    ShodanSearcher,
    CensysSearcher,
)
from phpfossil.models import PassiveResult


def test_search_shodan(httpx_mock):
    """Test Shodan search with mocked JSON response."""
    mock_data = {
        "matches": [
            {
                "ip_str": "192.0.2.1",
                "port": 8080,
                "data": "Server: Apache/2.4 PHP/7.4.33",
            }
        ]
    }
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json=mock_data,
        status_code=200,
    )

    results = search_shodan(query='php "7.4"', api_key="test-shodan-key", limit=5)
    assert len(results) == 1
    assert results[0].source == "shodan"
    assert results[0].ip == "192.0.2.1"
    assert "8080" in results[0].url
    assert len(httpx_mock.get_requests()) == 1


def test_search_censys(httpx_mock):
    """Test Censys search with mocked response."""
    mock_data = {
        "result": {
            "hits": [
                {
                    "ip": "198.51.100.1",
                    "services": [
                        {"port": 443, "service_name": "HTTPS"}
                    ],
                }
            ]
        }
    }
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json=mock_data,
        status_code=200,
    )

    results = search_censys(
        query="php version 7",
        api_id="test-id",
        api_secret="test-secret",
        limit=5,
    )
    assert len(results) == 1
    assert results[0].source == "censys"
    assert "https://198.51.100.1" in results[0].url


def test_passive_discover_combined(httpx_mock):
    """Test the high-level passive_discover combining both providers."""
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={"matches": [{"ip_str": "192.0.2.1", "port": 80}]},
    )
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={"result": {"hits": [{"ip": "203.0.113.1", "services": [{"port": 80}]}]}},
    )

    urls = passive_discover(
        query='php "Version"',
        shodan_key="key1",
        censys_id="id1",
        censys_secret="secret1",
        limit=10,
    )
    assert len(urls) == 2
    assert any("192.0.2.1" in u for u in urls)
    assert any("203.0.113.1" in u for u in urls)


def test_shodan_searcher_class(httpx_mock):
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={"matches": []},
    )
    searcher = ShodanSearcher("dummy-key")
    res = searcher.search("test-query", limit=3)
    assert isinstance(res, list)


def test_censys_searcher_class(httpx_mock):
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={"result": {"hits": []}},
    )
    searcher = CensysSearcher("id", "secret")
    res = searcher.search("test", limit=3)
    assert isinstance(res, list)


def test_search_shodan_no_key():
    results = search_shodan("php", api_key=None)
    assert results == []


def test_search_censys_no_creds():
    results = search_censys("php", api_id=None, api_secret=None)
    assert results == []
