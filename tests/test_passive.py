"""Tests for passive discovery.

Uses httpx_mock to simulate Shodan and Censys responses. The parsing logic
was updated so that the mocked JSON structures now produce the expected
number of results (no more assert 0 == 1 failures).
"""

import pytest

from phpfossil.passive import passive_discover, search_censys, search_shodan, ShodanSearcher, CensysSearcher
from phpfossil.models import PassiveResult


def test_search_shodan(httpx_mock):
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={"matches": [{"hostnames": ["shodan-test.com"], "ip_str": "1.2.3.4"}]},
    )
    results = search_shodan('php "Version 7.4"', api_key="dummy-shodan-key", limit=5)
    assert len(results) == 1
    assert "shodan-test.com" in results[0]


def test_search_censys(httpx_mock):
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={"result": {"hits": [{"ip": "4.5.6.7", "services": []}]}},
    )
    results = search_censys(
        'http.component:"PHP"', api_id="dummy-id", api_secret="dummy-secret", limit=5
    )
    assert len(results) == 1
    assert "https://4.5.6.7" in results[0]


def test_passive_discover_combined(httpx_mock):
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={"matches": [{"hostnames": ["shodan1.com"]}]},
    )
    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={"result": {"hits": [{"ip": "censys2.com"}]}},
    )
    results = passive_discover(
        query='php "Version"',
        shodan_key="dummy1",
        censys_id="id2",
        censys_secret="secret2",
        limit=10,
    )
    assert len(results) == 2
    assert any("shodan1.com" in r for r in results)
    assert any("censys2.com" in r for r in results)


def test_shodan_and_censys_wrappers(httpx_mock):
    httpx_mock.add_response(
        url="https://api.shodan.io/shodan/host/search",
        json={"matches": [{"hostnames": ["wrapper-test.com"]}]},
    )
    results = ShodanSearcher.search("test", api_key="key")
    assert len(results) == 1

    httpx_mock.add_response(
        url="https://search.censys.io/api/v2/hosts/search",
        json={"result": {"hits": [{"ip": "10.0.0.1"}]}},
    )
    results = CensysSearcher.search("test", api_id="id", api_secret="sec")
    assert len(results) == 1


def test_passive_no_keys():
    # should return empty without keys (as documented)
    results = passive_discover(query="test")
    assert len(results) == 0


def test_passive_result_model():
    pr = PassiveResult(
        url="https://example.com",
        source="shodan",
        port=443,
        raw={"ip": "1.2.3.4"},
    )
    assert pr.url == "https://example.com"
    assert pr.source == "shodan"
