"""Tests for passive discovery module."""

import pytest
from phpfossil import (
    search_shodan,
    search_censys,
    passive_discover,
    ShodanSearcher,
    CensysSearcher,
    PassiveResult,
)


def test_search_shodan(httpx_mock):
    httpx_mock.add_response(
        json={
            "matches": [
                {
                    "ip_str": "192.0.2.1",
                    "port": 80,
                    "hostnames": ["shodan-test.example.com"],
                }
            ]
        }
    )
    results = search_shodan('php "Version 7"', "fake-shodan-key", limit=5)
    assert len(results) == 1
    assert "shodan-test.example.com" in results[0]


def test_search_censys(httpx_mock):
    httpx_mock.add_response(
        json={
            "result": {
                "hits": [
                    {"ip": "192.0.2.2", "location": {}}
                ]
            }
        }
    )
    results = search_censys(
        'php "Version"', "fake-id", "fake-secret", limit=5
    )
    assert len(results) == 1


def test_passive_discover_combined(httpx_mock):
    httpx_mock.add_response(
        json={"matches": [{"ip_str": "192.0.2.1", "hostnames": ["test1.com"]}]}
    )
    httpx_mock.add_response(
        json={"result": {"hits": [{"ip": "192.0.2.2"}]}}
    )
    results = passive_discover(
        query='php "Version"',
        shodan_key="key1",
        censys_id="id",
        censys_secret="secret",
        limit=5,
    )
    assert len(results) == 2


def test_shodan_and_censys_wrappers(httpx_mock):
    httpx_mock.add_response(
        json={"matches": [{"ip_str": "1.2.3.4", "hostnames": ["test.com"]}]}
    )
    searcher = ShodanSearcher("fakekey")
    results = searcher.search("test query", 1)
    assert len(results) == 1
    assert isinstance(results[0], PassiveResult)
    assert results[0].source == "shodan"
    assert results[0].url.startswith("http")
    # censys wrapper
    httpx_mock.add_response(
        json={"result": {"hits": [{"ip": "5.6.7.8"}]}}
    )
    csearcher = CensysSearcher("id", "secret")
    cresults = csearcher.search("test", 1)
    assert len(cresults) == 1
    assert cresults[0].source == "censys"
