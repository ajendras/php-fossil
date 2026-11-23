"""Tests for CMS version fingerprinting in fingerprinter.py."""

import pytest

from phpfossil.fingerprinter import (
    detect_cms_version,
    detect_drupal_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_magento_version,
    detect_prestashop_version,
    detect_wordpress_version,
)


@pytest.mark.parametrize(
    "content,expected",
    [
        ('<meta name="generator" content="WordPress 6.4.2">', ("wordpress", "6.4.2")),
        ('<meta name="generator" content="Joomla! 4.4.0">', ("joomla", "4.4.0")),
        ('<meta name="generator" content="Drupal 10.2.3">', ("drupal", "10.2.3")),
        ('<meta name="generator" content="Magento 2.4.6">', ("magento", "2.4.6")),
        ('<meta name="generator" content="PrestaShop 8.1.0">', ("prestashop", "8.1.0")),
        ('<!-- Laravel Framework 10.4.1 -->', ("laravel", "10.4.1")),
    ],
)
def test_detect_cms_version(content: str, expected: tuple[str, str]) -> None:
    """Test unified CMS detector returns correct name/version tuples."""
    assert detect_cms_version(content) == expected


def test_detect_wordpress_version() -> None:
    """Test WordPress version extraction from meta tags and inline text."""
    assert (
        detect_wordpress_version(
            '<meta name="generator" content="WordPress 6.4.2">'
        )
        == "6.4.2"
    )
    assert detect_wordpress_version("Powered by WordPress 5.8.1") == "5.8.1"


def test_detect_joomla_version() -> None:
    """Test Joomla version extraction from generator meta tag."""
    assert (
        detect_joomla_version(
            '<meta name="generator" content="Joomla! - Open Source Content Management - Version 4.4.0">'
        )
        == "4.4.0"
    )


def test_detect_drupal_version() -> None:
    """Test Drupal version extraction from generator meta tag."""
    assert (
        detect_drupal_version('<meta name="generator" content="Drupal 10.2.3">')
        == "10.2.3"
    )


def test_detect_magento_version() -> None:
    """Test Magento version extraction from meta and comment patterns."""
    assert (
        detect_magento_version('<meta name="generator" content="Magento 2.4.6">')
        == "2.4.6"
    )
    assert detect_magento_version("Magento/2.4.6") == "2.4.6"


def test_detect_prestashop_version() -> None:
    """Test PrestaShop version extraction from powered-by and JS patterns."""
    assert detect_prestashop_version("Powered by PrestaShop 8.1.0") == "8.1.0"
    assert (
        detect_prestashop_version('prestashop.version = "8.0.2";') == "8.0.2"
    )


def test_detect_laravel_version() -> None:
    """Test Laravel version extraction from comments and inline text."""
    assert (
        detect_laravel_version("<!-- Laravel Framework 10.4.1 -->")
        == "10.4.1"
    )
    assert detect_laravel_version("Laravel 9.3.0") == "9.3.0"
