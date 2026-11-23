"""Tests for the CMS fingerprinting functions."""

from phpfossil.fingerprinter import (
    detect_cms_version,
    detect_codeigniter_version,
    detect_drupal_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_magento_version,
    detect_prestashop_version,
    detect_symfony_version,
    detect_wordpress_version,
)


def test_detect_wordpress_version():
    assert detect_wordpress_version(
        '<meta name="generator" content="WordPress 6.4.1">'
    ) == "6.4.1"
    assert detect_wordpress_version("WordPress 5.8.1") == "5.8.1"
    assert detect_wordpress_version("<p>No WP</p>") is None


def test_detect_joomla_version():
    assert detect_joomla_version(
        '<meta name="generator" content="Joomla! - Open Source Content Management - Version 4.4.0">'
    ) == "4.4.0"
    assert detect_joomla_version("Joomla! 3.10.11") == "3.10.11"
    assert detect_joomla_version("other") is None


def test_detect_drupal_version():
    assert detect_drupal_version(
        '<meta name="generator" content="Drupal 10.2.3">'
    ) == "10.2.3"
    assert detect_drupal_version("Drupal 9.5.0") == "9.5.0"
    assert detect_drupal_version("") is None


def test_detect_magento_version():
    assert detect_magento_version(
        '<meta name="generator" content="Magento 2.4.6">'
    ) == "2.4.6"
    assert detect_magento_version("Magento 2.4.6-p1") == "2.4.6"
    assert detect_magento_version("Magento/2.3.7") == "2.3.7"
    assert detect_magento_version("no magento") is None


def test_detect_prestashop_version():
    assert detect_prestashop_version(
        '<meta name="generator" content="PrestaShop 8.1.0">'
    ) == "8.1.0"
    assert detect_prestashop_version("Powered by PrestaShop 1.7.8.0") == "1.7.8.0"
    assert detect_prestashop_version("no prestashop") is None


def test_detect_laravel_version():
    assert detect_laravel_version("<!-- Laravel Framework 10.0.0 -->") == "10.0.0"
    assert detect_laravel_version("Laravel 9.3.0") == "9.3.0"
    assert detect_laravel_version("no laravel") is None


def test_detect_symfony_version():
    assert detect_symfony_version(
        '<meta name="generator" content="Symfony 6.4.3">'
    ) == "6.4.3"
    assert detect_symfony_version("Symfony 5.4.0") == "5.4.0"
    assert detect_symfony_version("symfony/v7.0.1") == "7.0.1"
    assert detect_symfony_version("No framework") is None


def test_detect_codeigniter_version():
    assert detect_codeigniter_version("CodeIgniter 4.5.2") == "4.5.2"
    assert detect_codeigniter_version(
        '<meta name="generator" content="CodeIgniter 3.1.13">'
    ) == "3.1.13"
    assert detect_codeigniter_version("This is CodeIgniter v4.3.0") == "4.3.0"
    assert detect_codeigniter_version("No CI") is None


def test_detect_cms_version_precedence():
    # Test order of precedence
    body = 'WordPress 6.0 and also Symfony 6.4'
    assert detect_cms_version(body) == ("wordpress", "6.0")

    body = '<meta name="generator" content="Drupal 10.1.0">'
    assert detect_cms_version(body) == ("drupal", "10.1.0")

    body = "Symfony 6.3.2"
    assert detect_cms_version(body) == ("symfony", "6.3.2")

    body = "CodeIgniter 4.4.0"
    assert detect_cms_version(body) == ("codeigniter", "4.4.0")

    assert detect_cms_version("nothing") is None
