import pytest

from phpfossil.fingerprinter import (
    detect_wordpress_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_cms_version,
)


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            '<meta name="generator" content="WordPress 5.8.1">',
            "5.8.1",
        ),
        (
            "<html><body>Welcome to WordPress 4.9.8</body></html>",
            "4.9.8",
        ),
        (
            "<!-- WordPress 3.5.2 -->",
            "3.5.2",
        ),
    ],
)
def test_detect_wordpress_version(html, expected):
    assert detect_wordpress_version(html) == expected


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            '<meta name="generator" content="Joomla! - Open Source Content Management - Version 3.9.24">',
            "3.9.24",
        ),
        (
            "<html><body>Powered by Joomla! 2.5.18</body></html>",
            "2.5.18",
        ),
        (
            "<!-- Joomla! 4.0.0 -->",
            "4.0.0",
        ),
    ],
)
def test_detect_joomla_version(html, expected):
    assert detect_joomla_version(html) == expected


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            "<!-- Laravel Framework 8.5.0 -->",
            "8.5.0",
        ),
        (
            "<html><body>Laravel 7.30.4 is running</body></html>",
            "7.30.4",
        ),
        (
            "<!-- Laravel 6.18.35 -->",
            "6.18.35",
        ),
    ],
)
def test_detect_laravel_version(html, expected):
    assert detect_laravel_version(html) == expected


def test_detect_cms_version_priority():
    # WordPress should be detected first
    body = (
        "<meta name='generator' content='WordPress 5.6.0'>"
        "<!-- Joomla! 3.9.0 -->"
        "<!-- Laravel Framework 8.0.0 -->"
    )
    assert detect_cms_version(body) == ("wordpress", "5.6.0")

    # If no WordPress, Joomla is next
    body2 = "<!-- Joomla! 3.9.0 --> <!-- Laravel Framework 8.0.0 -->"
    assert detect_cms_version(body2) == ("joomla", "3.9.0")

    # Finally Laravel
    body3 = "<!-- Laravel Framework 8.0.0 -->"
    assert detect_cms_version(body3) == ("laravel", "8.0.0")

    # No CMS found
    assert detect_cms_version("<html>No CMS here</html>") is None
