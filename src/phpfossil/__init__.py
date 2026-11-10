"""PHP Fossil — discovers legacy PHP sites via search dorks, fingerprints old versions,
maps vulns, extracts schemas and builds prioritized security lists.

Public API:
    scan_targets, generate_dorks, generate_report, validate_with_nuclei,
    generate_summary, ScanResult, Vulnerability, NucleiFinding, get_vulns_for_version,
    parse_sql_dump, store_results, get_historical_results, Store, run_tui
"""

__version__ = "0.1.0"

from .models import (
    ExposedFile,
    NucleiFinding,
    ScanResult,
    SchemaResult,
    Vulnerability,
)
from .scanner import scan_targets
from .search import generate_dorks
from .reporter import generate_report
from .vulndb import get_vulns_for_version
from .schema import parse_sql_dump
from .store import Store, get_historical_results, store_results
from .fingerprinter import (
    detect_from_headers,
    detect_from_body,
    detect_from_phpinfo,
    detect_from_error_page,
    detect_php_version,
    detect_wordpress_version,
    detect_joomla_version,
    detect_laravel_version,
    detect_cms_version,
)
from .nuclei import validate_with_nuclei, NucleiValidator
from .ollama import generate_summary, is_ollama_available, OllamaSummarizer
from .tui import run_tui

__all__ = [
    "__version__",
    "scan_targets",
    "generate_dorks",
    "generate_report",
    "validate_with_nuclei",
    "generate_summary",
    "ScanResult",
    "Vulnerability",
    "NucleiFinding",
    "ExposedFile",
    "SchemaResult",
    "get_vulns_for_version",
    "parse_sql_dump",
    "store_results",
    "get_historical_results",
    "Store",
    # Fingerprinter helpers
    "detect_from_headers",
    "detect_from_body",
    "detect_from_phpinfo",
    "detect_from_error_page",
    "detect_php_version",
    "detect_wordpress_version",
    "detect_joomla_version",
    "detect_laravel_version",
    "detect_cms_version",
    # Nuclei helpers
    "NucleiValidator",
    # Ollama helpers
    "generate_summary",
    "is_ollama_available",
    "OllamaSummarizer",
    # TUI
    "run_tui",
]
