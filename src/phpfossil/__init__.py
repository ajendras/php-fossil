"""PHP Fossil — discovers legacy PHP sites via search dorks, fingerprints old versions,
maps vulns, extracts schemas and builds prioritized security lists.

Public API:
    scan_targets, generate_dorks, generate_report, ScanResult, Vulnerability,
    get_vulns_for_version, parse_sql_dump, store_results, get_historical_results, Store
"""

__version__ = "0.1.0"

from .models import ExposedFile, ScanResult, SchemaResult, Vulnerability
from .scanner import scan_targets
from .search import generate_dorks
from .reporter import generate_report
from .vulndb import get_vulns_for_version
from .schema import parse_sql_dump
from .store import Store, get_historical_results, store_results

__all__ = [
    "__version__",
    "scan_targets",
    "generate_dorks",
    "generate_report",
    "ScanResult",
    "Vulnerability",
    "ExposedFile",
    "SchemaResult",
    "get_vulns_for_version",
    "parse_sql_dump",
    "store_results",
    "get_historical_results",
    "Store",
]
