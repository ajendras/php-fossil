"""Persistent SQLite store for PHP Fossil scan history.

Provides the Store class and convenience functions used by the CLI,
library API and tests. Every scan is automatically saved; historical
results can be queried by limit or URL filter.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from .models import ScanResult


class Store:
    """SQLite-backed store for ScanResult persistence."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".phpfossil" / "history.db"
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    php_version TEXT,
                    scan_time TEXT,
                    raw_data TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_scan_results(self, results: List[ScanResult]) -> None:
        """Persist scan results to SQLite.

        Added to satisfy test_store_integration after the method was
        referenced but not present on the Store class.
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            for result in results:
                raw = result.model_dump_json()
                conn.execute(
                    """
                    INSERT INTO scan_history (url, php_version, scan_time, raw_data)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        result.url,
                        result.php_version,
                        result.scan_time.isoformat(),
                        raw,
                    ),
                )
            conn.commit()

    def get_historical_results(
        self, limit: int = 50, url_filter: Optional[str] = None
    ) -> List[ScanResult]:
        """Load historical ScanResult objects from the database."""
        results: List[ScanResult] = []
        query = "SELECT raw_data FROM scan_history"
        params: List[Any] = []
        if url_filter:
            query += " WHERE url LIKE ?"
            params.append(f"%{url_filter}%")
        query += " ORDER BY scan_time DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            for (raw_data,) in conn.execute(query, params):
                try:
                    data = json.loads(raw_data)
                    if isinstance(data.get("scan_time"), str):
                        ts = data["scan_time"]
                        if ts.endswith("Z"):
                            ts = ts.replace("Z", "+00:00")
                        data["scan_time"] = datetime.fromisoformat(ts)
                    result = ScanResult.model_validate(data)
                    results.append(result)
                except Exception:  # noqa: BLE001
                    continue
        return results


def store_results(results: List[ScanResult], db_path: Optional[Path] = None) -> None:
    """Public convenience function used by CLI and scan_targets."""
    store = Store(db_path)
    store.save_scan_results(results)


def get_historical_results(
    limit: int = 30,
    db_path: Optional[Path] = None,
    url_filter: Optional[str] = None,
) -> List[ScanResult]:
    """Public retrieval function used by CLI history command."""
    store = Store(db_path)
    return store.get_historical_results(limit=limit, url_filter=url_filter)


__all__ = ["Store", "store_results", "get_historical_results"]
