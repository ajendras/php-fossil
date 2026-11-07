"""Persistent SQLite store for historical scan results.

Provides automatic persistence of ScanResult objects into a local SQLite
database. Includes a Store class for direct use and convenience functions
for the public API and CLI.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, List, Optional, Union

from .models import ScanResult


class Store:
    """SQLite persistent store for scan history.

    Creates ~/.phpfossil/history.db by default with a scan_history table
    that stores full serialized ScanResult JSON.
    """

    def __init__(self, db_path: Optional[Union[Path, str]] = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".phpfossil" / "history.db"
        elif isinstance(db_path, str):
            db_path = Path(db_path)
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create the scans table (and indexes) if it does not exist."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    url TEXT NOT NULL,
                    php_version TEXT,
                    result_json TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_url ON scan_history (url)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_version ON scan_history (php_version)"
            )

    def store(self, result: ScanResult) -> int:
        """Persist one ScanResult, returns the inserted row ID."""
        with sqlite3.connect(str(self.db_path)) as conn:
            json_data = result.model_dump_json()
            cur = conn.execute(
                """
                INSERT INTO scan_history (url, php_version, result_json)
                VALUES (?, ?, ?)
                """,
                (result.url, result.php_version, json_data),
            )
            conn.commit()
            return cur.lastrowid or 0

    def store_many(self, results: List[ScanResult]) -> List[int]:
        """Store multiple ScanResult objects."""
        return [self.store(r) for r in results]

    def get_history(
        self,
        limit: int = 50,
        url_filter: Optional[str] = None,
    ) -> List[ScanResult]:
        """Return most recent scans, optionally filtered by URL substring."""
        query = "SELECT result_json FROM scan_history"
        params: List[Any] = []
        if url_filter:
            query += " WHERE url LIKE ?"
            params.append(f"%{url_filter}%")
        query += " ORDER BY scan_time DESC, id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            results: List[ScanResult] = []
            for row in rows:
                data = json.loads(row["result_json"])
                results.append(ScanResult.model_validate(data))
            return results

    def count(self) -> int:
        """Total number of stored scans."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM scan_history")
            row = cursor.fetchone()
            return row[0] if row else 0


def store_results(
    results: List[ScanResult], db_path: Optional[Union[Path, str]] = None
) -> List[int]:
    """Store scan results to the persistent SQLite database."""
    if not results:
        return []
    store = Store(db_path)
    return store.store_many(results)


def get_historical_results(
    limit: int = 50,
    db_path: Optional[Union[Path, str]] = None,
    url_filter: Optional[str] = None,
) -> List[ScanResult]:
    """Retrieve historical results from the SQLite store."""
    store = Store(db_path)
    return store.get_history(limit=limit, url_filter=url_filter)


__all__ = [
    "Store",
    "store_results",
    "get_historical_results",
]
