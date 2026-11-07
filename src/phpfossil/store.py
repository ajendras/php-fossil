"""Persistent SQLite store for historical scan results.

Provides automatic persistence of ScanResult objects into a local SQLite
database. Includes a Store class for direct use and convenience functions
for the public API and CLI.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional, Union

from .models import ScanResult


class Store:
    """SQLite persistent store for scan history.

    Creates ``~/.phpfossil/history.db`` by default with a ``scan_history``
    table that stores the full serialized ``ScanResult`` JSON. The table
    also contains a ``scan_time`` column populated by SQLite's
    ``CURRENT_TIMESTAMP`` for quick chronological queries.
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    url TEXT NOT NULL,
                    php_version TEXT,
                    result_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_url ON scan_history (url)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_version ON scan_history (php_version)"
            )

    def store(self, result: ScanResult) -> int:
        """Persist a single :class:`~phpfossil.models.ScanResult`.

        Returns the inserted row ID (or ``0`` on failure). The full model
        is serialized to JSON and stored in the ``result_json`` column.
        """
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

    def store_many(self, results: Iterable[ScanResult]) -> List[int]:
        """Persist multiple ``ScanResult`` objects.

        Returns a list of inserted row IDs preserving order.
        """
        ids: List[int] = []
        for r in results:
            ids.append(self.store(r))
        return ids

    def get_history(
        self,
        limit: int = 50,
        url_filter: Optional[str] = None,
    ) -> List[ScanResult]:
        """Return the most recent scans, optionally filtered by URL substring.

        Args:
            limit: Maximum number of results to return (default 50).
            url_filter: Optional ``LIKE`` filter applied to the ``url`` column.

        Returns:
            A list of :class:`~phpfossil.models.ScanResult` objects ordered
            by insertion time (newest first).
        """
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
        """Return the total number of stored scans."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM scan_history")
            row = cursor.fetchone()
            return row[0] if row else 0


def store_results(
    results: Union[ScanResult, List[ScanResult]],
    db_path: Optional[Union[Path, str]] = None,
) -> List[int]:
    """Store scan results to the persistent SQLite database.

    The function is flexible: it accepts either a single ``ScanResult``
    instance or a list of them. In both cases a list of inserted row IDs
    is returned.

    Args:
        results: One ``ScanResult`` or a list of results to persist.
        db_path: Optional custom path to the SQLite database.

    Returns:
        List of row IDs corresponding to the stored results.
    """
    if isinstance(results, ScanResult):
        results = [results]

    if not results:
        return []

    store = Store(db_path)
    return store.store_many(results)  # type: ignore[arg-type]


def get_historical_results(
    limit: int = 50,
    db_path: Optional[Union[Path, str]] = None,
    url_filter: Optional[str] = None,
) -> List[ScanResult]:
    """Retrieve historical results from the SQLite store.

    Args:
        limit: Maximum number of results to return.
        db_path: Optional custom SQLite database path.
        url_filter: Optional substring filter applied to the ``url`` column.

    Returns:
        List of ``ScanResult`` objects ordered by most recent scan.
    """
    store = Store(db_path)
    return store.get_history(limit=limit, url_filter=url_filter)


__all__ = [
    "Store",
    "store_results",
    "get_historical_results",
]
