"""SQL schema extraction for PHP Fossil.

Contains functions to locate common SQL dump URLs and parse their contents into
SchemaResult objects with tables, columns and row count estimates.
Used to assess risk from exposed database dumps.
"""

import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import httpx

from .models import ExposedFile, SchemaResult


def locate_sql_urls(base_url: str) -> List[str]:
    """Generate list of common SQL backup file URLs to probe.

    Returns full URLs for likely dump locations.
    """
    common_names = [
        "backup.sql",
        "dump.sql",
        "database.sql",
        "db.sql",
        "data.sql",
        "backup.sql.gz",
        "dump.sql.gz",
        "phpmyadmin.sql",
        "mysql.sql",
        "schema.sql",
    ]

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = ["/", "/admin/", "/wp-admin/", "/old/", "/test/"]
    urls: List[str] = []
    for path in paths:
        for name in common_names:
            urls.append(urljoin(base + path, name))

    # also direct on the base
    for name in common_names:
        urls.append(urljoin(base_url.rstrip("/") + "/", name))

    # deduplicate while preserving order
    seen = dict.fromkeys(urls)
    return list(seen)


def parse_sql_dump(sql_content: str) -> SchemaResult:
    """Parse SQL dump content to extract schema information.

    Handles common mysqldump, phpmyadmin formats, comments, backticks.
    Estimates row counts from number of INSERT statements.
    """
    if not sql_content or not isinstance(sql_content, str):
        return SchemaResult()

    # Strip comments
    sql = re.sub(r"--.*", "", sql_content, flags=re.MULTILINE)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)

    tables: List[str] = []
    columns: Dict[str, List[str]] = {}
    row_counts: Dict[str, int] = {}

    # Extract table names from CREATE TABLE
    create_pattern = r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`'\"]?(\w+)[`'\"]?"
    for match in re.finditer(create_pattern, sql, re.IGNORECASE):
        tname = match.group(1).lower()
        if tname not in tables:
            tables.append(tname)
            columns[tname] = []

    # Extract columns (basic)
    for table in tables:
        table_def_match = re.search(
            rf"CREATE TABLE[^`]*?[`'\"]?{re.escape(table)}[`'\"]?[^;]*?\((.*?)\)[^;]*?;",
            sql,
            re.IGNORECASE | re.DOTALL,
        )
        if table_def_match:
            body = table_def_match.group(1)
            col_matches = re.findall(
                r"[`'\"]?(\w+)[`'\"]?\s+(?:`?\w+|`?\w+\s*\(\d+\))",
                body,
                re.IGNORECASE,
            )
            columns[table] = [c.lower() for c in col_matches if c.lower() not in ("key", "primary", "index")]

    # Estimate row counts from INSERTs
    for table in tables:
        insert_count = len(
            re.findall(
                rf"INSERT\s+INTO\s+[`'\"]?{re.escape(table)}[`'\"]?",
                sql,
                re.IGNORECASE,
            )
        )
        row_counts[table] = insert_count * 3 or (5 if insert_count > 0 else 0)

    return SchemaResult(
        tables=tables,
        columns=columns,
        row_counts=row_counts,
    )


def find_exposed_sql_dumps(base_url: str, timeout: int = 10) -> tuple[List[ExposedFile], SchemaResult | None]:
    """Probe for exposed SQL dumps and parse the first successful one.

    Returns list of ExposedFile and the parsed schema (if any).
    """
    candidates = locate_sql_urls(base_url)
    exposed: List[ExposedFile] = []
    schema: SchemaResult | None = None

    for sql_url in candidates[:6]:  # reasonable limit to avoid excessive requests
        try:
            resp = httpx.get(
                sql_url,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "PHP-Fossil-Scanner/0.1.0"},
            )
            if resp.status_code != 200 or len(resp.text.strip()) < 50:
                continue

            content_type = resp.headers.get("content-type", "").lower()
            preview = resp.text[:250].lower()
            if (
                "sql" in content_type
                or any(ext in sql_url.lower() for ext in (".sql", ".dump", ".gz"))
                or "create table" in preview
                or "insert into" in preview
            ):
                schema = parse_sql_dump(resp.text)
                exposed.append(
                    ExposedFile(
                        url=sql_url,
                        file_type="sql_dump",
                        content_preview=resp.text[:200] + ("..." if len(resp.text) > 200 else ""),
                    )
                )
                break
        except Exception:  # noqa: BLE001
            continue

    return exposed, schema


__all__ = [
    "locate_sql_urls",
    "parse_sql_dump",
    "find_exposed_sql_dumps",
]
