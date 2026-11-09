"""Schema extraction from exposed SQL dumps and discovery of common backup URLs.

Provides robust regex-based parsing of mysqldump-style files, table/column
extraction, row count estimation and helper to generate candidate SQL URLs.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from .models import SchemaResult


def parse_sql_dump(content: str) -> SchemaResult:
    """Parse an SQL dump and return structured SchemaResult.

    Extracts:
      - Unique table names from CREATE TABLE statements
      - Column names per table
      - Rough row count based on INSERT statement occurrences

    Handles common mysqldump, phpMyAdmin and manual backup formats.
    Gracefully degrades on malformed or non-SQL content. Improved regexes
    ensure all tables/columns are captured even with complex column defs
    (enums, decimals, INTEGER, JSON, etc.).

    Args:
        content: Full text content of a .sql file.

    Returns:
        SchemaResult with tables, columns and row_counts.
    """
    if not content or not isinstance(content, str):
        return SchemaResult()

    if len(content.strip()) < 20:
        return SchemaResult()

    # More permissive table detection supporting newlines, quotes and
    # optional parentheses or AS/LIKE clauses.
    table_pattern = re.compile(
        r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?(\w+)[`\"']?(?:\s*\(|\s+)",
        re.DOTALL | re.MULTILINE,
    )
    tables = table_pattern.findall(content)
    unique_tables = list(dict.fromkeys(tables))  # preserve first-seen order

    columns: Dict[str, List[str]] = {}
    row_counts: Dict[str, int] = {}

    for table in unique_tables:
        # Robust capture of column block: stops at ENGINE/CHARSET/; after the closing paren
        create_pattern = re.compile(
            rf"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?{re.escape(table)}[`\"']?"
            rf"\s*\((.+?)\)\s*(?:ENGINE|CHARSET|COLLATE|;|$)",
            re.DOTALL,
        )
        create_match = create_pattern.search(content)
        if create_match:
            col_block = create_match.group(1)
            # Expanded datatype list to handle INTEGER, JSON, BOOLEAN, etc.
            col_pattern = re.compile(
                r"[`\"']?(\w+)[`\"']?\s+(?:tinyint|smallint|mediumint|int|integer|bigint|float|"
                r"double|decimal|numeric|date|time|datetime|timestamp|year|char|varchar|binary|"
                r"varbinary|tinyblob|blob|mediumblob|longblob|tinytext|text|mediumtext|longtext|"
                r"enum|set|json|bool|boolean)",
                re.IGNORECASE,
            )
            col_names = col_pattern.findall(col_block)
            columns[table] = col_names

        # Estimate rows from INSERT statements
        insert_pattern = re.compile(
            rf"(?i)INSERT\s+(?:IGNORE\s+)?INTO\s+[`\"']?{re.escape(table)}[`\"']?",
        )
        row_counts[table] = len(insert_pattern.findall(content))

    return SchemaResult(
        tables=unique_tables,
        columns=columns,
        row_counts=row_counts,
    )


def locate_sql_urls(base_url: str) -> List[str]:
    """Generate list of candidate URLs where SQL dumps are commonly exposed.

    Appends well-known backup filenames to the base URL. Useful for the
    AsyncScanner to probe for exposed schema files.

    Args:
        base_url: Base target URL (http://example.com or with path).

    Returns:
        List of full candidate URLs to test.

    Raises:
        ValueError: If base_url is missing, invalid or not HTTP/HTTPS.
    """
    if not base_url or not isinstance(base_url, str):
        raise ValueError("base_url must be a non-empty string")

    base_url = base_url.strip()
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")

    common_paths = [
        "dump.sql",
        "backup.sql",
        "db.sql",
        "database.sql",
        "schema.sql",
        "backup/db.sql",
        "sql/backup.sql",
        "data.sql",
        "mysql.sql",
        "all.sql",
        "phpmyadmin.sql",
        "export.sql",
        "prod.sql",
        ".sql",
        "db_backup.sql",
    ]

    # Normalize base
    parsed = urlparse(base_url)
    normalized_base = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        normalized_base = urljoin(normalized_base, parsed.path.rstrip("/"))

    urls: List[str] = []
    for path in common_paths:
        candidate = urljoin(normalized_base + "/", path)
        if candidate not in urls:
            urls.append(candidate)

    return urls


def extract_sample_data(
    content: str, table_name: str, max_samples: int = 2
) -> List[Dict[str, Any]]:
    """Extract a few sample INSERT rows for a given table (demo only).

    Very lightweight parser - not a full SQL parser. Used mainly for
    HTML report enrichment when a schema leak is found.

    Args:
        content: SQL dump content.
        table_name: Target table.
        max_samples: Maximum number of sample rows to return.

    Returns:
        List of dicts with raw VALUES snippets.
    """
    if not content or not table_name:
        return []

    # Match VALUES clauses after INSERT INTO `table`
    pattern = re.compile(
        rf"(?i)INSERT\s+INTO\s+[`\"']?{re.escape(table_name)}[`\"']?.*?VALUES\s*"
        r"(\([^;]{10,80}?\))(?:,|\s*;)",
        re.DOTALL,
    )
    matches = pattern.findall(content)

    samples = []
    for match in matches[:max_samples]:
        cleaned = match.strip().replace("\n", " ")[:120]
        samples.append({"raw_values": cleaned + ("..." if len(match) > 120 else "")})

    return samples


class SchemaExtractor:
    """Optional OO wrapper around the functional API.

    Useful for extensibility when adding support for different dump formats
    (JSON, XML, CSV) in the future.
    """

    @staticmethod
    def from_content(content: str) -> SchemaResult:
        """Parse SQL content and return SchemaResult (alias for parse_sql_dump)."""
        return parse_sql_dump(content)

    @staticmethod
    def discover_urls(target_url: str) -> List[str]:
        """Alias for locate_sql_urls for a more object-oriented style."""
        return locate_sql_urls(target_url)


__all__ = [
    "parse_sql_dump",
    "locate_sql_urls",
    "extract_sample_data",
    "SchemaExtractor",
]
