"""SQL schema extraction from exposed dump files.

Locates common SQL backup URLs in HTML and parses CREATE TABLE / INSERT
statements into a SchemaResult. Used by AsyncScanner.
"""

import re
from typing import Dict, List, Optional

from .models import SchemaResult


def locate_sql_urls(body: str, base_url: str) -> List[str]:
    """Find potential SQL dump URLs in HTML body or by common naming patterns.

    Returns up to 5 unique candidate URLs.
    """
    urls: List[str] = []
    # Extract hrefs pointing to .sql / .dump files
    sql_links = re.findall(
        r'href=["\']([^"\']*?\.(?:sql|dump|backup)(?:\.(?:gz|bz2))?)[ "\']',
        body,
        re.IGNORECASE,
    )
    for link in sql_links:
        if not link.startswith(("http://", "https://")):
            link = f"{base_url.rstrip('/')}/{link.lstrip('/')}"
        if link not in urls:
            urls.append(link)

    # Common backup file names
    common = [
        "backup.sql",
        "dump.sql",
        "schema.sql",
        "database.sql",
        "data.sql",
        "backup.sql.gz",
    ]
    base = base_url.rstrip("/")
    for name in common:
        candidate = f"{base}/{name}"
        if candidate not in urls:
            urls.append(candidate)

    return urls[:5]


def parse_sql_dump(content: str) -> Optional[SchemaResult]:
    """Parse basic table/column information from an SQL dump.

    Looks for CREATE TABLE statements and counts INSERTs for rough row estimates.
    Returns None if no tables are found.
    """
    if not content or len(content.strip()) < 10:
        return None

    tables: List[str] = []
    columns: Dict[str, List[str]] = {}
    row_counts: Dict[str, int] = {}

    # Capture CREATE TABLE ... ( col definitions )
    create_matches = re.findall(
        r"CREATE\s+TABLE\s+[`\"']?(\w+)[`\"']?\s*\((.+?)\);",
        content,
        re.IGNORECASE | re.DOTALL,
    )
    for table_name, cols_def in create_matches:
        tname = table_name.lower()
        if tname not in tables:
            tables.append(tname)
        col_list = []
        for col_match in re.finditer(
            r"[`\"']?(\w+)[`\"']?\s+\w+", cols_def, re.IGNORECASE
        ):
            col_list.append(col_match.group(1).lower())
        columns[tname] = col_list

        # Rough row count from INSERT statements
        insert_count = len(
            re.findall(
                rf"INSERT\s+INTO\s+[`\"']?{re.escape(table_name)}[`\"']?",
                content,
                re.IGNORECASE,
            )
        )
        row_counts[tname] = max(insert_count * 5, 10)

    # Fallback: tables mentioned only in INSERTs
    if not tables:
        insert_tables = re.findall(
            r"INSERT\s+INTO\s+[`\"']?(\w+)[`\"']?", content, re.IGNORECASE
        )
        for t in insert_tables:
            tname = t.lower()
            if tname not in tables:
                tables.append(tname)
                columns[tname] = ["id", "value"]
                row_counts[tname] = 50

    if not tables:
        return None

    return SchemaResult(
        tables=tables, columns=columns, row_counts=row_counts
    )


__all__ = ["locate_sql_urls", "parse_sql_dump"]
