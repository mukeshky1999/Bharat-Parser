"""
Thread-safe forensic SQLite connection manager.
Provides unified, concurrency-safe SQLite connections with WAL mode and foreign key enforcement.
"""

from pathlib import Path
import sqlite3
from typing import Union


def connect_forensic_sqlite(
    db_path: Union[str, Path],
    read_only: bool = False,
    timeout: float = 30.0,
) -> sqlite3.Connection:
    """
    Connects to a forensic SQLite database with thread-safe options,
    WAL mode, busy timeouts, and foreign key constraints enabled.
    """
    path_str = str(db_path)
    if read_only and path_str != ":memory:":
        # True read-only open: no journal-mode change, no checkpoint-on-close, no WAL deletion.
        uri = Path(path_str).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout, check_same_thread=False)
    else:
        conn = sqlite3.connect(
            path_str,
            timeout=timeout,
            check_same_thread=False,
        )
    conn.row_factory = sqlite3.Row

    # Enforce database constraints and concurrency safeguards
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.execute("PRAGMA foreign_keys = ON;")

    if read_only:
        conn.execute("PRAGMA query_only = ON;")
    elif path_str != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")

    return conn
