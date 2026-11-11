"""
Forensic SQLite Engine Package.
Phase 2, Module 2.1 of Forensic Data Parser.
"""

from src.sqlite.engine import ForensicSQLiteEngine
from src.sqlite.models import SQLiteDiagnostics, RecoveredRecord, TableSchema, ColumnSchema
from src.sqlite.header import SQLiteHeader, BTreePageHeader, parse_sqlite_header, parse_btree_page_header
from src.sqlite.varint import decode_varint, encode_varint
from src.sqlite.record import decode_record, decode_serial_type
from src.sqlite.overflow import calculate_overflow_bounds, reassemble_overflow_chain
from src.sqlite.wal import WALReader, WALFrame, WALFrameState
from src.sqlite.journal import RollbackJournalReader, JournalPage
from src.sqlite.carver import ResidualCarver

__all__ = [
    "ForensicSQLiteEngine",
    "SQLiteDiagnostics",
    "RecoveredRecord",
    "TableSchema",
    "ColumnSchema",
    "SQLiteHeader",
    "BTreePageHeader",
    "parse_sqlite_header",
    "parse_btree_page_header",
    "decode_varint",
    "encode_varint",
    "decode_record",
    "decode_serial_type",
    "calculate_overflow_bounds",
    "reassemble_overflow_chain",
    "WALReader",
    "WALFrame",
    "WALFrameState",
    "RollbackJournalReader",
    "JournalPage",
    "ResidualCarver",
]
