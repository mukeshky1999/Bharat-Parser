"""Where, in the file, does a live SQLite row sit?  (X-13, stage B)

Given a database file and a table, finds the page number and the absolute byte offset of the cell for each
requested rowid by walking that table's b-tree with the ``src.sqlite`` reader. It decodes only the two
varints at the start of each cell, so it is cheap on large databases.

The offset is reported only when the main file is the whole truth. If a write-ahead log holding frames sits
next to the database, the newest version of a row may live in the log rather than at the main-file offset,
so the locator reports nothing for that database and the provenance says "Not recorded".
"""
from __future__ import annotations

import logging
import os
import struct
from typing import Dict, Iterable, Optional, Tuple

from src.sqlite.engine import ForensicSQLiteEngine
from src.sqlite.header import parse_btree_page_header, parse_sqlite_header
from src.sqlite.varint import decode_varint

logger = logging.getLogger(__name__)

WAL_HEADER_BYTES = 32


class RowLocator:
    """Locates cells of one database file. ``exact`` is False when offsets cannot be trusted."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.exact = False
        self.reason = ""
        self._engine = ForensicSQLiteEngine()
        self._page_size = 0
        self._file_size = 0
        self._fh = None
        try:
            self._open()
        except Exception as exc:                                    # unreadable or not SQLite
            self.reason = f"locator unavailable: {exc}"
            logger.debug("RowLocator(%s): %s", db_path, exc)

    # ------------------------------------------------------------------ setup
    def _open(self) -> None:
        self._file_size = os.path.getsize(self.db_path)
        with open(self.db_path, "rb") as f:
            header = parse_sqlite_header(f.read(100))
        self._page_size = header.page_size
        self._engine.db_header = header
        wal = self.db_path + "-wal"
        if os.path.isfile(wal) and os.path.getsize(wal) > WAL_HEADER_BYTES:
            self.reason = "a write-ahead log with frames exists; main-file offsets could be out of date"
            return
        self._fh = open(self.db_path, "rb")
        self._engine._parse_schema_from_page1(
            self._page(1), header.usable_page_size, header.text_encoding, self._page
        )
        self._engine._map_btree_pages(self._page)
        self.exact = True

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "RowLocator":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _page(self, number: int) -> bytes:
        if self._fh is None or number < 1 or (number - 1) * self._page_size >= self._file_size:
            return b""
        self._fh.seek((number - 1) * self._page_size)
        return self._fh.read(self._page_size)

    # ------------------------------------------------------------------ lookup
    def locate(self, table: str, rowids: Iterable[int]) -> Dict[int, Tuple[int, int]]:
        """{rowid: (page number, absolute byte offset of the cell)} for the rowids found in the live b-tree."""
        if not self.exact:
            return {}
        schema = self._engine.table_schemas.get(table)
        if schema is None or schema.is_without_rowid:
            return {}
        wanted = {int(r) for r in rowids}
        found: Dict[int, Tuple[int, int]] = {}
        for page_num, owner in self._engine.page_owner_map.items():
            if owner != table:
                continue
            data = self._page(page_num)
            hdr_off = 100 if page_num == 1 else 0
            if len(data) < hdr_off + 8 or data[hdr_off] != 0x0D:
                continue
            hdr = parse_btree_page_header(data, page_num)
            base = (page_num - 1) * self._page_size
            for i in range(hdr.cell_count):
                pos = hdr_off + hdr.header_size + i * 2
                if pos + 2 > len(data):
                    break
                cell_off = struct.unpack(">H", data[pos:pos + 2])[0]
                if cell_off >= len(data):
                    continue
                try:
                    payload_len, n1 = decode_varint(data, cell_off)
                    rowid, _ = decode_varint(data, cell_off + n1)
                except Exception:
                    continue
                if rowid in wanted:
                    found[rowid] = (page_num, base + cell_off)
        return found
