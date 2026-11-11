"""
Dual SQLite FTS5 (unicode61 + trigram + Indic NFC) & Roaring Bitmap Search Engine (Sub-Engine 8.2D).
Provides sub-50ms lexical and substring searching and in-memory 32-bit Roaring Bitmap facet filtering.
"""

import os
import re
import sqlite3
import struct
import unicodedata
from typing import Any, Optional

from src.zero_omission_and_fts5.models import (
    RoaringFacetEntry,
    SearchDocument,
)


class RoaringBitmap32:
    """Compressed 32-bit Roaring Bitmap implementation for fast in-RAM facet filtering."""

    COOKIE = b"\x30\x3b"  # 0x3B30 Roaring standard magic cookie
    ARRAY_CONTAINER = 0
    BITSET_CONTAINER = 1

    def __init__(self):
        # Maps chunk_key (uint16) -> (container_type, data)
        # For ARRAY_CONTAINER: data is a set of uint16 ints
        # For BITSET_CONTAINER: data is a bytearray of 8192 bytes
        self.chunks: dict[int, tuple[int, Any]] = {}

    def add(self, uid: int) -> None:
        """Adds a 32-bit unsigned integer to the bitmap."""
        chunk_key = (uid >> 16) & 0xFFFF
        val = uid & 0xFFFF

        if chunk_key not in self.chunks:
            self.chunks[chunk_key] = (self.ARRAY_CONTAINER, {val})
            return

        c_type, data = self.chunks[chunk_key]
        if c_type == self.ARRAY_CONTAINER:
            data.add(val)
            if len(data) >= 4096:
                # Convert array container to dense bitset container
                bitset = bytearray(8192)
                for v in data:
                    bitset[v // 8] |= 1 << (v % 8)
                self.chunks[chunk_key] = (self.BITSET_CONTAINER, bitset)
        else:
            data[val // 8] |= 1 << (val % 8)

    def contains(self, uid: int) -> bool:
        """Tests whether a 32-bit integer is present."""
        chunk_key = (uid >> 16) & 0xFFFF
        val = uid & 0xFFFF
        if chunk_key not in self.chunks:
            return False

        c_type, data = self.chunks[chunk_key]
        if c_type == self.ARRAY_CONTAINER:
            return val in data
        return bool(data[val // 8] & (1 << (val % 8)))

    def cardinality(self) -> int:
        """Computes the total population count (POPCNT) of the bitmap."""
        total = 0
        for c_type, data in self.chunks.values():
            if c_type == self.ARRAY_CONTAINER:
                total += len(data)
            else:
                total += sum(b.bit_count() for b in data)
        return total

    def to_list(self) -> list[int]:
        """Returns sorted list of all 32-bit integers in the bitmap."""
        result: list[int] = []
        for chunk_key in sorted(self.chunks.keys()):
            c_type, data = self.chunks[chunk_key]
            base = chunk_key << 16
            if c_type == self.ARRAY_CONTAINER:
                for v in sorted(data):
                    result.append(base | v)
            else:
                for byte_idx, b in enumerate(data):
                    if b > 0:
                        for bit_idx in range(8):
                            if b & (1 << bit_idx):
                                result.append(base | ((byte_idx * 8) + bit_idx))
        return result

    def intersection(self, other: "RoaringBitmap32") -> "RoaringBitmap32":
        """Bitwise AND intersection returning a new RoaringBitmap32."""
        res = RoaringBitmap32()
        common_keys = set(self.chunks.keys()).intersection(other.chunks.keys())

        for k in common_keys:
            t1, d1 = self.chunks[k]
            t2, d2 = other.chunks[k]

            if t1 == self.ARRAY_CONTAINER and t2 == self.ARRAY_CONTAINER:
                inter = d1.intersection(d2)
                if inter:
                    res.chunks[k] = (self.ARRAY_CONTAINER, inter)
            elif t1 == self.BITSET_CONTAINER and t2 == self.BITSET_CONTAINER:
                bs = bytearray(a & b for a, b in zip(d1, d2))
                if any(b > 0 for b in bs):
                    # Check if reduced bitset should convert back to array
                    cnt = sum(b.bit_count() for b in bs)
                    if cnt < 4096:
                        arr = set()
                        for byte_idx, b in enumerate(bs):
                            if b > 0:
                                for bit_idx in range(8):
                                    if b & (1 << bit_idx):
                                        arr.add((byte_idx * 8) + bit_idx)
                        res.chunks[k] = (self.ARRAY_CONTAINER, arr)
                    else:
                        res.chunks[k] = (self.BITSET_CONTAINER, bs)
            elif t1 == self.ARRAY_CONTAINER and t2 == self.BITSET_CONTAINER:
                inter = {v for v in d1 if (d2[v // 8] & (1 << (v % 8)))}
                if inter:
                    res.chunks[k] = (self.ARRAY_CONTAINER, inter)
            else:  # t1 == BITSET_CONTAINER and t2 == ARRAY_CONTAINER
                inter = {v for v in d2 if (d1[v // 8] & (1 << (v % 8)))}
                if inter:
                    res.chunks[k] = (self.ARRAY_CONTAINER, inter)

        return res

    def union(self, other: "RoaringBitmap32") -> "RoaringBitmap32":
        """Bitwise OR union returning a new RoaringBitmap32."""
        res = RoaringBitmap32()
        for k, (t, d) in self.chunks.items():
            if t == self.ARRAY_CONTAINER:
                res.chunks[k] = (t, set(d))
            else:
                res.chunks[k] = (t, bytearray(d))

        for k, (t2, d2) in other.chunks.items():
            if k not in res.chunks:
                if t2 == self.ARRAY_CONTAINER:
                    res.chunks[k] = (t2, set(d2))
                else:
                    res.chunks[k] = (t2, bytearray(d2))
            else:
                t1, d1 = res.chunks[k]
                if t1 == self.ARRAY_CONTAINER and t2 == self.ARRAY_CONTAINER:
                    combined = d1.union(d2)
                    if len(combined) >= 4096:
                        bs = bytearray(8192)
                        for v in combined:
                            bs[v // 8] |= 1 << (v % 8)
                        res.chunks[k] = (self.BITSET_CONTAINER, bs)
                    else:
                        res.chunks[k] = (self.ARRAY_CONTAINER, combined)
                elif t1 == self.BITSET_CONTAINER and t2 == self.BITSET_CONTAINER:
                    for i in range(8192):
                        d1[i] |= d2[i]
                elif t1 == self.ARRAY_CONTAINER and t2 == self.BITSET_CONTAINER:
                    bs = bytearray(d2)
                    for v in d1:
                        bs[v // 8] |= 1 << (v % 8)
                    res.chunks[k] = (self.BITSET_CONTAINER, bs)
                else:  # t1 == BITSET, t2 == ARRAY
                    for v in d2:
                        d1[v // 8] |= 1 << (v % 8)

        return res

    def to_bytes(self) -> bytes:
        """Serializes bitmap into binary format with 0x3B30 cookie header."""
        chunks_count = len(self.chunks)
        out = bytearray(self.COOKIE)
        out.extend(struct.pack("<I", chunks_count))

        for k in sorted(self.chunks.keys()):
            c_type, data = self.chunks[k]
            if c_type == self.ARRAY_CONTAINER:
                cnt = len(data)
                out.extend(struct.pack("<HHB", k, cnt, self.ARRAY_CONTAINER))
                out.extend(struct.pack(f"<{cnt}H", *sorted(data)))
            else:
                cnt = sum(b.bit_count() for b in data)
                out.extend(struct.pack("<HHB", k, cnt, self.BITSET_CONTAINER))
                out.extend(data)

        return bytes(out)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "RoaringBitmap32":
        """Deserializes a RoaringBitmap32 from binary bytes."""
        bm = cls()
        if len(raw) < 6 or raw[:2] != cls.COOKIE:
            return bm

        chunks_count = struct.unpack_from("<I", raw, 2)[0]
        offset = 6

        for _ in range(chunks_count):
            if offset + 5 > len(raw):
                break
            k, cnt, c_type = struct.unpack_from("<HHB", raw, offset)
            offset += 5

            if c_type == cls.ARRAY_CONTAINER:
                byte_len = cnt * 2
                if offset + byte_len > len(raw):
                    break
                elements = set(struct.unpack_from(f"<{cnt}H", raw, offset))
                bm.chunks[k] = (cls.ARRAY_CONTAINER, elements)
                offset += byte_len
            else:
                byte_len = 8192
                if offset + byte_len > len(raw):
                    break
                bm.chunks[k] = (cls.BITSET_CONTAINER, bytearray(raw[offset : offset + byte_len]))
                offset += byte_len

        return bm


class DualFts5AndRoaringEngine:
    """Manages custom-tokenized lexical FTS5, trigram substring FTS5, and Roaring Bitmap facet storage."""

    ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\u200E\u200F\uFEFF]")

    def __init__(self):
        self.db_path: Optional[str] = None
        self._facet_cache: dict[tuple[str, str], RoaringBitmap32] = {}

    @classmethod
    def normalize_text(cls, text: Optional[str]) -> str:
        """Applies Unicode NFC Canonical Composition and strips invisible zero-width characters."""
        if not text:
            return ""
        nfc_text = unicodedata.normalize("NFC", text)
        return cls.ZERO_WIDTH_CHARS.sub("", nfc_text)

    def initialize_database(self, db_path: str) -> None:
        """Creates the master document table and companion FTS5 virtual tables and triggers."""
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # 1. Master document table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS global_search_documents_master (
                doc_uid INTEGER PRIMARY KEY,
                timeline_event_uid INTEGER,
                originating_phase_module TEXT NOT NULL,
                artifact_domain TEXT NOT NULL,
                app_package TEXT,
                source_vfs_file_id INTEGER,
                source_record_pointer TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                timestamp_utc_ns INTEGER,
                actor_names_and_handles_nfc TEXT,
                searchable_body_text_nfc TEXT
            );
            """
        )

        # 2. Custom-Tokenized Lexical FTS5 Index
        cur.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS global_fts5_lexical_index USING fts5(
                actor_names_and_handles_nfc,
                searchable_body_text_nfc,
                content='global_search_documents_master',
                content_rowid='doc_uid',
                tokenize="unicode61 remove_diacritics 2 tokenchars '@._:-+/$#'"
            );
            """
        )

        # 3. Trigram Substring FTS5 Index
        cur.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS global_fts5_trigram_index USING fts5(
                actor_names_and_handles_nfc,
                searchable_body_text_nfc,
                content='global_search_documents_master',
                content_rowid='doc_uid',
                tokenize="trigram case_sensitive 0"
            );
            """
        )

        # 4. Triggers to keep FTS5 in sync with Master document table
        cur.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_docs_ai AFTER INSERT ON global_search_documents_master BEGIN
                INSERT INTO global_fts5_lexical_index(rowid, actor_names_and_handles_nfc, searchable_body_text_nfc)
                VALUES (new.doc_uid, new.actor_names_and_handles_nfc, new.searchable_body_text_nfc);
                INSERT INTO global_fts5_trigram_index(rowid, actor_names_and_handles_nfc, searchable_body_text_nfc)
                VALUES (new.doc_uid, new.actor_names_and_handles_nfc, new.searchable_body_text_nfc);
            END;
            """
        )

        # 5. Roaring Bitmap Facet Store Table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS roaring_bitmap_facet_index_store (
                facet_bitmap_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                target_table_scope TEXT NOT NULL,
                facet_dimension_name TEXT NOT NULL,
                facet_value_key TEXT NOT NULL,
                total_matching_cardinality INTEGER NOT NULL,
                serialized_roaring_bitmap_blob BLOB NOT NULL
            );
            """
        )

        conn.commit()
        conn.close()

    def index_documents(self, docs: list[SearchDocument]) -> None:
        """Inserts documents, synchronizes FTS5 virtual tables, and compiles Roaring Bitmap facets."""
        if not self.db_path:
            raise RuntimeError("Database not initialized")

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Build in-memory facet bitmaps during ingestion
        facet_map: dict[tuple[str, str], RoaringBitmap32] = {}

        for doc in docs:
            norm_actor = self.normalize_text(doc.actor_names_and_handles_nfc)
            norm_body = self.normalize_text(doc.searchable_body_text_nfc)

            cur.execute(
                """
                INSERT OR REPLACE INTO global_search_documents_master (
                    doc_uid,
                    timeline_event_uid,
                    originating_phase_module,
                    artifact_domain,
                    app_package,
                    source_vfs_file_id,
                    source_record_pointer,
                    recovery_classification,
                    timestamp_utc_ns,
                    actor_names_and_handles_nfc,
                    searchable_body_text_nfc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    doc.doc_uid,
                    doc.timeline_event_uid,
                    doc.originating_phase_module,
                    doc.artifact_domain,
                    doc.app_package,
                    doc.source_vfs_file_id,
                    doc.source_record_pointer,
                    doc.recovery_classification,
                    doc.timestamp_utc_ns,
                    norm_actor,
                    norm_body,
                ),
            )

            uid = doc.doc_uid or cur.lastrowid

            # Track categorical facets
            facets_to_track = [
                ("originating_phase_module", doc.originating_phase_module),
                ("artifact_domain", doc.artifact_domain),
                ("recovery_classification", doc.recovery_classification),
            ]
            if doc.app_package:
                facets_to_track.append(("app_package", doc.app_package))

            for dim, val in facets_to_track:
                key = (dim, val)
                if key not in facet_map:
                    facet_map[key] = RoaringBitmap32()
                facet_map[key].add(uid)

        # Store Roaring Bitmaps in database
        for (dim, val), bm in facet_map.items():
            cardinality = bm.cardinality()
            blob = bm.to_bytes()
            cur.execute(
                """
                INSERT INTO roaring_bitmap_facet_index_store (
                    target_table_scope,
                    facet_dimension_name,
                    facet_value_key,
                    total_matching_cardinality,
                    serialized_roaring_bitmap_blob
                ) VALUES (?, ?, ?, ?, ?);
                """,
                ("GLOBAL_SEARCH_DOCUMENTS", dim, val, cardinality, blob),
            )
            self._facet_cache[(dim, val)] = bm

        conn.commit()
        conn.close()

    def search_lexical(self, query: str) -> list[SearchDocument]:
        """Runs custom-tokenized lexical FTS5 search (supporting intact VPAs and Indic NFC)."""
        if not self.db_path:
            return []

        norm_query = self.normalize_text(query).strip()
        if not norm_query:
            return []

        # If query contains tokenchars or spaces, wrap in double quotes for exact token matching
        special_chars = set("@._:-+/$# ")
        if any(c in special_chars for c in norm_query):
            clean_q = norm_query.replace('"', '""')
            match_expr = f'"{clean_q}"'
        else:
            match_expr = norm_query

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT m.doc_uid, m.timeline_event_uid, m.originating_phase_module, m.artifact_domain,
                   m.app_package, m.source_vfs_file_id, m.source_record_pointer, m.recovery_classification,
                   m.timestamp_utc_ns, m.actor_names_and_handles_nfc, m.searchable_body_text_nfc
            FROM global_fts5_lexical_index f
            JOIN global_search_documents_master m ON f.rowid = m.doc_uid
            WHERE global_fts5_lexical_index MATCH ?
            ORDER BY rank;
            """,
            (match_expr,),
        )

        rows = cur.fetchall()
        conn.close()

        results: list[SearchDocument] = []
        for r in rows:
            results.append(
                SearchDocument(
                    doc_uid=r[0],
                    timeline_event_uid=r[1],
                    originating_phase_module=r[2],
                    artifact_domain=r[3],
                    app_package=r[4],
                    source_vfs_file_id=r[5],
                    source_record_pointer=r[6],
                    recovery_classification=r[7],
                    timestamp_utc_ns=r[8],
                    actor_names_and_handles_nfc=r[9],
                    searchable_body_text_nfc=r[10],
                )
            )
        return results

    def search_trigram(self, substring: str) -> list[SearchDocument]:
        """Runs sub-50ms 3-character trigram substring matching."""
        if not self.db_path:
            return []

        norm_sub = self.normalize_text(substring).strip()
        if not norm_sub:
            return []

        clean_sub = norm_sub.replace('"', '""')
        match_expr = f'"{clean_sub}"'

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT m.doc_uid, m.timeline_event_uid, m.originating_phase_module, m.artifact_domain,
                   m.app_package, m.source_vfs_file_id, m.source_record_pointer, m.recovery_classification,
                   m.timestamp_utc_ns, m.actor_names_and_handles_nfc, m.searchable_body_text_nfc
            FROM global_fts5_trigram_index f
            JOIN global_search_documents_master m ON f.rowid = m.doc_uid
            WHERE global_fts5_trigram_index MATCH ?
            ORDER BY rank;
            """,
            (match_expr,),
        )

        rows = cur.fetchall()
        conn.close()

        results: list[SearchDocument] = []
        for r in rows:
            results.append(
                SearchDocument(
                    doc_uid=r[0],
                    timeline_event_uid=r[1],
                    originating_phase_module=r[2],
                    artifact_domain=r[3],
                    app_package=r[4],
                    source_vfs_file_id=r[5],
                    source_record_pointer=r[6],
                    recovery_classification=r[7],
                    timestamp_utc_ns=r[8],
                    actor_names_and_handles_nfc=r[9],
                    searchable_body_text_nfc=r[10],
                )
            )
        return results

    def query_facets(self, facet_filters: dict[str, str]) -> list[int]:
        """Performs multi-dimensional facet filtering in RAM using bitwise Roaring Bitmap intersection."""
        if not facet_filters:
            return []

        bitmaps: list[RoaringBitmap32] = []
        for dim, val in facet_filters.items():
            key = (dim, val)
            bm = self._facet_cache.get(key)
            if bm is None and self.db_path:
                # Load from database if not cached
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT serialized_roaring_bitmap_blob
                    FROM roaring_bitmap_facet_index_store
                    WHERE facet_dimension_name = ? AND facet_value_key = ?
                    LIMIT 1;
                    """,
                    (dim, val),
                )
                row = cur.fetchone()
                conn.close()
                if row:
                    bm = RoaringBitmap32.from_bytes(row[0])
                    self._facet_cache[key] = bm

            if bm is None:
                # Filter matched 0 documents
                return []
            bitmaps.append(bm)

        # Intersect all bitmaps in RAM
        result_bm = bitmaps[0]
        for next_bm in bitmaps[1:]:
            result_bm = result_bm.intersection(next_bm)

        return result_bm.to_list()
