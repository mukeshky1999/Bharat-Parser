"""
Virtual Filesystem (VFS) Query & Streaming Engine.
Phase 1, Module 1.1, Section 7: On-demand memory stream and SQLite co-file staging.
"""

import hashlib
import io
import os
import shutil
import sqlite3
import stat
import struct
import tarfile
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List, Dict, Any

from src.core.enums import (
    CompressionMethod,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ForensicGroup,
)


@dataclass(slots=True)
class StagedSQLiteFamily:
    """Represents a materialized SQLite database family for safe forensic examination."""
    primary_db_path: Path
    wal_path: Optional[Path]
    journal_path: Optional[Path]
    shm_path: Optional[Path]
    product_b1_db_sha256: str
    companion_wal_sha256: Optional[str]
    companion_journal_sha256: Optional[str]
    working_copy_db_path: Path
    working_copy_wal_path: Optional[Path]
    evidentiary_state: EvidentiaryState


class VFSReader:
    """Provides targeted zero-extraction file queries, memory streams, and database staging."""

    def __init__(self, catalog_db_path: Union[str, Path]):
        self.catalog_db_path = Path(catalog_db_path)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.catalog_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def vfs_query_paths(self, pattern_or_exact_path: str) -> List[Dict[str, Any]]:
        """
        Queries the master catalog using either an exact canonical path or SQL LIKE pattern.
        """
        conn = self._get_connection()
        cur = conn.cursor()

        if "%" in pattern_or_exact_path or "_" in pattern_or_exact_path:
            cur.execute(
                "SELECT * FROM vfs_index WHERE canonical_path LIKE ? ORDER BY canonical_path",
                (pattern_or_exact_path,)
            )
        else:
            cur.execute(
                "SELECT * FROM vfs_index WHERE canonical_path = ? ORDER BY canonical_path",
                (pattern_or_exact_path,)
            )

        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return rows

    def _get_container_path(self, container_id: int) -> Path:
        """Looks up the physical filesystem path of the container."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT source_path FROM container_sources WHERE container_id = ?", (container_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            raise FileNotFoundError(f"Container ID {container_id} not registered in container_sources")
        return Path(row["source_path"])

    def vfs_open_memory_stream(self, file_id: int) -> io.BytesIO:
        """
        Decompresses and returns the target file bytes in memory without touching host disk.
        """
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM vfs_index WHERE file_id = ?", (file_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            raise FileNotFoundError(f"Virtual file ID {file_id} not found in catalog")

        container_path = self._get_container_path(row["container_id"])
        comp_method = row["compression_method"]
        offset = row["archive_data_offset"]
        uncomp_size = row["uncompressed_size"]
        comp_size = row["compressed_size"]

        if comp_method == CompressionMethod.RAW_STORED.value:
            with open(container_path, "rb") as f:
                f.seek(offset)
                data = f.read(uncomp_size)
            return io.BytesIO(data)

        elif comp_method in (CompressionMethod.ZIP_DEFLATE.value, CompressionMethod.ZIP_ZSTD.value):
            with open(container_path, "rb") as f:
                f.seek(offset)
                local_header = f.read(30)
                if not local_header.startswith(b"PK\x03\x04"):
                    raise ValueError(f"Corrupt ZIP local file header at offset {offset}")
                name_len, extra_len = struct.unpack("<HH", local_header[26:30])
                payload_offset = offset + 30 + name_len + extra_len
                f.seek(payload_offset)
                raw_compressed = f.read(comp_size)

            if comp_method == CompressionMethod.ZIP_DEFLATE.value:
                # -15 raw deflate window bits
                decompressor = zlib.decompressobj(-15)
                decompressed = decompressor.decompress(raw_compressed)
            else:
                decompressed = raw_compressed
            return io.BytesIO(decompressed)

        elif comp_method == CompressionMethod.TAR_GZ_STREAM.value:
            with tarfile.open(container_path, mode="r:gz") as tar:
                member = tar.getmember(row["original_raw_path"])
                extracted = tar.extractfile(member)
                if extracted is None:
                    return io.BytesIO(b"")
                return io.BytesIO(extracted.read())

        elif comp_method == CompressionMethod.IOS_BACKUP_FILE.value:
            sha1_name = row["backup_file_id_sha1"]
            if not sha1_name:
                raise ValueError(f"Missing backup SHA-1 filename for virtual file ID {file_id}")
            disk_target = container_path / sha1_name[:2] / sha1_name
            if not disk_target.exists():
                # Check root of backup
                disk_target = container_path / sha1_name
            with open(disk_target, "rb") as f:
                return io.BytesIO(f.read())

        elif comp_method == CompressionMethod.ANDROID_AB_STREAM.value:
            from src.vfs.indexer import AbUnpacker
            ab_info = AbUnpacker.parse_header(container_path)
            with open(container_path, "rb") as f:
                f.seek(ab_info.data_offset)
                payload_bytes = f.read()
            try:
                uncompressed_stream = zlib.decompress(payload_bytes)
            except Exception:
                decompressor = zlib.decompressobj()
                uncompressed_stream = decompressor.decompress(payload_bytes)
            data = uncompressed_stream[offset:offset + uncomp_size]
            return io.BytesIO(data)

        else:
            with open(container_path, "rb") as f:
                f.seek(offset)
                data = f.read(uncomp_size)
            return io.BytesIO(data)

    def vfs_stage_sqlite_family(
        self,
        primary_db_file_id: int,
        staging_dir: Union[str, Path]
    ) -> StagedSQLiteFamily:
        """
        Discovers companion SQLite files (-wal, -journal, -shm), stages them into an isolated UUID folder,
        hashes Product B1 bytes, locks Product B1 as read-only, and creates a writable working copy (Product B2).
        """
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM vfs_index WHERE file_id = ?", (primary_db_file_id,))
        primary_row = cur.fetchone()

        if not primary_row:
            conn.close()
            raise FileNotFoundError(f"Primary SQLite file ID {primary_db_file_id} not found in catalog")

        parent_dir = primary_row["parent_dir_path"]
        base_name = primary_row["filename"]

        # Search for companion files in the exact same directory
        cur.execute(
            """
            SELECT * FROM vfs_index
            WHERE parent_dir_path = ? AND filename IN (?, ?, ?)
            """,
            (
                parent_dir,
                f"{base_name}-wal",
                f"{base_name}-journal",
                f"{base_name}-shm"
            )
        )
        companion_rows = {r["filename"]: dict(r) for r in cur.fetchall()}
        conn.close()

        # Create isolated flat UUID folder in staging directory
        safe_uid = f"stg_{uuid.uuid4().hex[:12]}"
        stg_path = Path(staging_dir) / safe_uid
        stg_path.mkdir(parents=True, exist_ok=True)

        work_path = stg_path / "work"
        work_path.mkdir(parents=True, exist_ok=True)

        # 1. Materialize Primary DB (target.db)
        primary_stream = self.vfs_open_memory_stream(primary_db_file_id)
        primary_bytes = primary_stream.read()
        db_sha256 = hashlib.sha256(primary_bytes).hexdigest()

        target_db_path = stg_path / "target.db"
        with open(target_db_path, "wb") as f:
            f.write(primary_bytes)

        # 2. Materialize Companion -wal if present
        wal_path = None
        wal_sha256 = None
        wal_key = f"{base_name}-wal"
        if wal_key in companion_rows:
            wal_stream = self.vfs_open_memory_stream(companion_rows[wal_key]["file_id"])
            wal_bytes = wal_stream.read()
            wal_sha256 = hashlib.sha256(wal_bytes).hexdigest()
            wal_path = stg_path / "target.db-wal"
            with open(wal_path, "wb") as f:
                f.write(wal_bytes)

        # 3. Materialize Companion -journal if present
        journal_path = None
        journal_sha256 = None
        journal_key = f"{base_name}-journal"
        if journal_key in companion_rows:
            journal_stream = self.vfs_open_memory_stream(companion_rows[journal_key]["file_id"])
            journal_bytes = journal_stream.read()
            journal_sha256 = hashlib.sha256(journal_bytes).hexdigest()
            journal_path = stg_path / "target.db-journal"
            with open(journal_path, "wb") as f:
                f.write(journal_bytes)

        # 4. Materialize Companion -shm if present
        shm_path = None
        shm_key = f"{base_name}-shm"
        if shm_key in companion_rows:
            shm_stream = self.vfs_open_memory_stream(companion_rows[shm_key]["file_id"])
            shm_path = stg_path / "target.db-shm"
            with open(shm_path, "wb") as f:
                f.write(shm_stream.read())

        # 5. Lock Product B1 files as Read-Only
        os.chmod(target_db_path, stat.S_IREAD)
        if wal_path:
            os.chmod(wal_path, stat.S_IREAD)
        if journal_path:
            os.chmod(journal_path, stat.S_IREAD)
        if shm_path:
            os.chmod(shm_path, stat.S_IREAD)

        # 6. Create writable working copies (Product B2) in work/
        working_db_path = work_path / "working_copy.db"
        shutil.copyfile(target_db_path, working_db_path)
        os.chmod(working_db_path, stat.S_IREAD | stat.S_IWRITE)

        working_wal_path = None
        if wal_path:
            working_wal_path = work_path / "working_copy.db-wal"
            shutil.copyfile(wal_path, working_wal_path)
            os.chmod(working_wal_path, stat.S_IREAD | stat.S_IWRITE)

        if journal_path:
            working_journal = work_path / "working_copy.db-journal"
            shutil.copyfile(journal_path, working_journal)
            os.chmod(working_journal, stat.S_IREAD | stat.S_IWRITE)

        evidentiary_state = EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            provenance_pointer=f"file_id={primary_db_file_id};offset={primary_row['archive_data_offset']}",
            corroboration_score=1.0,
            linked_artifact_ids=[str(primary_db_file_id)],
            forensic_group=ForensicGroup.G01_INGESTION_AND_OWNERSHIP
        )

        return StagedSQLiteFamily(
            primary_db_path=target_db_path,
            wal_path=wal_path,
            journal_path=journal_path,
            shm_path=shm_path,
            product_b1_db_sha256=db_sha256,
            companion_wal_sha256=wal_sha256,
            companion_journal_sha256=journal_sha256,
            working_copy_db_path=working_db_path,
            working_copy_wal_path=working_wal_path,
            evidentiary_state=evidentiary_state
        )
