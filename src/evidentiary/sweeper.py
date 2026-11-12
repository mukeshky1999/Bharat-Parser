"""
Unknown & Unclassified Artifacts Sweeper (The UNK & PHY Ledger).
Phase 1, Module 1.4, Section 4.
"""

from src.core.sqlite_uri import ro_uri
import json
import logging
import math
import sqlite3
from pathlib import Path
from typing import Optional, Union, Dict, Any

from src.evidentiary.enums import UnclassifiedStorageFormat, ExaminerReviewStatus
from src.evidentiary.ledger import TripartiteLedgerDatabase

logger = logging.getLogger(__name__)

SQLITE3_MAGIC = b"SQLite format 3\x00"
BPLIST_MAGIC = b"bplist00"


class UnclassifiedArtifactsSweeper:
    """Discovers and deep-inspects unparsed databases and binary files in app sandboxes."""

    def __init__(self, ledger: TripartiteLedgerDatabase):
        self.ledger = ledger

    def inspect_unclassified_file(
        self,
        vfs_file_id: int,
        canonical_path: str,
        file_disk_path: Union[str, Path],
        owning_app_instance_id: Optional[int] = None,
        inferred_forensic_group: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Inspects unparsed files, auto-extracts SQLite table names & row counts,
        and assigns sequential UNK codes.
        """
        disk_path = Path(file_disk_path)
        file_size = disk_path.stat().st_size if disk_path.exists() else 0

        header = b""
        if disk_path.exists() and file_size > 0:
            with open(disk_path, "rb") as f:
                header = f.read(64)

        # 1. Format Detection
        table_summary_json: Optional[str] = None
        storage_format = UnclassifiedStorageFormat.UNKNOWN_BINARY

        if header.startswith(SQLITE3_MAGIC):
            storage_format = UnclassifiedStorageFormat.SQLITE3
            table_summary = self._inspect_sqlite_tables(disk_path)
            table_summary_json = json.dumps(table_summary)

        elif b"mmkv" in disk_path.name.lower().encode() or disk_path.suffix.lower() == ".crc":
            storage_format = UnclassifiedStorageFormat.MMKV

        elif disk_path.name in ("CURRENT", "MANIFEST") or disk_path.suffix.lower() in (".ldb", ".sst"):
            storage_format = UnclassifiedStorageFormat.LEVELDB

        elif disk_path.suffix.lower() == ".realm":
            storage_format = UnclassifiedStorageFormat.REALM

        elif header.startswith(BPLIST_MAGIC):
            storage_format = UnclassifiedStorageFormat.BPLIST

        elif file_size > 1024 and self._calculate_entropy(header) > 7.8:
            storage_format = UnclassifiedStorageFormat.HIGH_ENTROPY_ENCRYPTED

        # 2. Sequential UNK ID Generation
        existing_records = self.ledger.get_unclassified_artifacts()
        next_num = len(existing_records) + 1
        unk_id = f"UNK-{next_num:04d}"

        # 3. Ledger Registration
        self.ledger.record_unclassified_artifact(
            unk_id=unk_id,
            vfs_file_id=vfs_file_id,
            canonical_path=canonical_path,
            detected_storage_format=storage_format.value,
            file_size_bytes=file_size,
            sqlite_table_summary_json=table_summary_json,
            app_instance_id=owning_app_instance_id,
            inferred_forensic_group=inferred_forensic_group,
            examiner_review_status=ExaminerReviewStatus.PENDING_REVIEW.value
        )

        return {
            "unk_id": unk_id,
            "vfs_file_id": vfs_file_id,
            "canonical_path": canonical_path,
            "detected_storage_format": storage_format.value,
            "file_size_bytes": file_size,
            "sqlite_table_summary_json": table_summary_json,
            "owning_app_instance_id": owning_app_instance_id,
            "inferred_forensic_group": inferred_forensic_group,
            "examiner_review_status": ExaminerReviewStatus.PENDING_REVIEW.value
        }

    def _inspect_sqlite_tables(self, sqlite_path: Path) -> Dict[str, int]:
        """Opens database in read-only mode and computes table row counts."""
        tables_dict: Dict[str, int] = {}
        try:
            uri_path = ro_uri(sqlite_path.resolve().as_posix())
            conn = sqlite3.connect(uri_path, uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cur.fetchall()]

            for t in tables:
                try:
                    cur.execute(f"SELECT COUNT(*) FROM \"{t}\";")
                    row = cur.fetchone()
                    tables_dict[t] = int(row[0]) if row else 0
                except Exception as err:
                    logger.debug("Failed counting rows for table %s: %s", t, err)
                    tables_dict[t] = 0
            conn.close()
        except Exception as err:
            logger.debug("Failed reading SQLite tables from %s: %s", sqlite_path, err)
        return tables_dict

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies: Dict[int, int] = {}
        for b in data:
            frequencies[b] = frequencies.get(b, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
