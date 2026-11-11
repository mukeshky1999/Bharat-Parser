"""
Master Non-SQLite Forensic Storage Engine.
Coordinates Tencent MMKV, Google LevelDB/Chromium IndexedDB, and Apple Biome SEGB decoders
and exports extracted artifacts to the canonical non-SQLite forensic ledger database.
Adheres strictly to Specification Section 7 and AGENTS.md Forensic Invariants.
"""

from pathlib import Path
import sqlite3
from typing import Any, List, Optional, Tuple

from src.core.enums import ResidualConfidence
from src.nonsqlite.leveldb import LevelDBDecoder
from src.nonsqlite.mmkv import MMKVDecoder
from src.nonsqlite.models import (
    BiomeSEGBRecord,
    EngineFormat,
    KVRecoveredRecord,
    KVStoreDiagnostics,
    SEGBVersion,
)
from src.nonsqlite.segb import SEGBDecoder


def _enum_val(val: Any) -> str:
    """Extracts raw string representation from enum or string."""
    if hasattr(val, "value"):
        return str(val.value)
    return str(val) if val is not None else ""


class NonSQLiteForensicEngine:
    """
    Coordinates multi-engine non-SQLite binary decoders and persists
    extracted evidentiary stores into `nonsqlite_forensic_engine.sqlite`.
    """

    def __init__(self) -> None:
        self.mmkv_decoder = MMKVDecoder()
        self.leveldb_decoder = LevelDBDecoder()
        self.segb_decoder = SEGBDecoder()

    def process_mmkv_file(
        self,
        file_path: Path | str,
        vfs_file_id: int = 0,
        canonical_path: str = "",
        app_instance_id: Optional[int] = None,
    ) -> Tuple[KVStoreDiagnostics, List[KVRecoveredRecord]]:
        """
        Decodes an MMKV file and produces diagnostic profile and recovered records.
        """
        p = Path(file_path)
        records = self.mmkv_decoder.decode_mmkv_file(p)

        active_count = sum(
            1 for r in records if r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD
        )
        historical_count = sum(
            1 for r in records if r.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD
        )
        residual_count = sum(
            1 for r in records if r.recovery_classification in (
                ResidualConfidence.RESIDUAL_RECORD,
                ResidualConfidence.PARTIAL_RECORD,
            )
        )

        diag = KVStoreDiagnostics(
            vfs_file_id=vfs_file_id,
            canonical_path=canonical_path or str(p),
            engine_format=EngineFormat.TENCENT_MMKV.value,
            is_encrypted=0,
            active_records_count=active_count,
            historical_superseded_count=historical_count,
            residual_deleted_count=residual_count,
            app_instance_id=app_instance_id,
        )
        return diag, records

    def process_leveldb_dir(
        self,
        dir_path: Path | str,
        vfs_file_id: int = 0,
        canonical_path: str = "",
        app_instance_id: Optional[int] = None,
    ) -> Tuple[KVStoreDiagnostics, List[KVRecoveredRecord]]:
        """
        Decodes a LevelDB / IndexedDB directory and produces diagnostic profile and recovered records.
        """
        p = Path(dir_path)
        records = self.leveldb_decoder.decode_leveldb_directory(p)

        active_count = sum(
            1 for r in records if r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD
        )
        historical_count = sum(
            1 for r in records if r.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD
        )
        residual_count = sum(
            1 for r in records if r.recovery_classification in (
                ResidualConfidence.RESIDUAL_RECORD,
                ResidualConfidence.PARTIAL_RECORD,
            )
        )

        diag = KVStoreDiagnostics(
            vfs_file_id=vfs_file_id,
            canonical_path=canonical_path or str(p),
            engine_format=EngineFormat.GOOGLE_LEVELDB.value,
            is_encrypted=0,
            active_records_count=active_count,
            historical_superseded_count=historical_count,
            residual_deleted_count=residual_count,
            app_instance_id=app_instance_id,
        )
        return diag, records

    def process_segb_file(
        self,
        file_path: Path | str,
        vfs_file_id: int = 0,
        canonical_path: str = "",
        stream_name: str = "Unknown",
        app_instance_id: Optional[int] = None,
    ) -> Tuple[KVStoreDiagnostics, List[BiomeSEGBRecord]]:
        """
        Decodes an Apple Biome SEGB segment file and produces diagnostic profile and recovered records.
        """
        p = Path(file_path)
        records = self.segb_decoder.decode_segb_file(p, stream_name=stream_name)

        active_count = sum(
            1 for r in records if r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD
        )
        residual_count = sum(
            1 for r in records if r.recovery_classification in (
                ResidualConfidence.RESIDUAL_RECORD,
                ResidualConfidence.PARTIAL_RECORD,
            )
        )

        engine_fmt = EngineFormat.APPLE_SEGB_V2.value
        if records and records[0].segb_version == SEGBVersion.SEGB_V1.value:
            engine_fmt = EngineFormat.APPLE_SEGB_V1.value

        diag = KVStoreDiagnostics(
            vfs_file_id=vfs_file_id,
            canonical_path=canonical_path or str(p),
            engine_format=engine_fmt,
            is_encrypted=0,
            active_records_count=active_count,
            historical_superseded_count=0,
            residual_deleted_count=residual_count,
            app_instance_id=app_instance_id,
        )
        return diag, records

    def export_to_ledger(
        self,
        diagnostics: List[KVStoreDiagnostics],
        kv_records: List[KVRecoveredRecord],
        segb_records: List[BiomeSEGBRecord],
        ledger_path: Path | str,
    ) -> None:
        """
        Initializes canonical non-SQLite forensic ledger schema and commits
        all diagnostic and recovered records in a unified transaction.
        """
        p = Path(ledger_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            # Enable foreign keys
            cur.execute("PRAGMA foreign_keys = ON;")

            # 1. Table: kv_store_diagnostics
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS kv_store_diagnostics (
                    kv_store_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vfs_file_id INTEGER NOT NULL,
                    app_instance_id INTEGER,
                    canonical_path TEXT NOT NULL,
                    engine_format TEXT NOT NULL,
                    is_encrypted INTEGER DEFAULT 0,
                    active_records_count INTEGER DEFAULT 0,
                    historical_superseded_count INTEGER DEFAULT 0,
                    residual_deleted_count INTEGER DEFAULT 0
                );
                """
            )

            # 2. Table: kv_recovered_records_master
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS kv_recovered_records_master (
                    kv_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    kv_store_id INTEGER NOT NULL,
                    key_name_text TEXT NOT NULL,
                    sequence_or_append_order INTEGER NOT NULL,
                    value_operation_type TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    inferred_data_type TEXT NOT NULL,
                    decoded_value_text_or_json TEXT,
                    source_file_name TEXT NOT NULL,
                    source_byte_offset INTEGER NOT NULL,
                    FOREIGN KEY (kv_store_id) REFERENCES kv_store_diagnostics(kv_store_id)
                );
                """
            )

            # 3. Table: biome_segb_records_master
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS biome_segb_records_master (
                    segb_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    kv_store_id INTEGER NOT NULL,
                    biome_stream_name TEXT NOT NULL,
                    segb_version TEXT NOT NULL,
                    device_locality TEXT NOT NULL,
                    segb_record_state INTEGER NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    segb_write_cocoa_raw REAL NOT NULL,
                    segb_write_utc_iso TEXT NOT NULL,
                    payload_event_utc_iso TEXT,
                    decoded_protobuf_json TEXT,
                    payload_byte_offset INTEGER NOT NULL,
                    FOREIGN KEY (kv_store_id) REFERENCES kv_store_diagnostics(kv_store_id)
                );
                """
            )

            # Performance indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_kv_rec_store ON kv_recovered_records_master(kv_store_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_kv_rec_key ON kv_recovered_records_master(key_name_text);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_segb_store ON biome_segb_records_master(kv_store_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_segb_stream ON biome_segb_records_master(biome_stream_name);")

            # Insert Diagnostics
            for d in diagnostics:
                if d.kv_store_id is not None:
                    cur.execute(
                        """
                        INSERT INTO kv_store_diagnostics (
                            kv_store_id, vfs_file_id, app_instance_id, canonical_path,
                            engine_format, is_encrypted, active_records_count,
                            historical_superseded_count, residual_deleted_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            d.kv_store_id,
                            d.vfs_file_id,
                            d.app_instance_id,
                            d.canonical_path,
                            _enum_val(d.engine_format),
                            d.is_encrypted,
                            d.active_records_count,
                            d.historical_superseded_count,
                            d.residual_deleted_count,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO kv_store_diagnostics (
                            vfs_file_id, app_instance_id, canonical_path,
                            engine_format, is_encrypted, active_records_count,
                            historical_superseded_count, residual_deleted_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            d.vfs_file_id,
                            d.app_instance_id,
                            d.canonical_path,
                            _enum_val(d.engine_format),
                            d.is_encrypted,
                            d.active_records_count,
                            d.historical_superseded_count,
                            d.residual_deleted_count,
                        ),
                    )
                    d.kv_store_id = cur.lastrowid

            # Insert KV Recovered Records
            for r in kv_records:
                cur.execute(
                    """
                    INSERT INTO kv_recovered_records_master (
                        kv_store_id, key_name_text, sequence_or_append_order,
                        value_operation_type, recovery_classification, inferred_data_type,
                        decoded_value_text_or_json, source_file_name, source_byte_offset
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        r.kv_store_id,
                        r.key_name_text,
                        r.sequence_or_append_order,
                        _enum_val(r.value_operation_type),
                        _enum_val(r.recovery_classification),
                        _enum_val(r.inferred_data_type),
                        r.decoded_value_text_or_json,
                        r.source_file_name,
                        r.source_byte_offset,
                    ),
                )
                r.kv_record_uid = cur.lastrowid

            # Insert Biome SEGB Records
            for s in segb_records:
                cur.execute(
                    """
                    INSERT INTO biome_segb_records_master (
                        kv_store_id, biome_stream_name, segb_version,
                        device_locality, segb_record_state, recovery_classification,
                        segb_write_cocoa_raw, segb_write_utc_iso, payload_event_utc_iso,
                        decoded_protobuf_json, payload_byte_offset
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        s.kv_store_id,
                        s.biome_stream_name,
                        _enum_val(s.segb_version),
                        s.device_locality,
                        s.segb_record_state,
                        _enum_val(s.recovery_classification),
                        s.segb_write_cocoa_raw,
                        s.segb_write_utc_iso,
                        s.payload_event_utc_iso,
                        s.decoded_protobuf_json,
                        s.payload_byte_offset,
                    ),
                )
                s.segb_record_uid = cur.lastrowid

            con.commit()
        finally:
            con.close()
