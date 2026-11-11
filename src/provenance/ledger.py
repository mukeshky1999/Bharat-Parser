"""
Provenance Ledger Database & Courtroom Audit Engine.
Phase 1, Module 1.2, Section 6: Manages Product A, Product B, and Section 63(4)(c) BSA Chain of Custody Ledgers.
"""

import sqlite3
from pathlib import Path
from typing import Optional, Union, Dict, Any, List


class ProvenanceLedger:
    """Manages the 4 core forensic integrity and chain-of-custody tables."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Creates the 4 mandatory forensic integrity tables with WAL journal mode."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA temp_store = MEMORY;")

        # Table 1: container_integrity_ledger (Product A)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS container_integrity_ledger (
                container_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_input_path TEXT NOT NULL,
                container_type TEXT NOT NULL,
                acquisition_tier TEXT NOT NULL,
                total_size_bytes INTEGER NOT NULL,
                product_a_sha256 TEXT NOT NULL,
                product_a_md5 TEXT,
                vendor_log_path TEXT,
                vendor_expected_hash TEXT,
                verification_status TEXT NOT NULL,
                hash_started_utc TEXT NOT NULL,
                hash_completed_utc TEXT NOT NULL
            );
        """)

        # Table 2: file_provenance_catalog (File Inode & Security Metadata)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_provenance_catalog (
                vfs_file_id INTEGER PRIMARY KEY,
                canonical_path TEXT NOT NULL,
                mtime_raw TEXT,
                mtime_utc_ns INTEGER,
                mtime_utc_iso TEXT,
                btime_raw TEXT,
                btime_utc_ns INTEGER,
                btime_utc_iso TEXT,
                ctime_utc_iso TEXT,
                atime_utc_iso TEXT,
                ts_tz_provenance TEXT NOT NULL,
                posix_mode_octal TEXT,
                owner_uid INTEGER,
                owner_gid INTEGER,
                ios_protection_class TEXT,
                android_selinux_label TEXT,
                where_froms_urls_json TEXT,
                is_backup_excluded INTEGER DEFAULT 0,
                tamper_anomaly_flag TEXT
            );
        """)

        # Table 3: derivative_staging_ledger (Product B)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS derivative_staging_ledger (
                staging_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_vfs_file_id INTEGER NOT NULL,
                companion_wal_file_id INTEGER,
                staged_local_path TEXT NOT NULL,
                product_b1_raw_sha256 TEXT NOT NULL,
                companion_wal_sha256 TEXT,
                derivation_action TEXT NOT NULL,
                crypto_key_reference TEXT,
                product_b2_derived_sha256 TEXT,
                staged_utc_timestamp TEXT NOT NULL
            );
        """)

        # Table 4: chain_of_custody_audit_log (Section 63(4)(c) BSA Trail)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chain_of_custody_audit_log (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_utc_iso TEXT NOT NULL,
                software_version TEXT NOT NULL,
                workstation_hostname TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target_description TEXT NOT NULL,
                input_sha256 TEXT,
                output_sha256 TEXT
            );
        """)

        conn.commit()
        conn.close()

    def record_container_integrity(
        self,
        source_input_path: str,
        container_type: str,
        acquisition_tier: str,
        total_size_bytes: int,
        product_a_sha256: str,
        verification_status: str,
        hash_started_utc: str,
        hash_completed_utc: str,
        product_a_md5: Optional[str] = None,
        vendor_log_path: Optional[str] = None,
        vendor_expected_hash: Optional[str] = None
    ) -> int:
        """Records Product A container hashing digest and returns container_id."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO container_integrity_ledger (
                source_input_path, container_type, acquisition_tier, total_size_bytes,
                product_a_sha256, product_a_md5, vendor_log_path, vendor_expected_hash,
                verification_status, hash_started_utc, hash_completed_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            source_input_path, container_type, acquisition_tier, total_size_bytes,
            product_a_sha256, product_a_md5, vendor_log_path, vendor_expected_hash,
            verification_status, hash_started_utc, hash_completed_utc
        ))
        container_id = cur.lastrowid
        conn.commit()
        conn.close()
        if container_id is None:
            raise RuntimeError("Failed to insert container integrity record")
        return container_id

    def record_file_provenance(
        self,
        vfs_file_id: int,
        canonical_path: str,
        ts_tz_provenance: str,
        mtime_raw: Optional[str] = None,
        mtime_utc_ns: Optional[int] = None,
        mtime_utc_iso: Optional[str] = None,
        btime_raw: Optional[str] = None,
        btime_utc_ns: Optional[int] = None,
        btime_utc_iso: Optional[str] = None,
        ctime_utc_iso: Optional[str] = None,
        atime_utc_iso: Optional[str] = None,
        posix_mode_octal: Optional[str] = None,
        owner_uid: Optional[int] = None,
        owner_gid: Optional[int] = None,
        ios_protection_class: Optional[str] = None,
        android_selinux_label: Optional[str] = None,
        where_froms_urls_json: Optional[str] = None,
        is_backup_excluded: int = 0,
        tamper_anomaly_flag: Optional[str] = None
    ) -> None:
        """Inserts or replaces file inode and security metadata."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO file_provenance_catalog (
                vfs_file_id, canonical_path, mtime_raw, mtime_utc_ns, mtime_utc_iso,
                btime_raw, btime_utc_ns, btime_utc_iso, ctime_utc_iso, atime_utc_iso,
                ts_tz_provenance, posix_mode_octal, owner_uid, owner_gid,
                ios_protection_class, android_selinux_label, where_froms_urls_json,
                is_backup_excluded, tamper_anomaly_flag
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            vfs_file_id, canonical_path, mtime_raw, mtime_utc_ns, mtime_utc_iso,
            btime_raw, btime_utc_ns, btime_utc_iso, ctime_utc_iso, atime_utc_iso,
            ts_tz_provenance, posix_mode_octal, owner_uid, owner_gid,
            ios_protection_class, android_selinux_label, where_froms_urls_json,
            is_backup_excluded, tamper_anomaly_flag
        ))
        conn.commit()
        conn.close()

    def record_derivative_staging(
        self,
        source_vfs_file_id: int,
        staged_local_path: str,
        product_b1_raw_sha256: str,
        derivation_action: str,
        staged_utc_timestamp: str,
        companion_wal_file_id: Optional[int] = None,
        companion_wal_sha256: Optional[str] = None,
        crypto_key_reference: Optional[str] = None,
        product_b2_derived_sha256: Optional[str] = None
    ) -> int:
        """Records Product B staging and derivative file hashes."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO derivative_staging_ledger (
                source_vfs_file_id, companion_wal_file_id, staged_local_path,
                product_b1_raw_sha256, companion_wal_sha256, derivation_action,
                crypto_key_reference, product_b2_derived_sha256, staged_utc_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            source_vfs_file_id, companion_wal_file_id, staged_local_path,
            product_b1_raw_sha256, companion_wal_sha256, derivation_action,
            crypto_key_reference, product_b2_derived_sha256, staged_utc_timestamp
        ))
        staging_id = cur.lastrowid
        conn.commit()
        conn.close()
        if staging_id is None:
            raise RuntimeError("Failed to insert derivative staging record")
        return staging_id

    def record_chain_of_custody_event(
        self,
        event_utc_iso: str,
        software_version: str,
        workstation_hostname: str,
        action_type: str,
        target_description: str,
        input_sha256: Optional[str] = None,
        output_sha256: Optional[str] = None
    ) -> int:
        """Appends an immutable event to the courtroom audit ledger."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO chain_of_custody_audit_log (
                event_utc_iso, software_version, workstation_hostname,
                action_type, target_description, input_sha256, output_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            event_utc_iso, software_version, workstation_hostname,
            action_type, target_description, input_sha256, output_sha256
        ))
        event_id = cur.lastrowid
        conn.commit()
        conn.close()
        if event_id is None:
            raise RuntimeError("Failed to insert chain of custody event")
        return event_id

    def get_container_record(self, container_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves container record by container_id."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM container_integrity_ledger WHERE container_id = ?;", (container_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_file_provenance(self, vfs_file_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves file provenance metadata by vfs_file_id."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM file_provenance_catalog WHERE vfs_file_id = ?;", (vfs_file_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_derivative_record(self, staging_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves derivative staging record by staging_id."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM derivative_staging_ledger WHERE staging_id = ?;", (staging_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_chain_of_custody_events(self) -> List[Dict[str, Any]]:
        """Retrieves all chronological chain of custody events."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM chain_of_custody_audit_log ORDER BY event_id ASC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
