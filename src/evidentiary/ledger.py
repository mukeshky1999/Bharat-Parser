"""
Tripartite Ledger Database and 18-Group Rollup Engine.
Phase 1, Module 1.4, Section 5.
"""

import sqlite3
from pathlib import Path
from typing import Optional, Union, List, Dict, Any

from src.core.sqlite_manager import connect_forensic_sqlite
from src.evidentiary.models import EvidentiaryAuditEntry


FORENSIC_GROUP_TITLES: Dict[int, str] = {
    1: "Group 01 — Ingestion & Ownership",
    2: "Group 02 — UPI & Digital Wallets",
    3: "Group 03 — Domestic & Corporate Banking",
    4: "Group 04 — Financial SMS & Notifications",
    5: "Group 05 — Crypto Self-Custody Wallets",
    6: "Group 06 — Crypto Exchanges & Seeds",
    7: "Group 07 — Mainstream & Modded Chats",
    8: "Group 08 — High-OpSec & Criminal Chats",
    9: "Group 09 — Cross-Border VoIP, Regional & Covert Chats",
    10: "Group 10 — Call Logs & Contacts",
    11: "Group 11 — WebView & Browser Sandboxes",
    12: "Group 12 — OS Geolocation & Timeline",
    13: "Group 13 — Hyper-Local Delivery, Ride & Travel",
    14: "Group 14 — Network, Wi-Fi, Bluetooth & Data Usage",
    15: "Group 15 — OS Behavioral Telemetry",
    16: "Group 16 — Security, Keychain & Tamper Detection",
    17: "Group 17 — Media, C2PA & Visual Residuals",
    18: "Group 18 — Documents, Sideloaded APKs & OCR Index",
}


class TripartiteLedgerDatabase:
    """Manages the master 5D evidentiary audit trail, UNK sweep register, and tripartite rollups."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return connect_forensic_sqlite(self.db_path)

    def _init_db(self) -> None:
        """Creates the 3 core evidentiary tracking tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_forensic_sqlite(self.db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA temp_store = MEMORY;")

        # Table 1: evidentiary_audit_trail
        cur.execute("""
            CREATE TABLE IF NOT EXISTS evidentiary_audit_trail (
                audit_entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_code TEXT NOT NULL,
                forensic_group_num INTEGER NOT NULL,
                forensic_group_name TEXT NOT NULL,
                app_instance_id INTEGER,
                vfs_file_id INTEGER,
                expected_canonical_path TEXT NOT NULL,
                tripartite_stored_state TEXT NOT NULL,
                dim_a_presence TEXT NOT NULL,
                dim_b_accessibility TEXT NOT NULL,
                dim_c_integrity TEXT NOT NULL,
                dim_d_coverage TEXT NOT NULL,
                dim_e_maturity TEXT NOT NULL,
                parser_module_name TEXT,
                active_records_parsed INTEGER DEFAULT 0,
                residual_records_parsed INTEGER DEFAULT 0,
                diagnostic_notes TEXT
            );
        """)

        # Table 2: unclassified_artifacts_register
        cur.execute("""
            CREATE TABLE IF NOT EXISTS unclassified_artifacts_register (
                unk_id TEXT PRIMARY KEY,
                vfs_file_id INTEGER NOT NULL,
                app_instance_id INTEGER,
                canonical_path TEXT NOT NULL,
                detected_storage_format TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                sqlite_table_summary_json TEXT,
                inferred_forensic_group INTEGER,
                examiner_review_status TEXT DEFAULT 'PENDING_REVIEW'
            );
        """)

        # Table 3: tripartite_case_summary
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tripartite_case_summary (
                group_number INTEGER PRIMARY KEY,
                group_title TEXT NOT NULL,
                stored_targets_expected INTEGER NOT NULL,
                acquired_targets_present INTEGER NOT NULL,
                gated_or_excluded_count INTEGER NOT NULL,
                interpreted_targets_count INTEGER NOT NULL,
                total_active_artifacts INTEGER NOT NULL,
                total_residual_artifacts INTEGER NOT NULL
            );
        """)

        conn.commit()
        conn.close()

    def record_audit_entry(self, entry: EvidentiaryAuditEntry) -> int:
        """Inserts an evaluated artifact entry into the master audit trail."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO evidentiary_audit_trail (
                artifact_code, forensic_group_num, forensic_group_name,
                app_instance_id, vfs_file_id, expected_canonical_path,
                tripartite_stored_state, dim_a_presence, dim_b_accessibility,
                dim_c_integrity, dim_d_coverage, dim_e_maturity,
                parser_module_name, active_records_parsed, residual_records_parsed,
                diagnostic_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            entry.artifact_code,
            entry.forensic_group_num,
            entry.forensic_group_name,
            entry.app_instance_id,
            entry.vfs_file_id,
            entry.expected_canonical_path,
            entry.tripartite_stored_state.value,
            entry.dim_a_presence.value,
            entry.dim_b_accessibility.value,
            entry.dim_c_integrity.value,
            entry.dim_d_coverage.value,
            entry.dim_e_maturity.value,
            entry.parser_module_name,
            entry.active_records_parsed,
            entry.residual_records_parsed,
            entry.diagnostic_notes
        ))
        row_id = cur.lastrowid
        conn.commit()
        conn.close()
        if row_id is None:
            raise RuntimeError("Failed to insert evidentiary audit entry")
        return row_id

    def get_audit_entries(self) -> List[Dict[str, Any]]:
        """Retrieves all rows in evidentiary_audit_trail."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM evidentiary_audit_trail ORDER BY audit_entry_id ASC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def record_unclassified_artifact(
        self,
        unk_id: str,
        vfs_file_id: int,
        canonical_path: str,
        detected_storage_format: str,
        file_size_bytes: int,
        sqlite_table_summary_json: Optional[str] = None,
        app_instance_id: Optional[int] = None,
        inferred_forensic_group: Optional[int] = None,
        examiner_review_status: str = "PENDING_REVIEW"
    ) -> str:
        """Inserts an unparsed database or container into the UNK register."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO unclassified_artifacts_register (
                unk_id, vfs_file_id, app_instance_id, canonical_path,
                detected_storage_format, file_size_bytes, sqlite_table_summary_json,
                inferred_forensic_group, examiner_review_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            unk_id, vfs_file_id, app_instance_id, canonical_path,
            detected_storage_format, file_size_bytes, sqlite_table_summary_json,
            inferred_forensic_group, examiner_review_status
        ))
        conn.commit()
        conn.close()
        return unk_id

    def get_unclassified_artifacts(self) -> List[Dict[str, Any]]:
        """Retrieves all UNK/PHY records for examiner triage."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM unclassified_artifacts_register ORDER BY unk_id ASC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def generate_tripartite_rollup(self) -> List[Dict[str, Any]]:
        """
        Computes executive and courtroom statistics across all 18 Canonical Forensic Groups.
        """
        conn = self._get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                forensic_group_num,
                COUNT(*) as stored_expected,
                SUM(CASE WHEN dim_a_presence IN ('PRESENT', 'PRESENT_EMPTY_STUB') THEN 1 ELSE 0 END) as acquired_present,
                SUM(CASE
                    WHEN dim_a_presence IN ('SOURCE_PRESENT_NOT_ACQUIRED_TIER', 'SOURCE_PRESENT_NOT_ACQUIRED_BFU', 'SOURCE_PRESENT_NOT_ACQUIRED_LUN')
                      OR dim_b_accessibility IN ('ENCRYPTED_GATED_BY_HARDWARE', 'ENCRYPTED_GATED_MISSING_KEY')
                    THEN 1 ELSE 0 END) as gated_excluded,
                SUM(CASE
                    WHEN dim_b_accessibility IN ('READABLE', 'READABLE_DECRYPTED')
                     AND dim_d_coverage IN ('DIRECTLY_PARSED_FULL', 'PARSED_WITH_SUPPLIED_KEYS')
                    THEN 1 ELSE 0 END) as interpreted_count,
                SUM(active_records_parsed) as total_active,
                SUM(residual_records_parsed) as total_residual
            FROM evidentiary_audit_trail
            GROUP BY forensic_group_num;
        """)

        group_stats = {row["forensic_group_num"]: dict(row) for row in cur.fetchall()}

        summary_rows: List[Dict[str, Any]] = []
        for g_num in range(1, 19):
            title = FORENSIC_GROUP_TITLES.get(g_num, f"Group {g_num:02d}")
            stats = group_stats.get(g_num, {})
            stored = stats.get("stored_expected", 0)
            acquired = stats.get("acquired_present", 0)
            gated = stats.get("gated_excluded", 0)
            interpreted = stats.get("interpreted_count", 0)
            active = stats.get("total_active", 0)
            residual = stats.get("total_residual", 0)

            cur.execute("""
                INSERT OR REPLACE INTO tripartite_case_summary (
                    group_number, group_title, stored_targets_expected,
                    acquired_targets_present, gated_or_excluded_count,
                    interpreted_targets_count, total_active_artifacts,
                    total_residual_artifacts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (g_num, title, stored, acquired, gated, interpreted, active, residual))

            summary_rows.append({
                "group_number": g_num,
                "group_title": title,
                "stored_targets_expected": stored,
                "acquired_targets_present": acquired,
                "gated_or_excluded_count": gated,
                "interpreted_targets_count": interpreted,
                "total_active_artifacts": active,
                "total_residual_artifacts": residual
            })

        conn.commit()
        conn.close()
        return summary_rows

    def get_tripartite_case_summary(self) -> List[Dict[str, Any]]:
        """Retrieves the rollup summary across all 18 groups."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM tripartite_case_summary ORDER BY group_number ASC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
