"""
Sub-Engine 6.5B & 6.5C: Mathematical Clock-Tampering ("Time-Travel"),
Monotonic ROWID Inversion, sqlite_sequence Tail-Deletion Gaps & Device Migration Classifier.
Complies with Sections 4 & 5 of Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

from src.core.sqlite_uri import ro_uri
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.antiforensics.models import (
    TamperCategory,
    ClockTamperGapRecord,
)


def _ts_to_iso(ts_seconds: float) -> str:
    """Converts unix timestamp in seconds to UTC ISO-8601 string."""
    dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ClockTamperGapDetector:
    """Detects monotonic ROWID regressions, clock rollbacks, and sqlite_sequence deletion gaps."""

    def audit_sqlite_database(
        self,
        db_path: str,
        table_name: str,
        rowid_col: str,
        date_col: str,
        source_vfs_file_id: int,
    ) -> List[ClockTamperGapRecord]:
        """
        Scans an active SQLite database table for monotonic ROWID vs wall-clock regressions
        and checks sqlite_sequence for evidence of deleted tail rows.
        """
        records: List[ClockTamperGapRecord] = []
        if not os.path.exists(db_path):
            return records

        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()

        # 1. Fetch rows ordered by ROWID ascending
        try:
            query = f"SELECT {rowid_col}, {date_col} FROM {table_name} ORDER BY {rowid_col} ASC"
            cur.execute(query)
            rows = cur.fetchall()

            parsed_rows: List[Tuple[int, float]] = []
            for r in rows:
                row_id = int(r[0])
                raw_ts = float(r[1])
                # Convert milliseconds to seconds if epoch > 1e11
                ts_sec = raw_ts / 1000.0 if raw_ts > 1e11 else raw_ts
                parsed_rows.append((row_id, ts_sec))

            # Scan for clock rollback / inversion
            n = len(parsed_rows)
            for i in range(1, n):
                prev_id, prev_ts = parsed_rows[i - 1]
                curr_id, curr_ts = parsed_rows[i]

                # Condition: ROWID strictly monotonic, but timestamp jumps backward by > 300s (5 minutes)
                delta_s = curr_ts - prev_ts
                if curr_id > prev_id and delta_s < -300.0:
                    # Find upper bracket
                    next_normal_ts = prev_ts
                    for j in range(i + 1, n):
                        if parsed_rows[j][1] >= prev_ts:
                            next_normal_ts = parsed_rows[j][1]
                            break

                    bracket_earliest = _ts_to_iso(prev_ts)
                    bracket_latest = _ts_to_iso(next_normal_ts)
                    claimed_iso = _ts_to_iso(curr_ts)
                    delta_hours = abs(delta_s) / 3600.0

                    detail = (
                        f"ROWID {curr_id} > ROWID {prev_id}, but timestamp jumped backward by "
                        f"-{delta_hours:.1f} hours ({abs(delta_s):.0f}s)"
                    )
                    explanation = (
                        f"Suspect rolled device clock backward to backdate row {curr_id}. "
                        f"The true creation time is mathematically bounded within [{bracket_earliest}, {bracket_latest}]."
                    )

                    records.append(
                        ClockTamperGapRecord(
                            tamper_category=TamperCategory.CLOCK_ROLLBACK_ROWID_INVERSION,
                            severity_level="CRITICAL",
                            affected_app_or_database=f"{Path(db_path).name} ({table_name})",
                            source_vfs_file_id=source_vfs_file_id,
                            monotonic_anchor_detail=detail,
                            claimed_wallclock_utc_iso=claimed_iso,
                            true_bracketed_window_utc=f"[{bracket_earliest}, {bracket_latest}]",
                            courtroom_explanation_note=explanation,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance=f"{Path(db_path).name}:{table_name}:{rowid_col}={curr_id}",
                            dim_corroboration=1.0,
                        )
                    )
        except sqlite3.OperationalError as _err:
            records.extend([])

        # 2. Check sqlite_sequence for tail row deletions
        try:
            cur.execute("SELECT MAX(seq) FROM sqlite_sequence WHERE name = ?", (table_name,))
            seq_row = cur.fetchone()
            if seq_row is not None and seq_row[0] is not None:
                max_seq = int(seq_row[0])
                cur.execute(f"SELECT MAX({rowid_col}) FROM {table_name}")
                max_rowid_res = cur.fetchone()
                current_max_rowid = int(max_rowid_res[0]) if max_rowid_res and max_rowid_res[0] is not None else 0

                tail_deleted = max_seq - current_max_rowid
                if tail_deleted > 0:
                    detail = (
                        f"sqlite_sequence.seq ({max_seq}) > MAX({rowid_col}) ({current_max_rowid}): "
                        f"{tail_deleted} tail rows deleted"
                    )
                    explanation = (
                        f"Forensic tail-gap analysis proves {tail_deleted} consecutive records at the end "
                        f"of {table_name} were deleted prior to acquisition. SQLite autoincrement sequence counter was not reset."
                    )
                    records.append(
                        ClockTamperGapRecord(
                            tamper_category=TamperCategory.SQLITE_SEQUENCE_TAIL_DELETION_GAP,
                            severity_level="HIGH",
                            affected_app_or_database=f"{Path(db_path).name} ({table_name})",
                            source_vfs_file_id=source_vfs_file_id,
                            monotonic_anchor_detail=detail,
                            claimed_wallclock_utc_iso=None,
                            true_bracketed_window_utc=None,
                            courtroom_explanation_note=explanation,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance=f"{Path(db_path).name}:sqlite_sequence:table={table_name}",
                            dim_corroboration=1.0,
                        )
                    )
        except sqlite3.OperationalError as _err:
            records.extend([])

        conn.close()
        return records

    def audit_timesync_jump(
        self,
        timesync_records: List[Dict[str, Any]],
        source_vfs_file_id: int,
    ) -> List[ClockTamperGapRecord]:
        """
        Audits iOS .timesync logs for backward or discontinuous wall-clock shifts
        while kernel ticks progress monotonically.
        """
        records: List[ClockTamperGapRecord] = []
        for i in range(1, len(timesync_records)):
            prev = timesync_records[i - 1]
            curr = timesync_records[i]

            prev_tick = prev.get("kernel_anchor_tick", 0)
            curr_tick = curr.get("kernel_anchor_tick", 0)
            prev_wall = prev.get("wallclock_anchor_utc_ns", 0)
            curr_wall = curr.get("wallclock_anchor_utc_ns", 0)

            if curr_tick > prev_tick:
                wall_delta_sec = (curr_wall - prev_wall) / 1e9
                if wall_delta_sec < -60.0:
                    detail = (
                        f"Kernel ticks monotonically increased (delta={curr_tick - prev_tick}), "
                        f"but wallclock jumped backward by {abs(wall_delta_sec):.2f}s"
                    )
                    records.append(
                        ClockTamperGapRecord(
                            tamper_category=TamperCategory.TIMESYNC_KERNEL_WALLCLOCK_JUMP,
                            severity_level="CRITICAL",
                            affected_app_or_database="kernel_timesync",
                            source_vfs_file_id=source_vfs_file_id,
                            monotonic_anchor_detail=detail,
                            claimed_wallclock_utc_iso=_ts_to_iso(curr_wall / 1e9),
                            true_bracketed_window_utc=None,
                            courtroom_explanation_note="Direct kernel-level proof of manual clock manipulation while device was active.",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance="timesync_trace",
                            dim_corroboration=1.0,
                        )
                    )
        return records

    def audit_bulk_migration_vs_timestomp(
        self,
        files: List[Dict[str, Any]],
        source_vfs_file_id: int,
    ) -> List[ClockTamperGapRecord]:
        """
        Classifies file timestamp discrepancies between bulk device migrations (Apple Quick Start,
        Smart Switch, Google Restore) vs surgical individual file backdating (timestomp).
        """
        records: List[ClockTamperGapRecord] = []
        discrepant_files = []
        for f in files:
            btime = f.get("btime", 0.0)
            mtime = f.get("mtime", 0.0)
            if btime > (mtime + 86400.0):
                discrepant_files.append(f)

        if len(discrepant_files) >= 100:
            # Clustered migration
            detail = f"Identified {len(discrepant_files)} files created during device migration/restore event"
            records.append(
                ClockTamperGapRecord(
                    tamper_category=TamperCategory.BULK_BACKUP_RESTORE_MIGRATION,
                    severity_level="INFO_MIGRATION",
                    affected_app_or_database="filesystem_metadata",
                    source_vfs_file_id=source_vfs_file_id,
                    monotonic_anchor_detail=detail,
                    claimed_wallclock_utc_iso=None,
                    true_bracketed_window_utc=None,
                    courtroom_explanation_note="Legitimate phone-to-phone migration or backup restore preserved original historical mtime.",
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                    dim_existence=EvidentiaryExistence.OBSERVED,
                    dim_access=EvidentiaryAccess.PLAINTEXT,
                    dim_storage=EvidentiaryStorage.LIVE_RECORD,
                    dim_provenance="vfs_cluster_classifier",
                    dim_corroboration=1.0,
                )
            )
        elif 1 <= len(discrepant_files) < 10:
            for f in discrepant_files:
                name = f.get("name", "unknown_file")
                detail = f"Isolated file {name} has mtime significantly older than btime"
                records.append(
                    ClockTamperGapRecord(
                        tamper_category=TamperCategory.SURGICAL_FILE_TIMESTOMP,
                        severity_level="HIGH",
                        affected_app_or_database=name,
                        source_vfs_file_id=source_vfs_file_id,
                        monotonic_anchor_detail=detail,
                        claimed_wallclock_utc_iso=None,
                        true_bracketed_window_utc=None,
                        courtroom_explanation_note="Isolated surgical timestamp manipulation (timestomp) suspected on individual file.",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"file_inode:{f.get('inode', 0)}",
                        dim_corroboration=1.0,
                    )
                )

        return records
