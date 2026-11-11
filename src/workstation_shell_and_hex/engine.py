"""
Workstation Shell & UI State Persistence Engine (Sub-Engine 9.1B & Section 7).
Manages examiner bookmarks, relied-upon tags, and Case Command Center summaries in workstation_ui_state.sqlite.
"""

from datetime import datetime, timezone
import os
import sqlite3
from typing import Any, Optional

from src.core.sqlite_manager import connect_forensic_sqlite
from src.workstation_shell_and_hex.models import (
    ExaminerBookmarkRecord,
    TagCategoryBadge,
    TimezoneDisplayMode,
)


class WorkstationShellEngine:
    """Coordinates UI state persistence, bookmarks ledger, and Case Command Center aggregation."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS examiner_bookmarks_and_tags_ledger (
        bookmark_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        target_domain_table TEXT NOT NULL,
        target_record_uid INTEGER NOT NULL,
        source_vfs_file_id INTEGER NOT NULL,
        physical_byte_offset INTEGER,
        tag_category_badge TEXT NOT NULL,
        is_relied_upon_for_sec230_bnss INTEGER DEFAULT 1,
        examiner_narrative_note TEXT,
        created_by_examiner TEXT NOT NULL,
        created_at_ist_iso TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bookmarks_domain_record
        ON examiner_bookmarks_and_tags_ledger(target_domain_table, target_record_uid);

    CREATE INDEX IF NOT EXISTS idx_bookmarks_relied_upon
        ON examiner_bookmarks_and_tags_ledger(is_relied_upon_for_sec230_bnss);
    """

    def initialize_ui_state_db(self, db_path: str) -> None:
        """Creates the workstation_ui_state.sqlite database schema if not present."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = connect_forensic_sqlite(db_path)
        try:
            conn.executescript(self.SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def add_bookmark(self, db_path: str, bookmark: ExaminerBookmarkRecord) -> int:
        """Inserts an examiner bookmark and tag record, returning the allocated bookmark_uid."""
        conn = connect_forensic_sqlite(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO examiner_bookmarks_and_tags_ledger (
                    target_domain_table,
                    target_record_uid,
                    source_vfs_file_id,
                    physical_byte_offset,
                    tag_category_badge,
                    is_relied_upon_for_sec230_bnss,
                    examiner_narrative_note,
                    created_by_examiner,
                    created_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    bookmark.target_domain_table,
                    bookmark.target_record_uid,
                    bookmark.source_vfs_file_id,
                    bookmark.physical_byte_offset,
                    bookmark.tag_category_badge.value
                    if isinstance(bookmark.tag_category_badge, TagCategoryBadge)
                    else str(bookmark.tag_category_badge),
                    bookmark.is_relied_upon_for_sec230_bnss,
                    bookmark.examiner_narrative_note,
                    bookmark.created_by_examiner,
                    bookmark.created_at_ist_iso,
                ),
            )
            conn.commit()
            return cur.lastrowid or 0
        finally:
            conn.close()

    def get_bookmarks(
        self, db_path: str, domain_table: Optional[str] = None
    ) -> list[ExaminerBookmarkRecord]:
        """Queries examiner bookmarks with optional filtering by target domain table."""
        conn = connect_forensic_sqlite(db_path)
        try:
            cur = conn.cursor()
            if domain_table:
                cur.execute(
                    """
                    SELECT
                        bookmark_uid,
                        target_domain_table,
                        target_record_uid,
                        source_vfs_file_id,
                        physical_byte_offset,
                        tag_category_badge,
                        is_relied_upon_for_sec230_bnss,
                        examiner_narrative_note,
                        created_by_examiner,
                        created_at_ist_iso
                    FROM examiner_bookmarks_and_tags_ledger
                    WHERE target_domain_table = ?
                    ORDER BY bookmark_uid ASC;
                    """,
                    (domain_table,),
                )
            else:
                cur.execute(
                    """
                    SELECT
                        bookmark_uid,
                        target_domain_table,
                        target_record_uid,
                        source_vfs_file_id,
                        physical_byte_offset,
                        tag_category_badge,
                        is_relied_upon_for_sec230_bnss,
                        examiner_narrative_note,
                        created_by_examiner,
                        created_at_ist_iso
                    FROM examiner_bookmarks_and_tags_ledger
                    ORDER BY bookmark_uid ASC;
                    """
                )

            records: list[ExaminerBookmarkRecord] = []
            for row in cur.fetchall():
                records.append(
                    ExaminerBookmarkRecord(
                        bookmark_uid=row[0],
                        target_domain_table=row[1],
                        target_record_uid=row[2],
                        source_vfs_file_id=row[3],
                        physical_byte_offset=row[4],
                        tag_category_badge=TagCategoryBadge(row[5]),
                        is_relied_upon_for_sec230_bnss=row[6],
                        examiner_narrative_note=row[7],
                        created_by_examiner=row[8],
                        created_at_ist_iso=row[9],
                    )
                )
            return records
        finally:
            conn.close()

    def remove_bookmark(self, db_path: str, bookmark_uid: int) -> bool:
        """Deletes a bookmark record by primary key."""
        conn = connect_forensic_sqlite(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM examiner_bookmarks_and_tags_ledger WHERE bookmark_uid = ?;",
                (bookmark_uid,),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def get_relied_upon_records(self, db_path: str) -> list[ExaminerBookmarkRecord]:
        """Fetches all records marked as relied-upon for Section 230 BNSS disclosure."""
        conn = connect_forensic_sqlite(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    bookmark_uid,
                    target_domain_table,
                    target_record_uid,
                    source_vfs_file_id,
                    physical_byte_offset,
                    tag_category_badge,
                    is_relied_upon_for_sec230_bnss,
                    examiner_narrative_note,
                    created_by_examiner,
                    created_at_ist_iso
                FROM examiner_bookmarks_and_tags_ledger
                WHERE is_relied_upon_for_sec230_bnss = 1
                ORDER BY bookmark_uid ASC;
                """
            )
            records: list[ExaminerBookmarkRecord] = []
            for row in cur.fetchall():
                records.append(
                    ExaminerBookmarkRecord(
                        bookmark_uid=row[0],
                        target_domain_table=row[1],
                        target_record_uid=row[2],
                        source_vfs_file_id=row[3],
                        physical_byte_offset=row[4],
                        tag_category_badge=TagCategoryBadge(row[5]),
                        is_relied_upon_for_sec230_bnss=row[6],
                        examiner_narrative_note=row[7],
                        created_by_examiner=row[8],
                        created_at_ist_iso=row[9],
                    )
                )
            return records
        finally:
            conn.close()

    @staticmethod
    def render_dual_timezone(
        utc_ts_ns: int,
        mode: TimezoneDisplayMode = TimezoneDisplayMode.DUAL_IST_AND_UTC,
        device_tz_offset_hours: float = 5.5,
    ) -> str:
        """Renders formatted timestamps according to the active timezone display mode."""
        utc_seconds = utc_ts_ns / 1_000_000_000.0
        utc_dt = datetime.fromtimestamp(utc_seconds, tz=timezone.utc)
        utc_str = utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        ist_seconds = utc_seconds + 19800.0  # +05:30
        ist_dt = datetime.fromtimestamp(ist_seconds, tz=timezone.utc)
        ist_str = ist_dt.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        if mode == TimezoneDisplayMode.IST_PRIMARY_ONLY:
            return ist_str
        elif mode == TimezoneDisplayMode.UTC_PRIMARY_WITH_DEVICE_RECORDED_TZ:
            dev_seconds = utc_seconds + (device_tz_offset_hours * 3600.0)
            dev_dt = datetime.fromtimestamp(dev_seconds, tz=timezone.utc)
            sign = "+" if device_tz_offset_hours >= 0 else "-"
            hours = int(abs(device_tz_offset_hours))
            mins = int((abs(device_tz_offset_hours) - hours) * 60)
            dev_str = dev_dt.strftime(f"%Y-%m-%d %H:%M:%S [UTC{sign}{hours:02d}:{mins:02d}]")
            return f"{utc_str} | Device TZ: {dev_str}"

        # Default DUAL_IST_AND_UTC
        return f"{ist_str}\n{utc_str}"

    def build_case_command_center_summary(
        self,
        case_id: str,
        device_passport: dict[str, Any],
        pipeline_dag: dict[str, Any],
        golden_hour_alerts: list[dict[str, Any]],
        zero_omission_donut: dict[str, Any],
    ) -> dict[str, Any]:
        """Constructs the unified 4-Quadrant executive cockpit payload for the Case Command Center."""
        return {
            "case_id": case_id,
            "quadrant_1_device_passport": device_passport,
            "quadrant_2_pipeline_dag_and_immutability": pipeline_dag,
            "quadrant_3_golden_hour_crime_alerts": golden_hour_alerts,
            "quadrant_4_zero_omission_accounting": zero_omission_donut,
            "server_timestamp_ist": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S IST (+05:30)"
            ),
        }
