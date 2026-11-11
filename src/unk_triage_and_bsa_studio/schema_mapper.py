"""
Interactive Zero-Code SQLite & Protobuf Schema Mapper (Sub-Engine 9.5A & Section 7).
Promotes custom UNK tables into the live case and records promotion audit entries in SQLite.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any

from src.unk_triage_and_bsa_studio.models import (
    PromotedSchemaRecord,
    SemanticColumnRole,
)


class ZeroCodeSchemaMapper:
    """Manages semantic role assignment and zero-code table promotion into the live case."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS unk_promoted_custom_schemas_ledger (
        mapping_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        vfs_file_id INTEGER NOT NULL,
        source_table_or_key_path TEXT NOT NULL,
        column_role_mappings_json TEXT NOT NULL,
        promoted_rows_count INTEGER NOT NULL,
        promoted_by_examiner TEXT NOT NULL,
        promoted_at_ist_iso TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_promoted_vfs
        ON unk_promoted_custom_schemas_ledger(vfs_file_id);
    """

    def initialize_triage_db(self, db_path: str) -> None:
        """Initializes unk_promoted_custom_schemas_ledger table in SQLite."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(self.SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def promote_table_to_case(
        self,
        db_path: str,
        vfs_file_id: int,
        table_name: str,
        column_roles: dict[str, SemanticColumnRole],
        raw_rows: list[dict[str, Any]],
        examiner_name: str = "Examiner",
    ) -> PromotedSchemaRecord:
        """Promotes rows from an unrecognized table into the case and records an audit entry."""
        now_dt = datetime.now(timezone.utc)
        ist_ts = now_dt.timestamp() + 19800.0  # +05:30
        ist_dt = datetime.fromtimestamp(ist_ts, tz=timezone.utc)
        ist_str = ist_dt.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")

        # Convert roles dictionary to serializable strings
        roles_serialized = {
            col: (role.value if isinstance(role, SemanticColumnRole) else str(role))
            for col, role in column_roles.items()
        }
        roles_json = json.dumps(roles_serialized)

        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO unk_promoted_custom_schemas_ledger (
                    vfs_file_id,
                    source_table_or_key_path,
                    column_role_mappings_json,
                    promoted_rows_count,
                    promoted_by_examiner,
                    promoted_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    vfs_file_id,
                    table_name,
                    roles_json,
                    len(raw_rows),
                    examiner_name,
                    ist_str,
                ),
            )
            conn.commit()
            allocated_uid = cur.lastrowid or 0

            return PromotedSchemaRecord(
                vfs_file_id=vfs_file_id,
                table_name=table_name,
                promoted_rows_count=len(raw_rows),
                column_roles_json=roles_json,
                promoted_by_examiner=examiner_name,
                promoted_at_ist_iso=ist_str,
                mapping_uid=allocated_uid,
            )
        finally:
            conn.close()
