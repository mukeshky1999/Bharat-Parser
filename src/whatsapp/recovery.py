"""
Sub-Engine 5.1D: Revoked/Edited Message Recovery Engine & Rolling Backup Diff-Merger.
Reconstructs 'Delete for Everyone' revoked messages from surviving quoted replies,
modded APK anti-revoke tables, and historical rolling .crypt14/.crypt15 backups.
Complies with Section 6 of Phase 5 Module 5.1 Specification.
"""

import logging
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

from src.core.enums import (
    ResidualConfidence,
)
from src.whatsapp.models import (
    MessageTypeCategory,
    WhatsAppMessageRecord,
)
from src.whatsapp.decoder import WhatsAppDatabaseDecoder
from src.crypto.whatsapp import decrypt_crypt15_backup


def reconstruct_revoked_messages(
    messages: List[WhatsAppMessageRecord],
    msgstore_path: Optional[str] = None,
) -> List[WhatsAppMessageRecord]:
    """
    Executes 4-source recovery search for 'Delete for Everyone' revoked messages:
    1. Surviving quote replies in message_quoted
    2. Modded APK anti-revoke tables (revoked_messages)
    """
    # 1. Build map of surviving quotes from in-memory messages
    quoted_by_key: Dict[str, str] = {}
    for m in messages:
        if m.quoted_parent_key_id and m.quoted_parent_text_preview:
            quoted_by_key[m.quoted_parent_key_id] = m.quoted_parent_text_preview

    # 2. Check msgstore.db database tables if available
    db_quotes: Dict[str, str] = {}
    mod_revoked: Dict[str, str] = {}
    if msgstore_path and os.path.exists(msgstore_path):
        try:
            conn = sqlite3.connect(msgstore_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cur.fetchall()}

            if "message_quoted" in tables:
                cur.execute("SELECT key_id, text_data FROM message_quoted WHERE text_data IS NOT NULL")
                for q_key, q_text in cur.fetchall():
                    if q_key and q_text:
                        db_quotes[q_key] = q_text

            # Modded APK anti-revoke tables
            for mod_table in ("revoked_messages", "del_msgs", "gb_revoked"):
                if mod_table in tables:
                    cur.execute(f"SELECT key_id, text_data FROM {mod_table} WHERE text_data IS NOT NULL")
                    for r_key, r_text in cur.fetchall():
                        if r_key and r_text:
                            mod_revoked[r_key] = r_text
            conn.close()
        except Exception as exc:
            logger.debug("Failed querying revoked tables: %s", exc)

    # 3. Reconstruct revoked messages
    reconstructed: List[WhatsAppMessageRecord] = []
    for m in messages:
        if m.is_revoked_deleted_for_everyone == 1 or m.message_type_category == MessageTypeCategory.REVOKED_DELETED_FOR_EVERYONE:
            # Check surviving quote in DB
            recovered_text = db_quotes.get(m.message_key_id) or quoted_by_key.get(m.message_key_id)
            if recovered_text:
                m.recovered_pre_revoke_or_edit_text = recovered_text
                m.recovery_classification = ResidualConfidence.RECONSTRUCTED_RECORD
                m.recovery_source_detail = "QUOTED_REPLY_SURVIVOR"
            elif m.message_key_id in mod_revoked:
                m.recovered_pre_revoke_or_edit_text = mod_revoked[m.message_key_id]
                m.recovery_classification = ResidualConfidence.HISTORICAL_COMMITTED_RECORD
                m.recovery_source_detail = "MODDED_APK_ANTI_REVOKE"

        reconstructed.append(m)

    return reconstructed


def merge_historical_crypt15_backup(
    live_messages: List[WhatsAppMessageRecord],
    crypt15_path: str,
    root_key_32: bytes,
    app_instance_id: int = 1,
    source_vfs_file_id: int = 0,
) -> List[WhatsAppMessageRecord]:
    """
    Decrypts a WhatsApp .crypt15 backup file via Module 2.2 and merges
    missing historical messages into the master ledger.
    """
    if not os.path.exists(crypt15_path):
        return list(live_messages)

    tmp_dir = Path("./.workspace_tmp/crypt15_decrypt_staging")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    temp_decrypted_db = tmp_dir / f"decrypted_{Path(crypt15_path).stem}.db"

    success = decrypt_crypt15_backup(
        crypt15_path=crypt15_path,
        output_db_path=temp_decrypted_db,
        root_key_32=root_key_32,
    )
    if not success or not temp_decrypted_db.exists():
        return list(live_messages)

    try:
        decoder = WhatsAppDatabaseDecoder()
        backup_messages = decoder.extract_messages(
            msgstore_path=str(temp_decrypted_db),
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
        )

        live_keys: Set[str] = {m.message_key_id for m in live_messages}
        merged: List[WhatsAppMessageRecord] = list(live_messages)

        for b_msg in backup_messages:
            if b_msg.message_key_id not in live_keys:
                b_msg.recovery_classification = ResidualConfidence.HISTORICAL_COMMITTED_RECORD
                b_msg.recovery_source_detail = "CRYPT15_ROLLING_BACKUP_DIFF"
                b_msg.app_instance_id = app_instance_id
                b_msg.source_vfs_file_id = source_vfs_file_id
                merged.append(b_msg)
                live_keys.add(b_msg.message_key_id)

        return merged
    finally:
        if temp_decrypted_db.exists():
            temp_decrypted_db.unlink(missing_ok=True)
