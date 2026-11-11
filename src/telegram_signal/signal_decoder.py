"""
Sub-Engine 5.2D: The Signal Messenger Deep Decoder (signal.db & Signal.sqlite).
Parses recipients, Phone Number Privacy (ACI/PNI UUIDs), message edit revision chains,
View-Once media, and disappearing message self-destruct timers.
Complies with Section 6 of Phase 5 Module 5.2 Specification.
"""

from datetime import datetime, timezone
import json
import logging
import os
import sqlite3
from typing import Dict, List, Optional, Tuple

from src.core.enums import (
    ResidualConfidence,
)
from src.telegram_signal.models import (
    PlatformFamily,
    PeerType,
    LocalRoleInGroup,
    ThreadClassification,
    MessagingPeerRecord,
    MessagingMessageRecord,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix timestamp in milliseconds to UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class SignalDatabaseDecoder:
    """Decoder for Signal Android (signal.db) and Signal iOS (Signal.sqlite)."""

    def extract_peers(
        self,
        db_path: str,
        account_slot_name: str = "signal_primary",
        app_instance_id: int = 1,
    ) -> List[MessagingPeerRecord]:
        """Extracts recipients and groups from Signal database."""
        peers: List[MessagingPeerRecord] = []
        if not os.path.exists(db_path):
            return peers

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        # CASE 1: Signal Android (recipient table)
        if "recipient" in tables:
            try:
                cur.execute(
                    "SELECT _id, e164, aci, pni, username, system_joined_name, profile_joined_name, group_id FROM recipient"
                )
                for r_id, e164, aci, pni, uname, s_name, p_name, g_id in cur.fetchall():
                    peer_type = PeerType.GROUP_CHAT if g_id else PeerType.USER_CONTACT
                    display_name = s_name or p_name
                    handle = f"@{uname}" if uname else None

                    rec = MessagingPeerRecord(
                        platform_family=PlatformFamily.SIGNAL,
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        peer_type=peer_type,
                        native_peer_id=str(r_id),
                        secondary_uuid_or_pni=aci or pni,
                        username_handle=handle,
                        phone_number_e164=e164,
                        display_or_group_name=display_name,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    peers.append(rec)
            except Exception as exc:
                logger.debug("Failed reading Signal Android recipient: %s", exc)

        # CASE 2: Signal iOS (model_SignalRecipient)
        elif "model_SignalRecipient" in tables:
            try:
                cur.execute(
                    "SELECT recipientPhoneNumber, recipientUUID, givenName, familyName FROM model_SignalRecipient"
                )
                for phone, uuid_str, g_name, f_name in cur.fetchall():
                    full_name = " ".join([n for n in (g_name, f_name) if n]) or None
                    rec = MessagingPeerRecord(
                        platform_family=PlatformFamily.SIGNAL,
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        peer_type=PeerType.USER_CONTACT,
                        native_peer_id=uuid_str or phone or "unknown",
                        secondary_uuid_or_pni=uuid_str,
                        phone_number_e164=phone,
                        display_or_group_name=full_name,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    peers.append(rec)
            except Exception as exc:
                logger.debug("Failed reading Signal iOS recipient: %s", exc)

        conn.close()
        return peers

    def extract_messages(
        self,
        db_path: str,
        account_slot_name: str = "signal_primary",
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> List[MessagingMessageRecord]:
        """Extracts messages and links edit revision histories."""
        messages: List[MessagingMessageRecord] = []
        if not os.path.exists(db_path):
            return messages

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        # -------------------------------------------------------------------
        # CASE 1: Signal Android (message table)
        # -------------------------------------------------------------------
        if "message" in tables:
            try:
                # First pass: load all raw message rows
                cur.execute("""
                    SELECT _id, thread_id, from_recipient_id, date_sent, body,
                           expires_in, expire_started, view_once, latest_revision_id,
                           original_message_id, revision_number
                    FROM message
                """)
                raw_rows = cur.fetchall()

                # Build revision mapping: latest_id -> list of earlier revisions
                revisions_map: Dict[int, List[dict]] = {}
                for row in raw_rows:
                    m_id = row[0]
                    body = row[4]
                    sent = row[3]
                    latest_id = row[8]
                    rev_num = row[10]

                    if latest_id:
                        revisions_map.setdefault(latest_id, []).append({
                            "revision_id": m_id,
                            "body": body,
                            "date_sent": sent,
                            "revision_number": rev_num,
                        })

                # Second pass: construct messages
                for row in raw_rows:
                    m_id = row[0]
                    thread_id = row[1]
                    from_id = row[2]
                    sent = row[3]
                    body = row[4]
                    expires_in = row[5] or 0
                    expire_started = row[6] or 0
                    view_once = row[7] or 0
                    latest_id = row[8]
                    orig_id = row[9]
                    rev_num = row[10] or 0

                    is_edited = 1 if (m_id in revisions_map or orig_id is not None or rev_num > 0) else 0
                    past_revs = revisions_map.get(m_id)
                    diff_json = json.dumps(past_revs) if past_revs else None

                    # Calculate disappearing timer in seconds
                    ttl_sec = int(expires_in / 1000) if expires_in > 0 else 0

                    sent_ns = sent * 1_000_000
                    sent_iso = _format_utc_iso_ms(sent)

                    rec = MessagingMessageRecord(
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        source_vfs_file_id=source_vfs_file_id,
                        thread_or_dialog_id=str(thread_id),
                        thread_classification=ThreadClassification.DIRECT_1ON1_CHAT,
                        native_message_id=str(m_id),
                        direction="INCOMING_RECEIVED",
                        sent_utc_ns=sent_ns,
                        sent_utc_iso=sent_iso,
                        sender_peer_id=str(from_id) if from_id else None,
                        message_text=body,
                        is_edited_or_past_revision=is_edited,
                        pre_edit_or_diff_json=diff_json,
                        ttl_disappearing_seconds=ttl_sec,
                        is_view_once_media=view_once,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    messages.append(rec)
            except Exception as exc:
                logger.debug("Failed reading Signal Android message: %s", exc)

        # -------------------------------------------------------------------
        # CASE 2: Signal iOS (model_TSInteraction)
        # -------------------------------------------------------------------
        elif "model_TSInteraction" in tables:
            try:
                # Check for edit revisions table
                edit_revisions_map: Dict[str, List[dict]] = {}
                if "InteractionEditRecord" in tables:
                    try:
                        cur.execute("SELECT latestRevisionId, pastRevisionId FROM InteractionEditRecord")
                        for l_id, p_id in cur.fetchall():
                            edit_revisions_map.setdefault(l_id, []).append({"pastRevisionId": p_id})
                    except Exception as exc:
                        logger.debug("Failed querying InteractionEditRecord: %s", exc)

                cur.execute("""
                    SELECT uniqueId, threadUniqueId, body, timestamp, recordType,
                           expiresInSeconds, isViewOnceMessage
                    FROM model_TSInteraction
                """)
                for uid_val, t_uid, body, ts, r_type, exp_sec, v_once in cur.fetchall():
                    is_edited = 1 if uid_val in edit_revisions_map else 0
                    diff_json = json.dumps(edit_revisions_map[uid_val]) if uid_val in edit_revisions_map else None

                    direction = "OUTGOING_SENT" if (r_type and "Outgoing" in r_type) else "INCOMING_RECEIVED"
                    sent_ns = ts * 1_000_000 if ts else 0
                    sent_iso = _format_utc_iso_ms(ts) if ts else ""

                    rec = MessagingMessageRecord(
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        source_vfs_file_id=source_vfs_file_id,
                        thread_or_dialog_id=t_uid or "",
                        thread_classification=ThreadClassification.DIRECT_1ON1_CHAT,
                        native_message_id=uid_val or "",
                        direction=direction,
                        sent_utc_ns=sent_ns,
                        sent_utc_iso=sent_iso,
                        message_text=body,
                        is_edited_or_past_revision=is_edited,
                        pre_edit_or_diff_json=diff_json,
                        ttl_disappearing_seconds=exp_sec or 0,
                        is_view_once_media=v_once or 0,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    messages.append(rec)
            except Exception as exc:
                logger.debug("Failed reading Signal iOS interactions: %s", exc)

        conn.close()
        return messages
