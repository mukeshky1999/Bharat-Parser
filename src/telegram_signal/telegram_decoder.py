"""
Sub-Engine 5.2A & 5.2C: Telegram Ecosystem Decoder & Multi-Account Slot Discoverer.
Parses Telegram cache4.db, unpacks 64-bit dialog and message IDs, discovers multi-account
slots, detects 'Saved Messages' vaults, and handles Secret Chats (enc_chats).
Complies with Section 3 and Section 5 of Phase 5 Module 5.2 Specification.
"""

import base64
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.telegram_signal.models import (
    PlatformFamily,
    PeerType,
    LocalRoleInGroup,
    ThreadClassification,
    MessagingPeerRecord,
    MessagingMessageRecord,
)
from src.telegram_signal.tl_deserializer import (
    decode_tl_user,
    decode_tl_message,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_sec(ts_sec: int) -> str:
    """Formats Unix timestamp seconds into UTC ISO-8601 string."""
    if ts_sec <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def unpack_dialog_uid(
    uid: int, self_user_id: Optional[int] = None
) -> Tuple[str, ThreadClassification, Optional[int]]:
    """
    Unpacks 64-bit signed Telegram dialog ID into peer type according to Section 3.3.
    """
    # Check Saved Messages Self Vault first
    if self_user_id is not None and uid == self_user_id:
        return str(uid), ThreadClassification.SAVED_MESSAGES_SELF_VAULT, uid

    low_32 = uid & 0xFFFFFFFF
    high_32 = (uid >> 32) & 0xFFFFFFFF

    # Case 3: Negative uid -> Group, Supergroup, or Channel
    if uid < 0:
        channel_id = abs(uid)
        if channel_id > 10**12:
            channel_id = channel_id - 1000000000000
        return str(uid), ThreadClassification.GROUP_OR_SUPERGROUP, channel_id

    # Case 2: Positive uid and high_32 != 0 with low_32 == 0 -> Secret Chat
    if uid > 0 and high_32 != 0 and low_32 == 0:
        return str(uid), ThreadClassification.SECRET_E2EE_CHAT, high_32

    # Case 1: Standard 1-on-1 private user chat
    return str(uid), ThreadClassification.DIRECT_1ON1_CHAT, uid


def discover_telegram_accounts(sandbox_path: str) -> List[Dict[str, Any]]:
    """
    Scans a Telegram sandbox directory for primary and secondary multi-account slots.
    Inspects /files/cache4.db, /files/account1..N/cache4.db, and /shared_prefs/userconfig*.xml.
    """
    accounts: List[Dict[str, Any]] = []
    base_path = Path(sandbox_path)

    # 1. Check Primary Slot 0
    primary_db = base_path / "files" / "cache4.db"
    primary_xml_cand1 = base_path / "shared_prefs" / "userconfing.xml"
    primary_xml_cand2 = base_path / "shared_prefs" / "userconfig.xml"
    primary_xml = primary_xml_cand1 if primary_xml_cand1.exists() else primary_xml_cand2

    if primary_db.exists() or primary_xml.exists():
        self_id, owner_dict = _parse_userconfig_xml(str(primary_xml)) if primary_xml.exists() else (None, {})
        accounts.append({
            "account_slot_name": "account0_primary",
            "db_path": str(primary_db) if primary_db.exists() else None,
            "config_xml_path": str(primary_xml) if primary_xml.exists() else None,
            "self_user_id": self_id,
            "owner_info": owner_dict,
        })

    # 2. Check Secondary Slots (account1, account2, ... account50)
    files_dir = base_path / "files"
    if files_dir.exists():
        for item in files_dir.iterdir():
            if item.is_dir() and item.name.startswith("account"):
                acc_name = item.name
                match = re.search(r"\d+", acc_name)
                acc_num = match.group(0) if match else "1"
                acc_db = item / "cache4.db"
                acc_xml = base_path / "shared_prefs" / f"userconfig{acc_num}.xml"

                self_id, owner_dict = _parse_userconfig_xml(str(acc_xml)) if acc_xml.exists() else (None, {})
                accounts.append({
                    "account_slot_name": acc_name,
                    "db_path": str(acc_db) if acc_db.exists() else None,
                    "config_xml_path": str(acc_xml) if acc_xml.exists() else None,
                    "self_user_id": self_id,
                    "owner_info": owner_dict,
                })

    return accounts


def _parse_userconfig_xml(xml_path: str) -> Tuple[Optional[int], Dict[str, Any]]:
    """Parses userconfig*.xml extracting self_user_id and TL_user profile."""
    owner_info: Dict[str, Any] = {}
    self_id: Optional[int] = None
    if not os.path.exists(xml_path):
        return None, owner_info

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for child in root:
            name_attr = child.attrib.get("name", "")
            val_attr = child.attrib.get("value")

            if name_attr in ("clientUserId", "user_id"):
                if val_attr:
                    self_id = int(val_attr)
                elif child.text:
                    self_id = int(child.text)

            elif name_attr == "user" and child.text:
                try:
                    user_blob = base64.b64decode(child.text.strip())
                    owner_info = decode_tl_user(user_blob)
                    if not self_id and owner_info.get("user_id"):
                        self_id = owner_info["user_id"]
                except Exception as exc:
                    logger.debug("Failed decoding userconfig base64 user: %s", exc)

    except Exception as exc:
        logger.debug("Failed parsing userconfig XML %s: %s", xml_path, exc)

    return self_id, owner_info


class TelegramDatabaseDecoder:
    """Decoder for Telegram Android cache4.db and associated tables."""

    def extract_peers(
        self,
        db_path: str,
        account_slot_name: str = "account0_primary",
        app_instance_id: int = 1,
    ) -> List[MessagingPeerRecord]:
        """Extracts users, chats, channels, and secret chats from cache4.db."""
        peers: List[MessagingPeerRecord] = []
        if not os.path.exists(db_path):
            return peers

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        # 1. Parse users table
        if "users" in tables:
            try:
                cur.execute("SELECT uid, name, status, data FROM users")
                for u_id, name, status, data in cur.fetchall():
                    first_name, last_name, username = None, None, None
                    if name:
                        parts = name.split(";;;")
                        if len(parts) >= 1 and parts[0]:
                            first_name = parts[0]
                        if len(parts) >= 2 and parts[1]:
                            last_name = parts[1]
                        if len(parts) >= 3 and parts[2]:
                            username = parts[2]

                    tl_info = decode_tl_user(data) if data else {}
                    phone = tl_info.get("phone")
                    phone_e164 = f"+{phone}" if phone else None

                    final_first = tl_info.get("first_name") or first_name
                    final_last = tl_info.get("last_name") or last_name
                    final_user = tl_info.get("username") or username
                    handle = f"@{final_user}" if final_user else None

                    names = [n for n in (final_first, final_last) if n]
                    display_name = " ".join(names) if names else None

                    peer_type = PeerType.TELEGRAM_BOT if tl_info.get("is_bot") else PeerType.USER_CONTACT
                    is_scam = 1 if (tl_info.get("is_scam") or tl_info.get("is_fake")) else 0

                    rec = MessagingPeerRecord(
                        platform_family=PlatformFamily.TELEGRAM,
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        peer_type=peer_type,
                        native_peer_id=str(u_id),
                        username_handle=handle,
                        phone_number_e164=phone_e164,
                        display_or_group_name=display_name,
                        is_scam_or_fake_flagged=is_scam,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    peers.append(rec)
            except Exception as exc:
                logger.debug("Failed reading users table: %s", exc)

        # 2. Parse chats table
        if "chats" in tables:
            try:
                cur.execute("SELECT uid, name, data FROM chats")
                for c_id, name, data in cur.fetchall():
                    rec = MessagingPeerRecord(
                        platform_family=PlatformFamily.TELEGRAM,
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        peer_type=PeerType.GROUP_CHAT,
                        native_peer_id=str(c_id),
                        display_or_group_name=name,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    peers.append(rec)
            except Exception as exc:
                logger.debug("Failed reading chats table: %s", exc)

        # 3. Parse enc_chats table (Secret Chats)
        if "enc_chats" in tables:
            try:
                cur.execute("SELECT uid, user, name FROM enc_chats")
                for s_id, u_target, name in cur.fetchall():
                    rec = MessagingPeerRecord(
                        platform_family=PlatformFamily.TELEGRAM,
                        app_instance_id=app_instance_id,
                        account_slot_name=account_slot_name,
                        peer_type=PeerType.SECRET_CHAT_PARTNER,
                        native_peer_id=str(s_id),
                        secondary_uuid_or_pni=str(u_target) if u_target else None,
                        display_or_group_name=name or f"Secret Chat {s_id}",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    peers.append(rec)
            except Exception as exc:
                logger.debug("Failed reading enc_chats table: %s", exc)

        conn.close()
        return peers

    def extract_messages(
        self,
        db_path: str,
        account_slot_name: str = "account0_primary",
        self_user_id: Optional[int] = None,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> List[MessagingMessageRecord]:
        """Extracts messages from cache4.db messages_v2 or messages table."""
        messages: List[MessagingMessageRecord] = []
        if not os.path.exists(db_path):
            return messages

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        target_table = "messages_v2" if "messages_v2" in tables else ("messages" if "messages" in tables else None)
        if not target_table:
            conn.close()
            return messages

        try:
            cur.execute(f"SELECT mid, uid, date, data, out, ttl FROM {target_table}")
            for mid, uid, date, data, out, ttl in cur.fetchall():
                thread_id_str, thread_class, _ = unpack_dialog_uid(uid, self_user_id)
                direction = "OUTGOING_SENT" if out == 1 else "INCOMING_RECEIVED"

                tl_info = decode_tl_message(data) if data else {}
                msg_text = tl_info.get("message_text")
                edit_date = tl_info.get("edit_date")
                is_edited = 1 if edit_date else 0

                fwd_info = tl_info.get("forward_from")
                fwd_json = json.dumps(fwd_info) if fwd_info else None

                reply_to = tl_info.get("reply_to_msg_id")
                reply_to_str = str(reply_to) if reply_to else None

                media_meta = tl_info.get("media_metadata")
                media_json = json.dumps(media_meta) if media_meta else None

                buttons_meta = tl_info.get("inline_buttons")
                buttons_json = json.dumps(buttons_meta) if buttons_meta else None

                ts_sec = date or tl_info.get("date") or 0
                sent_ns = ts_sec * 1_000_000_000
                sent_iso = _format_utc_iso_sec(ts_sec)

                from_id = tl_info.get("from_id")
                sender_peer = str(from_id) if from_id else (str(self_user_id) if out == 1 else str(uid))

                # Human sequential message number
                seq_mid = mid & 0xFFFFFFFF if mid else 0

                rec = MessagingMessageRecord(
                    app_instance_id=app_instance_id,
                    account_slot_name=account_slot_name,
                    source_vfs_file_id=source_vfs_file_id,
                    thread_or_dialog_id=thread_id_str,
                    thread_classification=thread_class,
                    native_message_id=str(seq_mid),
                    direction=direction,
                    sent_utc_ns=sent_ns,
                    sent_utc_iso=sent_iso,
                    sender_peer_id=sender_peer,
                    message_text=msg_text,
                    is_edited_or_past_revision=is_edited,
                    forwarded_from_info_json=fwd_json,
                    reply_to_msg_id=reply_to_str,
                    ttl_disappearing_seconds=ttl or 0,
                    media_attachment_json=media_json,
                    inline_bot_buttons_json=buttons_json,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
                messages.append(rec)
        except Exception as exc:
            logger.debug("Failed reading %s: %s", target_table, exc)

        conn.close()
        return messages
