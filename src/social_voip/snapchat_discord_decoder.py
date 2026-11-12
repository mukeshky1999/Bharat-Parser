"""
Sub-Engine 5.4B: Snapchat (arroyo.db Protobuf & UUID Join) & Discord (Simple Cache & Snowflake Math).
Decodes:
  - Snapchat arroyo.db conversation_message Protobuf payloads, joining 16-byte UUIDs with main.db Friend table.
  - Discord HTTP Simple Cache (*_0) JSON message arrays, applying exact 64-bit Snowflake timestamp bit-shift math.
Complies with Section 4 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.nonsqlite.protobuf import decode_raw_protobuf
from src.social_voip.models import (
    SocialPlatform,
    SocialAccountRole,
    SocialMessageDirection,
    SocialContentCategory,
    SocialAccountRecord,
    SocialMessageRecord,
    discord_snowflake_to_unix_ms,
    format_utc_iso_ms,
)

logger = logging.getLogger(__name__)


def _normalize_uuid_str(val: Any) -> str:
    """Normalizes binary 16-byte UUID or hex string into canonical 8-4-4-4-12 UUID format."""
    if isinstance(val, bytes):
        if len(val) == 16:
            return str(uuid.UUID(bytes=val))
        try:
            return str(uuid.UUID(hex=val.hex()))
        except Exception:
            return val.hex()
    elif isinstance(val, str):
        cleaned = val.strip().replace("-", "")
        if len(cleaned) == 32:
            try:
                return str(uuid.UUID(hex=cleaned))
            except Exception:
                return val
        return val
    return str(val)


def _extract_text_from_protobuf_dict(pb_dict: Dict[str, Any]) -> Optional[str]:
    """Extracts chat text string from Snapchat decoded Protobuf tree."""
    # Look for field_4 -> field_1 or any field containing printable text
    if not isinstance(pb_dict, dict):
        return None

    if "field_4" in pb_dict:
        f4 = pb_dict["field_4"]
        if isinstance(f4, dict):
            if "field_1" in f4:
                f1 = f4["field_1"]
                if isinstance(f1, str):
                    return f1
                elif isinstance(f1, dict) and "field_1" in f1 and isinstance(f1["field_1"], str):
                    return f1["field_1"]
        elif isinstance(f4, str):
            return f4

    for k, v in pb_dict.items():
        if isinstance(v, str) and len(v) > 0:
            return v
        elif isinstance(v, dict):
            nested_txt = _extract_text_from_protobuf_dict(v)
            if nested_txt:
                return nested_txt

    return None


class SnapchatDiscordDecoder:
    """Decoder for Snapchat (arroyo.db) and Discord (Simple Cache JSON & Snowflake)."""

    def decode_snapchat_sandbox(
        self,
        sandbox_path: str,
        app_instance_id: int = 2,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses Snapchat sandbox databases (main.db for friends, arroyo.db for messages)."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []
        base_path = Path(sandbox_path)

        # 1. Inspect main.db for contacts
        friend_map: Dict[str, Tuple[str, Optional[str]]] = {}
        main_db_cands = [
            base_path / "databases" / "main.db",
            base_path / "main.db",
        ]
        main_db_path = None
        for cand in main_db_cands:
            if cand.exists():
                main_db_path = cand
                break

        if main_db_path:
            try:
                conn_m = sqlite3.connect(main_db_path)
                cur_m = conn_m.cursor()
                cur_m.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables_m = {r[0] for r in cur_m.fetchall()}
                if "Friend" in tables_m:
                    cur_m.execute("SELECT userId, username, displayName FROM Friend")
                    for u_id, uname, dname in cur_m.fetchall():
                        canon_uid = _normalize_uuid_str(u_id)
                        friend_map[canon_uid] = (uname, dname)
                        accounts.append(
                            SocialAccountRecord(
                                platform_name=SocialPlatform.SNAPCHAT,
                                app_instance_id=app_instance_id,
                                account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
                                native_platform_id=canon_uid,
                                username_or_handle=uname,
                                display_full_name=dname,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                            )
                        )
                conn_m.close()
            except Exception as exc:
                logger.debug("Failed querying main.db in Snapchat sandbox: %s", exc)

        # 2. Inspect arroyo.db for messages
        arroyo_cands = [
            base_path / "databases" / "arroyo.db",
            base_path / "Documents" / "arroyo.db",
            base_path / "arroyo.db",
        ]
        arroyo_path = None
        for cand in arroyo_cands:
            if cand.exists():
                arroyo_path = cand
                break

        if not arroyo_path:
            return accounts, messages

        try:
            conn_a = sqlite3.connect(arroyo_path)
            cur_a = conn_a.cursor()
            cur_a.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables_a = {r[0] for r in cur_a.fetchall()}

            if "conversation_message" in tables_a:
                cur_a.execute("""
                    SELECT client_conversation_id, server_message_id, sender_id,
                           creation_timestamp, content_type, message_content
                    FROM conversation_message
                """)
                for c_cid, s_mid, s_id_raw, c_ts, c_type, m_content in cur_a.fetchall():
                    canon_sender_uid = _normalize_uuid_str(s_id_raw)
                    sender_handle = canon_sender_uid
                    if canon_sender_uid in friend_map:
                        u_name, _ = friend_map[canon_sender_uid]
                        sender_handle = f"@{u_name}"

                    # Decode Protobuf blob
                    chat_text = None
                    if m_content and isinstance(m_content, (bytes, bytearray)):
                        try:
                            pb_dict, is_valid = decode_raw_protobuf(bytes(m_content))
                            if is_valid:
                                chat_text = _extract_text_from_protobuf_dict(pb_dict)
                        except Exception as exc:
                            logger.debug("Protobuf decode failed on Snapchat message: %s", exc)

                    ts_ms = int(c_ts) if c_ts else 0
                    sent_ns = ts_ms * 1_000_000
                    sent_iso = format_utc_iso_ms(ts_ms)

                    cat = SocialContentCategory.TEXT if c_type == 1 else SocialContentCategory.EPHEMERAL_SNAP_OR_RAVEN

                    rec = SocialMessageRecord(
                        platform_name=SocialPlatform.SNAPCHAT,
                        app_instance_id=app_instance_id,
                        source_vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        thread_or_channel_id=str(c_cid),
                        native_message_id=str(s_mid),
                        direction="UNKNOWN",
                        sender_id_and_handle=sender_handle,
                        content_category=cat,
                        message_text=chat_text,
                        sent_utc_ns=sent_ns,
                        sent_utc_iso=sent_iso,
                        forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                    )
                    messages.append(rec)

            conn_a.close()
        except Exception as exc:
            logger.debug("Failed reading arroyo.db in Snapchat sandbox: %s", exc)

        return accounts, messages

    def decode_discord_sandbox(
        self,
        sandbox_path: str,
        app_instance_id: int = 3,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses Discord HTTP Simple Cache (*_0) files for message JSON arrays and Snowflake math."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []
        base_path = Path(sandbox_path)

        cache_dirs = [
            base_path / "cache" / "Cache_Data",
            base_path / "cache" / "http-cache",
            base_path / "app_webview" / "Default" / "Cache" / "Cache_Data",
        ]

        candidate_files: List[Path] = []
        for cdir in cache_dirs:
            if cdir.exists():
                for f in cdir.iterdir():
                    if f.is_file():
                        candidate_files.append(f)

        for cfile in candidate_files:
            try:
                content = cfile.read_text(encoding="utf-8", errors="ignore")
                if not content or "messages" not in content:
                    continue

                # Parse JSON
                data = json.loads(content)
                msg_list: List[dict] = []

                if isinstance(data, list):
                    msg_list = data
                elif isinstance(data, dict):
                    if "body_json" in data and isinstance(data["body_json"], list):
                        msg_list = data["body_json"]
                    elif "messages" in data and isinstance(data["messages"], list):
                        msg_list = data["messages"]

                for item in msg_list:
                    if not isinstance(item, dict) or "id" not in item:
                        continue

                    s_id_str = str(item["id"])
                    try:
                        s_id_int = int(s_id_str)
                        ts_ms = discord_snowflake_to_unix_ms(s_id_int)
                    except Exception:
                        ts_ms = 0

                    sent_ns = ts_ms * 1_000_000
                    sent_iso = format_utc_iso_ms(ts_ms)

                    ch_id = str(item.get("channel_id", "default_channel"))
                    txt = item.get("content")

                    author_obj = item.get("author", {})
                    author_id = str(author_obj.get("id", ""))
                    uname = author_obj.get("username")
                    gname = author_obj.get("global_name")

                    if author_id and not any(a.native_platform_id == author_id for a in accounts):
                        accounts.append(
                            SocialAccountRecord(
                                platform_name=SocialPlatform.DISCORD,
                                app_instance_id=app_instance_id,
                                account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
                                native_platform_id=author_id,
                                username_or_handle=uname,
                                display_full_name=gname,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                            )
                        )

                    rec = SocialMessageRecord(
                        platform_name=SocialPlatform.DISCORD,
                        app_instance_id=app_instance_id,
                        source_vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        thread_or_channel_id=ch_id,
                        native_message_id=s_id_str,
                        direction="UNKNOWN",
                        sender_id_and_handle=f"@{uname}" if uname else author_id,
                        content_category=SocialContentCategory.TEXT,
                        message_text=txt,
                        sent_utc_ns=sent_ns,
                        sent_utc_iso=sent_iso,
                        forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                    )
                    messages.append(rec)
            except Exception as exc:
                logger.debug("Failed parsing cache file %s: %s", cfile, exc)

        return accounts, messages
