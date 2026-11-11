"""
Sub-Engine 5.4A: Meta Ecosystem Decoders (Instagram Direct & Facebook Messenger).
Parses modern multi-user Instagram direct_<user_id>.db, reverb_*.db, and Meta MSYS SQLite databases.
Handles 16-digit microsecond timestamps and unsent quoted-reply extraction.
Complies with Section 3 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
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
from src.social_voip.models import (
    SocialPlatform,
    SocialAccountRole,
    SocialMessageDirection,
    SocialContentCategory,
    SocialAccountRecord,
    SocialMessageRecord,
    format_utc_iso_us,
    format_utc_iso_ms,
)

logger = logging.getLogger(__name__)


class MetaDecoder:
    """Decoder for Instagram Direct and Facebook Messenger databases."""

    def decode_instagram_database(
        self,
        db_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses Instagram direct_<user_id>.db database."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []

        if not os.path.exists(db_path):
            return accounts, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            viewer_id = ""

            # 1. Parse threads table
            if "threads" in tables:
                try:
                    cur.execute("PRAGMA table_info(threads)")
                    col_names = [r[1] for r in cur.fetchall()]
                    q_cols = [
                        "thread_id",
                        "viewer_id" if "viewer_id" in col_names else "NULL",
                        "named" if "named" in col_names else "NULL",
                        "last_activity_time" if "last_activity_time" in col_names else "NULL",
                        "thread_info" if "thread_info" in col_names else "NULL",
                    ]
                    cur.execute(f"SELECT {', '.join(q_cols)} FROM threads")
                    for t_id, v_id, named_val, l_act, t_info in cur.fetchall():
                        if v_id and not viewer_id:
                            viewer_id = str(v_id)

                        # Parse thread_info JSON for participants
                        if t_info:
                            try:
                                t_json = json.loads(t_info)
                                recipients = t_json.get("recipients", []) or t_json.get("users", [])
                                for rec in recipients:
                                    pk_val = str(rec.get("pk", ""))
                                    uname = rec.get("username")
                                    fname = rec.get("full_name")
                                    role = (
                                        SocialAccountRole.LOCAL_LOGGED_IN_OWNER
                                        if (viewer_id and pk_val == viewer_id)
                                        else SocialAccountRole.REMOTE_CONTACT_OR_FRIEND
                                    )
                                    if pk_val and not any(a.native_platform_id == pk_val for a in accounts):
                                        accounts.append(
                                            SocialAccountRecord(
                                                platform_name=SocialPlatform.INSTAGRAM,
                                                app_instance_id=app_instance_id,
                                                account_role=role,
                                                native_platform_id=pk_val,
                                                username_or_handle=uname,
                                                display_full_name=fname,
                                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                                forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                                            )
                                        )
                            except Exception as exc:
                                logger.debug("Failed parsing thread_info JSON in Instagram DB: %s", exc)
                except Exception as exc:
                    logger.debug("Failed querying threads table in Instagram DB: %s", exc)

            # 2. Parse messages table
            if "messages" in tables:
                try:
                    cur.execute("PRAGMA table_info(messages)")
                    col_names = [r[1] for r in cur.fetchall()]

                    m_id_col = "message_id" if "message_id" in col_names else "_id"
                    t_id_col = "thread_id" if "thread_id" in col_names else "'th_default'"
                    s_id_col = "sender_id" if "sender_id" in col_names else ("user_id" if "user_id" in col_names else "NULL")
                    ts_col = "timestamp" if "timestamp" in col_names else "0"
                    m_type_col = "message_type" if "message_type" in col_names else "NULL"
                    text_col = "text" if "text" in col_names else "NULL"
                    json_col = "message" if "message" in col_names else "NULL"

                    q = f"SELECT {m_id_col}, {t_id_col}, {s_id_col}, {ts_col}, {m_type_col}, {text_col}, {json_col} FROM messages"
                    cur.execute(q)

                    for m_id, t_id, s_id, ts_val, m_type, flat_text, msg_json_str in cur.fetchall():
                        # Timestamp normalization (16-digit microseconds vs 13-digit ms vs 10-digit s)
                        raw_ts = int(ts_val) if ts_val else 0
                        if raw_ts > 10**15:
                            # 16-digit Unix microseconds
                            sent_ns = raw_ts * 1000
                            sent_iso = format_utc_iso_us(raw_ts)
                        elif raw_ts > 10**11:
                            # 13-digit Unix milliseconds
                            sent_ns = raw_ts * 1_000_000
                            sent_iso = format_utc_iso_ms(raw_ts)
                        else:
                            # 10-digit Unix seconds
                            sent_ns = raw_ts * 1_000_000_000
                            sent_iso = format_utc_iso_ms(raw_ts * 1000)

                        msg_text = flat_text
                        quoted_reply = None
                        media_json = None

                        if msg_json_str:
                            try:
                                m_json = json.loads(msg_json_str)
                                if not msg_text and "text" in m_json:
                                    msg_text = m_json["text"]

                                # Quoted Reply Recovery (replied_to_message)
                                if "replied_to_message" in m_json:
                                    parent_obj = m_json["replied_to_message"]
                                    if isinstance(parent_obj, dict):
                                        quoted_reply = parent_obj.get("text")

                                if "media" in m_json or "visual_media" in m_json:
                                    media_json = json.dumps(m_json.get("media") or m_json.get("visual_media"))
                            except Exception as exc:
                                logger.debug("Failed parsing message JSON in Instagram DB: %s", exc)

                        direction = "INCOMING_RECEIVED"
                        if viewer_id and str(s_id) == viewer_id:
                            direction = "OUTGOING_SENT"

                        rec = SocialMessageRecord(
                            platform_name=SocialPlatform.INSTAGRAM,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_or_channel_id=str(t_id),
                            native_message_id=str(m_id),
                            direction=direction,
                            sender_id_and_handle=str(s_id) if s_id else None,
                            content_category=SocialContentCategory.TEXT,
                            message_text=msg_text,
                            quoted_reply_text=quoted_reply,
                            media_or_location_json=media_json,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying messages table in Instagram DB: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Instagram database %s: %s", db_path, exc)

        return accounts, messages

    def decode_messenger_database(
        self,
        db_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses Facebook Messenger MSYS or legacy threads_db2 database."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []

        if not os.path.exists(db_path):
            return accounts, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Parse MSYS contacts
            if "contacts" in tables:
                try:
                    cur.execute("PRAGMA table_info(contacts)")
                    cols = [r[1] for r in cur.fetchall()]
                    c_id = "contact_id" if "contact_id" in cols else "id"
                    name_col = "name" if "name" in cols else "display_name"
                    u_col = "username" if "username" in cols else "NULL"

                    cur.execute(f"SELECT {c_id}, {name_col}, {u_col} FROM contacts")
                    for cid, cname, cuname in cur.fetchall():
                        accounts.append(
                            SocialAccountRecord(
                                platform_name=SocialPlatform.FB_MESSENGER,
                                app_instance_id=app_instance_id,
                                account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
                                native_platform_id=str(cid),
                                username_or_handle=str(cuname) if cuname else None,
                                display_full_name=str(cname) if cname else None,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed querying MSYS contacts in Messenger DB: %s", exc)

            # 2. Parse MSYS messages (messages / cql_messages)
            msg_table = "cql_messages" if "cql_messages" in tables else ("messages" if "messages" in tables else None)
            if msg_table:
                try:
                    cur.execute(f"PRAGMA table_info({msg_table})")
                    cols = [r[1] for r in cur.fetchall()]
                    m_id_col = "message_id" if "message_id" in cols else ("msg_id" if "msg_id" in cols else "id")
                    t_col = "thread_key" if "thread_key" in cols else ("thread_id" if "thread_id" in cols else "1")
                    s_col = "sender_id" if "sender_id" in cols else "NULL"
                    ts_col = "timestamp_ms" if "timestamp_ms" in cols else ("timestamp" if "timestamp" in cols else "0")
                    txt_col = "text" if "text" in cols else ("body" if "body" in cols else "NULL")
                    reply_col = "reply_snippet" if "reply_snippet" in cols else "NULL"

                    q = f"SELECT {m_id_col}, {t_col}, {s_col}, {ts_col}, {txt_col}, {reply_col} FROM {msg_table}"
                    cur.execute(q)
                    for mid, th_key, sid, ts_val, txt, reply_snip in cur.fetchall():
                        ts_ms = int(ts_val) if ts_val else 0
                        sent_ns = ts_ms * 1_000_000
                        sent_iso = format_utc_iso_ms(ts_ms)

                        rec = SocialMessageRecord(
                            platform_name=SocialPlatform.FB_MESSENGER,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_or_channel_id=str(th_key),
                            native_message_id=str(mid),
                            direction="INCOMING_RECEIVED",
                            sender_id_and_handle=str(sid) if sid else None,
                            content_category=SocialContentCategory.TEXT,
                            message_text=txt,
                            quoted_reply_text=reply_snip,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying %s in Messenger DB: %s", msg_table, exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Messenger DB %s: %s", db_path, exc)

        return accounts, messages
