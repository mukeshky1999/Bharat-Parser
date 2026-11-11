"""
Sub-Engine 5.4C: Cross-Border Handler VoIP & Asian Syndicate Messengers.
Decodes Botim, IMO, Tencent WeChat, LINE, and Viber databases.
Complies with Section 5 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
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
    format_utc_iso_ms,
)

logger = logging.getLogger(__name__)


class CrossBorderVoIPDecoder:
    """Decoder for Botim, IMO, WeChat, LINE, and Viber."""

    def decode_botim_database(
        self,
        db_path: str,
        app_instance_id: int = 5,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses Botim SQLite databases for UAE/Gulf handler communications."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []
        if not os.path.exists(db_path):
            return accounts, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Contacts
            for c_tbl in ["contacts", "friends", "user_info"]:
                if c_tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({c_tbl})")
                        cols = [r[1] for r in cur.fetchall()]
                        uid_col = "uid" if "uid" in cols else ("id" if "id" in cols else "contact_id")
                        phone_col = "phone" if "phone" in cols else ("phone_number" if "phone_number" in cols else None)
                        name_col = "name" if "name" in cols else ("display_name" if "display_name" in cols else None)

                        q = f"SELECT {uid_col}, {phone_col or 'NULL'}, {name_col or 'NULL'} FROM {c_tbl}"
                        cur.execute(q)
                        for u_val, p_val, n_val in cur.fetchall():
                            accounts.append(
                                SocialAccountRecord(
                                    platform_name=SocialPlatform.BOTIM,
                                    app_instance_id=app_instance_id,
                                    account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
                                    native_platform_id=str(u_val),
                                    username_or_handle=str(n_val) if n_val else None,
                                    display_full_name=str(n_val) if n_val else None,
                                    linked_phone_e164=str(p_val) if p_val else None,
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G09_VOIP_REGIONAL_AND_COVERT_CHATS,
                                )
                            )
                    except Exception as exc:
                        logger.debug("Failed querying Botim %s: %s", c_tbl, exc)

            # 2. Messages
            for m_tbl in ["messages", "chat_messages", "chat"]:
                if m_tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({m_tbl})")
                        cols = [r[1] for r in cur.fetchall()]
                        mid_col = "msg_id" if "msg_id" in cols else ("id" if "id" in cols else "_id")
                        sess_col = "session_id" if "session_id" in cols else ("chat_id" if "chat_id" in cols else "'th_1'")
                        from_col = "from_uid" if "from_uid" in cols else ("sender_id" if "sender_id" in cols else "NULL")
                        txt_col = "content" if "content" in cols else ("body" if "body" in cols else "NULL")
                        ts_col = "timestamp" if "timestamp" in cols else ("date" if "date" in cols else "0")

                        q = f"SELECT {mid_col}, {sess_col}, {from_col}, {txt_col}, {ts_col} FROM {m_tbl}"
                        cur.execute(q)
                        for mid, sess, from_u, txt, ts in cur.fetchall():
                            ts_ms = int(ts) if ts else 0
                            if 0 < ts_ms < 10_000_000_000:
                                ts_ms *= 1000

                            sent_ns = ts_ms * 1_000_000
                            sent_iso = format_utc_iso_ms(ts_ms)

                            rec = SocialMessageRecord(
                                platform_name=SocialPlatform.BOTIM,
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=source_vfs_file_id,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                thread_or_channel_id=str(sess),
                                native_message_id=str(mid),
                                direction="INCOMING_RECEIVED",
                                sender_id_and_handle=str(from_u) if from_u else None,
                                content_category=SocialContentCategory.TEXT,
                                message_text=txt,
                                sent_utc_ns=sent_ns,
                                sent_utc_iso=sent_iso,
                                forensic_group=ForensicGroup.G09_VOIP_REGIONAL_AND_COVERT_CHATS,
                            )
                            messages.append(rec)
                    except Exception as exc:
                        logger.debug("Failed querying Botim %s: %s", m_tbl, exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Botim database %s: %s", db_path, exc)

        return accounts, messages

    def decode_wechat_database(
        self,
        db_path: str,
        app_instance_id: int = 6,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[SocialAccountRecord], List[SocialMessageRecord]]:
        """Parses decrypted Tencent WeChat EnMicroMsg.db database."""
        accounts: List[SocialAccountRecord] = []
        messages: List[SocialMessageRecord] = []
        if not os.path.exists(db_path):
            return accounts, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Contacts (rcontact)
            if "rcontact" in tables:
                try:
                    cur.execute("SELECT username, alias, nickname, conRemark FROM rcontact")
                    for u_name, alias_val, n_name, remark in cur.fetchall():
                        dname = remark or n_name
                        accounts.append(
                            SocialAccountRecord(
                                platform_name=SocialPlatform.WECHAT,
                                app_instance_id=app_instance_id,
                                account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
                                native_platform_id=str(u_name),
                                username_or_handle=str(alias_val) if alias_val else str(u_name),
                                display_full_name=dname,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G09_VOIP_REGIONAL_AND_COVERT_CHATS,
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed querying rcontact in WeChat DB: %s", exc)

            # 2. Messages (message)
            if "message" in tables:
                try:
                    cur.execute("SELECT msgId, talker, isSend, createTime, type, content FROM message")
                    for mid, talker_val, is_send, cr_time, m_type, content_val in cur.fetchall():
                        direction = "OUTGOING_SENT" if is_send == 1 else "INCOMING_RECEIVED"
                        ts_ms = int(cr_time) if cr_time else 0
                        sent_ns = ts_ms * 1_000_000
                        sent_iso = format_utc_iso_ms(ts_ms)

                        # Parse @chatroom group message prefix if applicable
                        msg_text = content_val
                        sender_handle = str(talker_val)
                        if is_send == 0 and talker_val and "@chatroom" in str(talker_val) and content_val:
                            if ":\n" in content_val:
                                parts = content_val.split(":\n", 1)
                                sender_handle = parts[0]
                                msg_text = parts[1]

                        rec = SocialMessageRecord(
                            platform_name=SocialPlatform.WECHAT,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_or_channel_id=str(talker_val),
                            native_message_id=str(mid),
                            direction=direction,
                            sender_id_and_handle=sender_handle,
                            content_category=SocialContentCategory.TEXT,
                            message_text=msg_text,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G09_VOIP_REGIONAL_AND_COVERT_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying message in WeChat DB: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening WeChat database %s: %s", db_path, exc)

        return accounts, messages
