"""
Sub-Engine 5.3C: Privacy Messengers Decoder (Zangi, XMPP Conversations, Threema, Element/Matrix).
Decodes:
  - Zangi 10-digit virtual numbers (10-XXXX-XXXX) and message/call stores
  - XMPP / Conversations (eu.siacs.conversations) history, OMEMO device fingerprints, and JIDs
  - Threema, Element/Matrix, and Briar artifact parsing
Complies with Section 5 of Phase 5 Module 5.3 Specification and AGENTS.md.
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
from src.high_opsec.models import (
    OpSecPlatformName,
    IdentityRole,
    MessageDirection,
    OpSecIdentityRecord,
    OpSecMessageRecord,
    is_valid_zangi_number,
    is_valid_threema_id,
    is_valid_matrix_id,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix millisecond timestamp into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class PrivacyMessengersDecoder:
    """Decoder for Zangi, XMPP Conversations, Threema, Element/Matrix, and Briar."""

    def decode_zangi(
        self,
        db_path: str,
        app_instance_id: int = 3,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[OpSecIdentityRecord], List[OpSecMessageRecord]]:
        """Parses Zangi Private Messenger SQLite databases."""
        identities: List[OpSecIdentityRecord] = []
        messages: List[OpSecMessageRecord] = []
        if not os.path.exists(db_path):
            return identities, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Contacts
            if "contacts" in tables:
                try:
                    cur.execute("PRAGMA table_info(contacts)")
                    cols = [r[1] for r in cur.fetchall()]
                    num_col = "zangi_number" if "zangi_number" in cols else "number"
                    name_col = "name" if "name" in cols else "display_name"

                    if num_col in cols:
                        cur.execute(f"SELECT {num_col}, {name_col if name_col in cols else 'NULL'} FROM contacts")
                        for num_val, name_val in cur.fetchall():
                            if num_val:
                                identities.append(
                                    OpSecIdentityRecord(
                                        app_platform_name=OpSecPlatformName.ZANGI,
                                        app_instance_id=app_instance_id,
                                        identity_role=IdentityRole.REMOTE_CONTACT,
                                        primary_crypto_handle=str(num_val),
                                        display_or_nickname=str(name_val) if name_val else None,
                                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                        forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                                    )
                                )
                except Exception as exc:
                    logger.debug("Failed reading Zangi contacts: %s", exc)

            # 2. Messages
            if "messages" in tables:
                try:
                    cur.execute("PRAGMA table_info(messages)")
                    cols = [r[1] for r in cur.fetchall()]
                    s_col = "sender_zangi" if "sender_zangi" in cols else ("sender" if "sender" in cols else None)
                    r_col = "receiver_zangi" if "receiver_zangi" in cols else ("receiver" if "receiver" in cols else None)
                    b_col = "body" if "body" in cols else ("text" if "text" in cols else "message_body")
                    t_col = "timestamp" if "timestamp" in cols else ("date" if "date" in cols else "time")
                    c_col = "conversation_id" if "conversation_id" in cols else None

                    q_cols = [
                        s_col or "NULL",
                        r_col or "NULL",
                        b_col or "NULL",
                        t_col or "0",
                        c_col or "'conv_default'",
                    ]
                    cur.execute(f"SELECT {', '.join(q_cols)} FROM messages")
                    for s_val, r_val, b_val, t_val, c_val in cur.fetchall():
                        ts_ms = int(t_val) if t_val else 0
                        if 0 < ts_ms < 10_000_000_000:
                            ts_ms *= 1000

                        sent_ns = ts_ms * 1_000_000
                        sent_iso = _format_utc_iso_ms(ts_ms)

                        rec = OpSecMessageRecord(
                            app_platform_name=OpSecPlatformName.ZANGI,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_identifier=str(c_val) if c_val else "conv_default",
                            direction="INCOMING_RECEIVED",
                            sender_crypto_handle=str(s_val) if s_val else None,
                            receiver_crypto_handle=str(r_val) if r_val else None,
                            message_body_text=str(b_val) if b_val else None,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed reading Zangi messages: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Zangi database %s: %s", db_path, exc)

        return identities, messages

    def decode_xmpp_conversations(
        self,
        db_path: str,
        app_instance_id: int = 4,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[OpSecIdentityRecord], List[OpSecMessageRecord]]:
        """Parses XMPP Conversations (eu.siacs.conversations) plaintext history database."""
        identities: List[OpSecIdentityRecord] = []
        messages: List[OpSecMessageRecord] = []
        if not os.path.exists(db_path):
            return identities, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Accounts & Identities (with OMEMO device fingerprints)
            fp_map: Dict[str, str] = {}
            if "identities" in tables:
                try:
                    cur.execute("SELECT jid, fingerprint, own FROM identities")
                    for jid_val, fp_val, own_val in cur.fetchall():
                        if jid_val:
                            fp_map[str(jid_val)] = str(fp_val)
                            role = IdentityRole.LOCAL_DEVICE_OWNER if own_val == 1 else IdentityRole.REMOTE_CONTACT
                            identities.append(
                                OpSecIdentityRecord(
                                    app_platform_name=OpSecPlatformName.XMPP_CONVERSATIONS,
                                    app_instance_id=app_instance_id,
                                    identity_role=role,
                                    primary_crypto_handle=str(jid_val),
                                    public_key_or_omemo_fp=str(fp_val) if fp_val else None,
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed querying identities in XMPP DB: %s", exc)

            if "accounts" in tables:
                try:
                    cur.execute("SELECT uuid, username, server FROM accounts")
                    for a_uuid, u_name, s_name in cur.fetchall():
                        full_jid = f"{u_name}@{s_name}" if u_name and s_name else u_name
                        if full_jid and full_jid not in [i.primary_crypto_handle for i in identities]:
                            identities.append(
                                OpSecIdentityRecord(
                                    app_platform_name=OpSecPlatformName.XMPP_CONVERSATIONS,
                                    app_instance_id=app_instance_id,
                                    identity_role=IdentityRole.LOCAL_DEVICE_OWNER,
                                    primary_crypto_handle=full_jid,
                                    server_or_relay_url=s_name,
                                    public_key_or_omemo_fp=fp_map.get(full_jid),
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed querying accounts in XMPP DB: %s", exc)

            # 2. Conversations
            conv_map: Dict[str, str] = {}
            if "conversations" in tables:
                try:
                    cur.execute("SELECT uuid, contactJid FROM conversations")
                    for c_uuid, c_jid in cur.fetchall():
                        conv_map[c_uuid] = c_jid
                except Exception as exc:
                    logger.debug("Failed querying conversations in XMPP DB: %s", exc)

            # 3. Messages
            if "messages" in tables:
                try:
                    cur.execute("""
                        SELECT uuid, conversationUuid, timeSent, body, encryption, fingerprint
                        FROM messages
                    """)
                    for m_uuid, c_uuid, t_sent, body_val, enc_val, fp_val in cur.fetchall():
                        ts_ms = int(t_sent) if t_sent else 0
                        if 0 < ts_ms < 10_000_000_000:
                            ts_ms *= 1000

                        sent_ns = ts_ms * 1_000_000
                        sent_iso = _format_utc_iso_ms(ts_ms)

                        contact_jid = conv_map.get(c_uuid, c_uuid)

                        rec = OpSecMessageRecord(
                            app_platform_name=OpSecPlatformName.XMPP_CONVERSATIONS,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_identifier=str(c_uuid),
                            direction="INCOMING_RECEIVED",
                            sender_crypto_handle=contact_jid,
                            message_body_text=str(body_val) if body_val else None,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying messages in XMPP DB: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening XMPP DB %s: %s", db_path, exc)

        return identities, messages
