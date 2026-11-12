"""
Sub-Engine 5.3A: Session Decentralized Oxen Onion-Routed Messenger Decoder.
Parses Session Android and iOS sandboxes:
  - shared_prefs/network.loki.messenger_preferences.xml (suspect's 05... Session ID & key)
  - session.db / Signal.sqlite (recipients, open groups SOGS, SMS/MMS messages, TTLs)
Complies with Section 3 of Phase 5 Module 5.3 Specification and AGENTS.md.
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
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
from src.high_opsec.models import (
    OpSecPlatformName,
    IdentityRole,
    MessageDirection,
    OpSecIdentityRecord,
    OpSecMessageRecord,
    is_valid_session_id,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix millisecond timestamp into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class SessionDecoder:
    """Decoder for Session (network.loki.messenger / com.loki-project.loki-messenger)."""

    def parse_preferences(self, xml_path: str) -> Dict[str, Any]:
        """Extracts owner Session ID and database secrets from preferences XML."""
        pref_data: Dict[str, Any] = {
            "owner_session_id": None,
            "database_secret": None,
        }
        if not os.path.exists(xml_path):
            return pref_data

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for child in root:
                name_attr = child.attrib.get("name", "")
                val_attr = child.attrib.get("value")
                text_val = child.text.strip() if child.text else (val_attr or "")

                if name_attr in ("pref_local_number", "user_public_key") and is_valid_session_id(text_val):
                    pref_data["owner_session_id"] = text_val
                elif name_attr in ("pref_database_unencrypted_secret", "pref_database_encrypted_secret"):
                    pref_data["database_secret"] = text_val
        except Exception as exc:
            logger.debug("Failed parsing Session preferences XML %s: %s", xml_path, exc)

        return pref_data

    def decode_sandbox(
        self,
        sandbox_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[OpSecIdentityRecord], List[OpSecMessageRecord]]:
        """Scans a Session sandbox for identities, public groups (SOGS), and messages."""
        identities: List[OpSecIdentityRecord] = []
        messages: List[OpSecMessageRecord] = []
        base_path = Path(sandbox_path)

        owner_session_id: Optional[str] = None

        # 1. Inspect shared_prefs for owner identity
        prefs_candidates = [
            base_path / "shared_prefs" / "network.loki.messenger_preferences.xml",
            base_path / "shared_prefs" / "com.loki-project.loki-messenger_preferences.xml",
        ]
        for pref_cand in prefs_candidates:
            if pref_cand.exists():
                pinfo = self.parse_preferences(str(pref_cand))
                if pinfo.get("owner_session_id"):
                    owner_session_id = pinfo["owner_session_id"]
                    identities.append(
                        OpSecIdentityRecord(
                            app_platform_name=OpSecPlatformName.SESSION,
                            app_instance_id=app_instance_id,
                            identity_role=IdentityRole.LOCAL_DEVICE_OWNER,
                            primary_crypto_handle=owner_session_id,
                            display_or_nickname="Session Owner",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                        )
                    )
                break

        # 2. Locate database (session.db on Android, Signal.sqlite / Session.sqlite on iOS)
        db_candidates = [
            base_path / "databases" / "session.db",
            base_path / "databases" / "Signal.sqlite",
            base_path / "grdb" / "Signal.sqlite",
            base_path / "grdb" / "Session.sqlite",
            base_path / "session.db",
        ]
        db_path = None
        for cand in db_candidates:
            if cand.exists():
                db_path = cand
                break

        if not db_path:
            return identities, messages

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 2a. Contacts / Recipients
            if "recipient" in tables:
                try:
                    cur.execute("PRAGMA table_info(recipient)")
                    col_names = [r[1] for r in cur.fetchall()]
                    address_col = "address" if "address" in col_names else "phone"
                    sig_name_col = "signal_profile_name" if "signal_profile_name" in col_names else "profile_name"
                    sys_name_col = "system_display_name" if "system_display_name" in col_names else "system_joined_name"

                    q = f"SELECT {address_col}"
                    q += f", {sig_name_col}" if sig_name_col in col_names else ", NULL"
                    q += f", {sys_name_col}" if sys_name_col in col_names else ", NULL"
                    q += " FROM recipient"

                    cur.execute(q)
                    for addr, sig_name, sys_name in cur.fetchall():
                        if addr and is_valid_session_id(str(addr)):
                            dname = sys_name or sig_name
                            # Don't duplicate owner if already inserted
                            if owner_session_id and str(addr) == owner_session_id:
                                continue
                            identities.append(
                                OpSecIdentityRecord(
                                    app_platform_name=OpSecPlatformName.SESSION,
                                    app_instance_id=app_instance_id,
                                    identity_role=IdentityRole.REMOTE_CONTACT,
                                    primary_crypto_handle=str(addr),
                                    display_or_nickname=dname,
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed querying recipient table in Session DB: %s", exc)

            # 2b. Open Groups (SOGS - Session Open Group Server)
            sogs_table = "loki_public_chat_database" if "loki_public_chat_database" in tables else (
                "open_group" if "open_group" in tables else None
            )
            if sogs_table:
                try:
                    cur.execute(f"SELECT server_url, room_token, name FROM {sogs_table}")
                    for s_url, r_tok, r_name in cur.fetchall():
                        identities.append(
                            OpSecIdentityRecord(
                                app_platform_name=OpSecPlatformName.SESSION,
                                app_instance_id=app_instance_id,
                                identity_role=IdentityRole.OPEN_COMMUNITY_SERVER,
                                primary_crypto_handle=r_tok or s_url,
                                display_or_nickname=r_name,
                                server_or_relay_url=s_url,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed querying %s table in Session DB: %s", sogs_table, exc)

            # 2c. Messages (sms, mms, message, interaction)
            msg_table = None
            for cand_tbl in ["sms", "mms", "message", "interaction", "model_TSInteraction"]:
                if cand_tbl in tables:
                    msg_table = cand_tbl
                    break

            if msg_table:
                try:
                    cur.execute(f"PRAGMA table_info({msg_table})")
                    col_names = [r[1] for r in cur.fetchall()]

                    body_col = "body" if "body" in col_names else "text"
                    addr_col = "address" if "address" in col_names else ("from_recipient_id" if "from_recipient_id" in col_names else "sender")
                    date_col = "date" if "date" in col_names else ("date_sent" if "date_sent" in col_names else "timestamp")
                    ttl_col = "expires_in" if "expires_in" in col_names else ("expiresInSeconds" if "expiresInSeconds" in col_names else None)
                    type_col = "type" if "type" in col_names else "recordType"
                    thread_col = "thread_id" if "thread_id" in col_names else ("threadUniqueId" if "threadUniqueId" in col_names else None)

                    q_parts = [
                        f"{col_names[0]}" if col_names else "1",
                        body_col if body_col in col_names else "NULL",
                        addr_col if addr_col in col_names else "NULL",
                        date_col if date_col in col_names else "0",
                        type_col if type_col in col_names else "NULL",
                        ttl_col if ttl_col and ttl_col in col_names else "0",
                        thread_col if thread_col and thread_col in col_names else "1",
                    ]
                    query = f"SELECT {', '.join(q_parts)} FROM {msg_table}"

                    cur.execute(query)
                    for m_id, body_val, sender_val, ts_val, type_val, ttl_val, th_val in cur.fetchall():
                        # Direction check
                        direction = "UNKNOWN"  # no sent/received flag read (X-14)
                        if type_val:
                            if isinstance(type_val, int) and type_val in (2, 23, 87, 88):
                                direction = "OUTGOING_SENT"
                            elif isinstance(type_val, str) and "outgoing" in type_val.lower():
                                direction = "OUTGOING_SENT"

                        ts_ms = int(ts_val) if ts_val else 0
                        # If timestamp is already seconds (10 digits), convert to ms
                        if 0 < ts_ms < 10_000_000_000:
                            ts_ms *= 1000

                        sent_ns = ts_ms * 1_000_000
                        sent_iso = _format_utc_iso_ms(ts_ms)

                        # Handle sender address or fallback to owner if sent
                        sender_str = str(sender_val) if sender_val else (owner_session_id if direction == "OUTGOING_SENT" else None)

                        # Normalize TTL
                        ttl_sec = int(ttl_val) if ttl_val else 0
                        if ttl_sec > 100_000_000:  # ms duration
                            ttl_sec //= 1000

                        rec = OpSecMessageRecord(
                            app_platform_name=OpSecPlatformName.SESSION,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_identifier=str(th_val) if th_val else "1",
                            direction=direction,
                            sender_crypto_handle=sender_str,
                            message_body_text=body_val,
                            ephemeral_ttl_seconds=ttl_sec,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying %s table in Session DB: %s", msg_table, exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Session database %s: %s", db_path, exc)

        return identities, messages
