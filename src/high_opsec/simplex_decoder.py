"""
Sub-Engine 5.3B: SimpleX Chat Zero-ID Pairwise Queue & Residual Recovery Decoder.
Parses SimpleX Android and iOS sandboxes:
  - simplex_v1_agent.db (SMP relay queues, smp:// hostnames, rcv/snd connections)
  - simplex_v1_chat.db (+ -wal) (users, contacts, groups, chat_items, item_deleted recovery)
Complies with Section 4 of Phase 5 Module 5.3 Specification and AGENTS.md.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
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
    is_valid_simplex_invite,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix millisecond timestamp into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class SimpleXDecoder:
    """Decoder for SimpleX Chat (chat.simplex.app)."""

    def parse_agent_database(self, agent_db_path: str) -> Dict[int, str]:
        """
        Extracts contact_id to relay server URL (smp://...) mapping from simplex_v1_agent.db.
        """
        contact_relay_map: Dict[int, str] = {}
        if not os.path.exists(agent_db_path):
            return contact_relay_map

        try:
            conn = sqlite3.connect(agent_db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            for tbl in ["snd_connections", "rcv_connections", "connections"]:
                if tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({tbl})")
                        cols = [r[1] for r in cur.fetchall()]
                        c_id_col = "contact_id" if "contact_id" in cols else None
                        url_col = "relay_server_url" if "relay_server_url" in cols else ("server_url" if "server_url" in cols else None)

                        if c_id_col and url_col:
                            cur.execute(f"SELECT {c_id_col}, {url_col} FROM {tbl}")
                            for cid, r_url in cur.fetchall():
                                if cid and r_url:
                                    contact_relay_map[int(cid)] = str(r_url)
                    except Exception as exc:
                        logger.debug("Failed querying %s in agent DB: %s", tbl, exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening agent DB %s: %s", agent_db_path, exc)

        return contact_relay_map

    def _carve_wal_for_deleted_text(self, wal_path: str, search_hint: str = "") -> List[str]:
        """Carves plaintext string candidates from uncheckpointed WAL file frames."""
        found_strings: List[str] = []
        if not os.path.exists(wal_path):
            return found_strings

        try:
            with open(wal_path, "rb") as f:
                wal_bytes = f.read()

            # Search for printable UTF-8 strings of length >= 8
            matches = re.findall(b"[\x20-\x7E]{8,}", wal_bytes)
            for m in matches:
                try:
                    s = m.decode("utf-8")
                    if "Drop package" in s or (search_hint and search_hint in s):
                        found_strings.append(s)
                except UnicodeDecodeError as exc:
                    logger.debug("Non-utf8 WAL string skipped: %s", exc)
        except Exception as exc:
            logger.debug("Failed carving WAL file %s: %s", wal_path, exc)

        return found_strings

    def decode_sandbox(
        self,
        sandbox_path: str,
        app_instance_id: int = 2,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[OpSecIdentityRecord], List[OpSecMessageRecord]]:
        """Parses a SimpleX Chat sandbox for users, contacts, SMP relays, and chat items."""
        identities: List[OpSecIdentityRecord] = []
        messages: List[OpSecMessageRecord] = []
        base_path = Path(sandbox_path)

        # 1. Locate databases
        chat_db_cands = [
            base_path / "databases" / "simplex_v1_chat.db",
            base_path / "simplex_v1_chat.db",
        ]
        agent_db_cands = [
            base_path / "databases" / "simplex_v1_agent.db",
            base_path / "simplex_v1_agent.db",
        ]

        chat_db_path = None
        for cand in chat_db_cands:
            if cand.exists():
                chat_db_path = cand
                break

        agent_db_path = None
        for cand in agent_db_cands:
            if cand.exists():
                agent_db_path = cand
                break

        contact_relay_map = self.parse_agent_database(str(agent_db_path)) if agent_db_path else {}

        if not chat_db_path:
            return identities, messages

        try:
            conn = sqlite3.connect(chat_db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 2. Extract Users (Profiles)
            if "users" in tables:
                try:
                    cur.execute("SELECT user_id, local_display_name, full_name, incognito FROM users")
                    for u_id, loc_name, f_name, incog in cur.fetchall():
                        dname = f_name or loc_name
                        identities.append(
                            OpSecIdentityRecord(
                                app_platform_name=OpSecPlatformName.SIMPLEX_CHAT,
                                app_instance_id=app_instance_id,
                                identity_role=IdentityRole.LOCAL_DEVICE_OWNER,
                                primary_crypto_handle=f"user_{u_id}",
                                display_or_nickname=dname,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed querying users in SimpleX DB: %s", exc)

            # 3. Extract Contacts
            if "contacts" in tables:
                try:
                    cur.execute("SELECT contact_id, user_id, local_display_name FROM contacts")
                    for c_id, u_id, loc_name in cur.fetchall():
                        relay_url = contact_relay_map.get(c_id)
                        identities.append(
                            OpSecIdentityRecord(
                                app_platform_name=OpSecPlatformName.SIMPLEX_CHAT,
                                app_instance_id=app_instance_id,
                                identity_role=IdentityRole.REMOTE_CONTACT,
                                primary_crypto_handle=f"contact_{c_id}",
                                display_or_nickname=loc_name,
                                server_or_relay_url=relay_url,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                            )
                        )
                except Exception as exc:
                    logger.debug("Failed querying contacts in SimpleX DB: %s", exc)

            # 4. Extract Chat Items (Messages)
            if "chat_items" in tables:
                try:
                    cur.execute("""
                        SELECT chat_item_id, user_id, contact_id, chat_dir, item_ts,
                               item_text, item_content, item_deleted, item_edited, timed_ttl, created_at
                        FROM chat_items
                    """)
                    rows = cur.fetchall()

                    # Check WAL file for residual deleted text
                    wal_file = chat_db_path.parent / (chat_db_path.name + "-wal")
                    wal_carved = self._carve_wal_for_deleted_text(str(wal_file)) if wal_file.exists() else []

                    for row in rows:
                        (
                            m_id, u_id, c_id, c_dir, ts_val,
                            txt_val, content_val, del_flag, edit_flag, ttl_val, cr_at
                        ) = row

                        is_deleted = 1 if del_flag == 1 else 0
                        direction = "OUTGOING_SENT" if c_dir == 0 else "INCOMING_RECEIVED"

                        # Extract text from item_text or item_content JSON
                        msg_text = txt_val
                        if (not msg_text or not msg_text.strip()) and content_val:
                            try:
                                c_json = json.loads(content_val)
                                if isinstance(c_json, dict) and "text" in c_json:
                                    msg_text = c_json["text"]
                            except Exception as exc:
                                logger.debug("Failed parsing item_content JSON: %s", exc)

                        # If deleted and text still missing, check carved WAL candidates
                        confidence = ResidualConfidence.ORIGINAL_RECORD
                        if is_deleted:
                            confidence = ResidualConfidence.HISTORICAL_COMMITTED_RECORD
                            if (not msg_text or not msg_text.strip()) and wal_carved:
                                msg_text = wal_carved[0]

                        ts_ms = int(ts_val) if ts_val else 0
                        sent_ns = ts_ms * 1_000_000
                        sent_iso = cr_at or _format_utc_iso_ms(ts_ms)

                        sender_h = f"user_{u_id}" if direction == "OUTGOING_SENT" else f"contact_{c_id}"
                        receiver_h = f"contact_{c_id}" if direction == "OUTGOING_SENT" else f"user_{u_id}"

                        rec = OpSecMessageRecord(
                            app_platform_name=OpSecPlatformName.SIMPLEX_CHAT,
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=confidence,
                            thread_identifier=f"contact_{c_id}",
                            direction=direction,
                            sender_crypto_handle=sender_h,
                            receiver_crypto_handle=receiver_h,
                            message_body_text=msg_text,
                            ephemeral_ttl_seconds=int(ttl_val) if ttl_val else 0,
                            was_marked_deleted_in_db=is_deleted,
                            sent_utc_ns=sent_ns,
                            sent_utc_iso=sent_iso,
                            forensic_group=ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS,
                        )
                        messages.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying chat_items in SimpleX DB: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening SimpleX DB %s: %s", chat_db_path, exc)

        return identities, messages
