"""
Sub-Engine 5.1B & 5.1C: WhatsApp Relational Database Decoder & @lid Unmasker.
Parses Android msgstore.db & wa.db, iOS ChatStorage.sqlite & ContactsV2.sqlite,
unmasks @lid privacy identifiers, and extracts normalized message & companion records.
Complies with Section 4 and Section 5 of Phase 5 Module 5.1 Specification.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.whatsapp.models import (
    IdentityType,
    MessageDirection,
    MessageTypeCategory,
    WhatsAppIdentityRecord,
    WhatsAppMessageRecord,
    WhatsAppCompanionDeviceRecord,
)

COCOA_EPOCH_OFFSET = 978307200


def _format_utc_iso(timestamp_ms_or_s: float, is_ms: bool = True) -> str:
    """Formats Unix timestamp (ms or s) into UTC ISO-8601 string."""
    if timestamp_ms_or_s <= 0:
        return ""
    seconds = timestamp_ms_or_s / 1000.0 if is_ms else timestamp_ms_or_s
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def unmask_lid(
    lid_string: str, identity_dict: Dict[str, Tuple[Optional[str], Optional[str]]]
) -> Tuple[Optional[str], Optional[str]]:
    """
    Looks up a privacy @lid string in the identity dictionary.
    Returns (phone_e164, push_or_saved_name).
    """
    clean_lid = lid_string.strip()
    return identity_dict.get(clean_lid, (None, None))


def build_unified_identity_directory(
    msgstore_path: str,
    wa_db_path: Optional[str] = None,
    app_instance_id: int = 1,
) -> List[WhatsAppIdentityRecord]:
    """
    Builds the unified JID <-> LID <-> PushName directory by joining
    msgstore.db (jid, jid_map, lid_display_name) with wa.db (wa_contacts).
    """
    identities: List[WhatsAppIdentityRecord] = []
    if not os.path.exists(msgstore_path):
        return identities

    conn_m = sqlite3.connect(msgstore_path)
    cur_m = conn_m.cursor()

    # Check tables in msgstore.db
    cur_m.execute("SELECT name FROM sqlite_master WHERE type='table'")
    m_tables = {row[0] for row in cur_m.fetchall()}

    jid_map_lid_to_jid_id: Dict[int, int] = {}
    if "jid_map" in m_tables:
        try:
            cur_m.execute("SELECT lid_row_id, jid_row_id FROM jid_map")
            for lid_id, jid_id in cur_m.fetchall():
                jid_map_lid_to_jid_id[lid_id] = jid_id
        except Exception as exc:
            logger.debug("Failed querying jid_map: %s", exc)

    lid_display_names: Dict[int, str] = {}
    if "lid_display_name" in m_tables:
        try:
            cur_m.execute("SELECT lid_row_id, display_name FROM lid_display_name")
            for lid_id, name in cur_m.fetchall():
                if name:
                    lid_display_names[lid_id] = name
        except Exception as exc:
            logger.debug("Failed querying lid_display_name: %s", exc)

    # Read wa.db wa_contacts if provided or adjacent
    wa_contacts_by_jid: Dict[str, Dict[str, str]] = {}
    wa_contacts_by_lid: Dict[str, Dict[str, str]] = {}

    target_wa_db = wa_db_path
    if not target_wa_db or not os.path.exists(target_wa_db):
        cand = Path(msgstore_path).parent / "wa.db"
        if cand.exists():
            target_wa_db = str(cand)

    if target_wa_db and os.path.exists(target_wa_db):
        try:
            conn_w = sqlite3.connect(target_wa_db)
            cur_w = conn_w.cursor()
            cur_w.execute("SELECT name FROM sqlite_master WHERE type='table'")
            w_tables = {row[0] for row in cur_w.fetchall()}
            if "wa_contacts" in w_tables:
                cur_w.execute(
                    "SELECT jid, lid, display_name, wa_name, number, status FROM wa_contacts"
                )
                for jid_val, lid_val, d_name, w_name, num, st in cur_w.fetchall():
                    data = {
                        "jid": jid_val or "",
                        "lid": lid_val or "",
                        "display_name": d_name or "",
                        "wa_name": w_name or "",
                        "number": num or "",
                        "status": st or "",
                    }
                    if jid_val:
                        wa_contacts_by_jid[jid_val] = data
                    if lid_val:
                        wa_contacts_by_lid[lid_val] = data
            conn_w.close()
        except Exception as exc:
            logger.debug("Failed reading wa_contacts: %s", exc)

    # Read jid table from msgstore.db
    if "jid" in m_tables:
        cur_m.execute("SELECT _id, user, server, raw_string FROM jid")
        jid_rows = cur_m.fetchall()
        jid_id_to_row = {r[0]: r for r in jid_rows}

        for jid_id, user, server, raw_string in jid_rows:
            server_clean = server.lower()
            if server_clean == "g.us":
                ident_type = IdentityType.GROUP_CHAT
            elif server_clean == "newsletter":
                ident_type = IdentityType.NEWSLETTER_CHANNEL
            elif server_clean == "broadcast":
                ident_type = IdentityType.BROADCAST_STATUS
            else:
                ident_type = IdentityType.USER

            phone_jid = None
            linked_lid = None
            phone_e164 = None
            d_name = None
            push_name = None
            about = None

            if server_clean == "s.whatsapp.net":
                phone_jid = raw_string
                phone_digits = "".join(ch for ch in user if ch.isdigit())
                phone_e164 = f"+{phone_digits}" if phone_digits else None
                c_info = wa_contacts_by_jid.get(raw_string)
                if c_info:
                    linked_lid = None
                    d_name = c_info.get("display_name") or None
                    push_name = c_info.get("wa_name") or None
                    about = c_info.get("status") or None

            elif server_clean == "lid":
                linked_lid = raw_string
                # Map to phone JID via jid_map or wa_contacts
                mapped_jid_id = jid_map_lid_to_jid_id.get(jid_id)
                if mapped_jid_id and mapped_jid_id in jid_id_to_row:
                    target_row = jid_id_to_row[mapped_jid_id]
                    phone_jid = target_row[3]
                    phone_digits = "".join(ch for ch in target_row[1] if ch.isdigit())
                    phone_e164 = f"+{phone_digits}" if phone_digits else None

                c_info = wa_contacts_by_lid.get(raw_string)
                if not c_info and phone_jid:
                    c_info = wa_contacts_by_jid.get(phone_jid)

                if c_info:
                    if not phone_jid and c_info.get("jid"):
                        phone_jid = c_info["jid"]
                    if not phone_e164 and c_info.get("number"):
                        phone_digits = "".join(ch for ch in c_info["number"] if ch.isdigit())
                        phone_e164 = f"+{phone_digits}" if phone_digits else None
                    d_name = c_info.get("display_name") or None
                    push_name = c_info.get("wa_name") or None
                    about = c_info.get("status") or None

                if not d_name and jid_id in lid_display_names:
                    d_name = lid_display_names[jid_id]

            rec = WhatsAppIdentityRecord(
                app_instance_id=app_instance_id,
                jid_row_id=jid_id,
                phone_jid_string=phone_jid,
                linked_lid_string=linked_lid,
                extracted_phone_e164=phone_e164,
                address_book_display_name=d_name,
                remote_profile_push_name=push_name,
                status_about_text=about,
                identity_type=ident_type,
            )
            identities.append(rec)

    conn_m.close()
    return identities


class WhatsAppDatabaseDecoder:
    """Master decoder for Android and iOS WhatsApp relational databases."""

    def __init__(self) -> None:
        self.cached_identities: List[WhatsAppIdentityRecord] = []

    def extract_identities(
        self,
        msgstore_path: str,
        wa_db_path: Optional[str] = None,
        app_instance_id: int = 1,
    ) -> List[WhatsAppIdentityRecord]:
        """Extracts and unmasks all identities into unified identity records."""
        records = build_unified_identity_directory(
            msgstore_path=msgstore_path,
            wa_db_path=wa_db_path,
            app_instance_id=app_instance_id,
        )
        self.cached_identities = records
        return records

    def extract_messages(
        self,
        msgstore_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> List[WhatsAppMessageRecord]:
        """
        Extracts all messages from an Android msgstore.db or iOS ChatStorage.sqlite database.
        Resolves @lid senders, quoted replies, media metadata, and message categories.
        """
        messages: List[WhatsAppMessageRecord] = []
        if not os.path.exists(msgstore_path):
            return messages

        conn = sqlite3.connect(msgstore_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        # -------------------------------------------------------------------
        # CASE 1: Android msgstore.db (message + jid + chat)
        # -------------------------------------------------------------------
        if "message" in tables and "jid" in tables:
            # Build identities if not already cached
            if not self.cached_identities:
                self.extract_identities(msgstore_path=msgstore_path, app_instance_id=app_instance_id)

            # Build fast lookups
            jid_lookup: Dict[int, Tuple[str, str, str]] = {}
            cur.execute("SELECT _id, user, server, raw_string FROM jid")
            for j_id, u, s, raw in cur.fetchall():
                jid_lookup[j_id] = (raw, u, s)

            chat_lookup: Dict[int, Tuple[str, Optional[str]]] = {}
            if "chat" in tables:
                cur.execute("SELECT _id, jid_row_id, subject FROM chat")
                for c_id, j_row, subj in cur.fetchall():
                    c_jid = jid_lookup.get(j_row, ("", "", ""))[0]
                    chat_lookup[c_id] = (c_jid, subj)

            # Pre-load satellite tables into memory dictionaries
            quoted_dict: Dict[int, Tuple[str, Optional[int], Optional[str]]] = {}
            if "message_quoted" in tables:
                try:
                    cur.execute("SELECT message_row_id, key_id, sender_jid_row_id, text_data FROM message_quoted")
                    for m_id, q_key, q_sender, q_text in cur.fetchall():
                        quoted_dict[m_id] = (q_key, q_sender, q_text)
                except Exception as exc:
                    logger.debug("Failed reading message_quoted: %s", exc)

            forwarded_dict: Dict[int, int] = {}
            if "message_forwarded" in tables:
                try:
                    cur.execute("SELECT message_row_id, forwarding_score FROM message_forwarded")
                    for m_id, score in cur.fetchall():
                        forwarded_dict[m_id] = score
                except Exception as exc:
                    logger.debug("Failed reading message_forwarded: %s", exc)

            ephemeral_dict: Dict[int, int] = {}
            if "message_ephemeral" in tables:
                try:
                    cur.execute("SELECT message_row_id, duration FROM message_ephemeral")
                    for m_id, dur in cur.fetchall():
                        ephemeral_dict[m_id] = dur
                except Exception as exc:
                    logger.debug("Failed reading message_ephemeral: %s", exc)

            media_dict: Dict[int, dict] = {}
            if "message_media" in tables:
                try:
                    cur.execute("SELECT message_row_id, file_path, file_size, mime_type, file_hash, width, height, media_duration FROM message_media")
                    for m_id, fp, fs, mt, fh, w, h, md in cur.fetchall():
                        media_dict[m_id] = {
                            "file_path": fp,
                            "file_size": fs,
                            "mime_type": mt,
                            "file_hash_sha256_b64": fh,
                            "width": w,
                            "height": h,
                            "media_duration": md,
                        }
                except Exception as exc:
                    logger.debug("Failed reading message_media: %s", exc)

            location_dict: Dict[int, dict] = {}
            if "message_location" in tables:
                try:
                    cur.execute("SELECT message_row_id, latitude, longitude, place_name, place_address, url, live_location_share_duration FROM message_location")
                    for m_id, lat, lon, pn, pa, u, lsd in cur.fetchall():
                        location_dict[m_id] = {
                            "latitude": lat,
                            "longitude": lon,
                            "place_name": pn,
                            "place_address": pa,
                            "url": u,
                            "live_duration": lsd,
                        }
                except Exception as exc:
                    logger.debug("Failed reading message_location: %s", exc)

            reactions_dict: Dict[int, list] = {}
            if "message_add_on_reaction" in tables:
                try:
                    cur.execute("SELECT message_row_id, reaction, sender_jid_row_id, timestamp FROM message_add_on_reaction")
                    for m_id, r_txt, s_jid_id, r_ts in cur.fetchall():
                        s_raw = jid_lookup.get(s_jid_id, ("", "", ""))[0]
                        reactions_dict.setdefault(m_id, []).append({
                            "emoji": r_txt,
                            "sender": s_raw,
                            "timestamp": r_ts,
                        })
                except Exception as exc:
                    logger.debug("Failed reading message_add_on_reaction: %s", exc)

            receipts_dict: Dict[int, Tuple[Optional[str], Optional[str]]] = {}
            if "receipt_user" in tables:
                try:
                    cur.execute("SELECT message_row_id, receipt_timestamp, read_timestamp FROM receipt_user")
                    for m_id, rec_ts, read_ts in cur.fetchall():
                        receipts_dict[m_id] = (
                            _format_utc_iso(rec_ts) if rec_ts else None,
                            _format_utc_iso(read_ts) if read_ts else None,
                        )
                except Exception as exc:
                    logger.debug("Failed reading receipt_user: %s", exc)

            # Map identity lookups: jid_row_id -> identity, raw_lid -> identity, raw_jid -> identity
            id_by_row = {i.jid_row_id: i for i in self.cached_identities if i.jid_row_id is not None}
            id_by_lid = {i.linked_lid_string: i for i in self.cached_identities if i.linked_lid_string}
            id_by_jid = {i.phone_jid_string: i for i in self.cached_identities if i.phone_jid_string}

            # Query core message table
            cur.execute("""
                SELECT _id, chat_row_id, from_me, key_id, sender_jid_row_id,
                       status, timestamp, received_timestamp, message_type, text_data
                FROM message
            """)
            for (
                m_id, chat_row, from_me, key_id, sender_row,
                status, ts, rec_ts, m_type, text_data
            ) in cur.fetchall():
                chat_info = chat_lookup.get(chat_row, ("", None))
                chat_jid = chat_info[0]
                chat_title = chat_info[1]

                direction = (MessageDirection.OUTGOING_SENT if from_me == 1
                             else MessageDirection.INCOMING_RECEIVED if from_me == 0 else MessageDirection.UNKNOWN)

                # Resolve sender
                resolved_phone_jid = None
                raw_lid = None
                push_and_saved_name = None

                effective_sender_row = sender_row if (sender_row and sender_row > 0) else None
                if direction == MessageDirection.INCOMING_RECEIVED:
                    if effective_sender_row and effective_sender_row in jid_lookup:
                        s_raw, s_user, s_server = jid_lookup[effective_sender_row]
                        if s_server.lower() == "lid":
                            raw_lid = s_raw
                        ident = id_by_row.get(effective_sender_row) or id_by_lid.get(s_raw) or id_by_jid.get(s_raw)
                        if ident:
                            resolved_phone_jid = ident.extracted_phone_e164 or ident.phone_jid_string
                            raw_lid = raw_lid or ident.linked_lid_string
                            names = []
                            if ident.address_book_display_name:
                                names.append(ident.address_book_display_name)
                            if ident.remote_profile_push_name:
                                names.append(f"({ident.remote_profile_push_name})")
                            push_and_saved_name = " ".join(names) if names else None
                        else:
                            if s_server.lower() == "s.whatsapp.net":
                                digits = "".join(c for c in s_user if c.isdigit())
                                resolved_phone_jid = f"+{digits}" if digits else s_raw
                    else:
                        # 1-on-1 incoming message: chat JID is counterparty
                        ident = id_by_jid.get(chat_jid)
                        if ident:
                            resolved_phone_jid = ident.extracted_phone_e164 or ident.phone_jid_string
                            raw_lid = ident.linked_lid_string
                            names = []
                            if ident.address_book_display_name:
                                names.append(ident.address_book_display_name)
                            if ident.remote_profile_push_name:
                                names.append(f"({ident.remote_profile_push_name})")
                            push_and_saved_name = " ".join(names) if names else None
                        elif "@s.whatsapp.net" in chat_jid:
                            digits = "".join(c for c in chat_jid.split("@")[0] if c.isdigit())
                            resolved_phone_jid = f"+{digits}" if digits else chat_jid

                # Map message_type integer to category
                is_revoked = 0
                if m_type in (11, 15, 64):
                    category = MessageTypeCategory.REVOKED_DELETED_FOR_EVERYONE
                    is_revoked = 1
                elif m_type == 1:
                    category = MessageTypeCategory.IMAGE
                elif m_type == 2:
                    category = MessageTypeCategory.VOICE_NOTE
                elif m_type == 3:
                    category = MessageTypeCategory.VIDEO
                elif m_type in (4, 14):
                    category = MessageTypeCategory.VCARD
                elif m_type == 5:
                    category = MessageTypeCategory.LOCATION_STATIC
                elif m_type == 9:
                    category = MessageTypeCategory.DOCUMENT
                elif m_type == 16:
                    category = MessageTypeCategory.LOCATION_LIVE
                elif m_type == 42:
                    category = MessageTypeCategory.VIEW_ONCE_IMAGE
                elif m_type == 43:
                    category = MessageTypeCategory.VIEW_ONCE_VIDEO
                elif m_type == 66:
                    category = MessageTypeCategory.POLL
                elif m_type == 82:
                    category = MessageTypeCategory.VIEW_ONCE_AUDIO
                else:
                    category = MessageTypeCategory.TEXT

                # Satellite data
                q_info = quoted_dict.get(m_id)
                quoted_key = q_info[0] if q_info else None
                quoted_text = q_info[2] if q_info else None

                f_score = forwarded_dict.get(m_id, 0)
                e_dur = ephemeral_dict.get(m_id, 0)

                m_meta = media_dict.get(m_id) or location_dict.get(m_id)
                media_json = json.dumps(m_meta) if m_meta else None

                reacts = reactions_dict.get(m_id)
                reacts_json = json.dumps(reacts) if reacts else None

                rec_delivery, rec_read = receipts_dict.get(m_id, (None, None))

                sent_ns = ts * 1_000_000
                sent_iso = _format_utc_iso(ts)

                rec = WhatsAppMessageRecord(
                    app_instance_id=app_instance_id,
                    source_vfs_file_id=source_vfs_file_id,
                    chat_jid=chat_jid,
                    chat_display_title=chat_title,
                    message_key_id=key_id,
                    sent_utc_ns=sent_ns,
                    sent_utc_iso=sent_iso,
                    direction=direction,
                    sender_resolved_phone_jid=resolved_phone_jid,
                    sender_raw_lid=raw_lid,
                    sender_push_and_saved_name=push_and_saved_name,
                    message_type_category=category,
                    message_text_or_caption=text_data,
                    is_revoked_deleted_for_everyone=is_revoked,
                    quoted_parent_key_id=quoted_key,
                    quoted_parent_text_preview=quoted_text,
                    forwarding_hop_score=f_score,
                    ephemeral_timer_seconds=e_dur,
                    media_metadata_json=media_json,
                    reactions_json=reacts_json,
                    delivered_utc_iso=rec_delivery,
                    read_blue_tick_utc_iso=rec_read,
                )
                messages.append(rec)

        # -------------------------------------------------------------------
        # CASE 2: iOS ChatStorage.sqlite (ZWAMESSAGE + ZWACHATSESSION)
        # -------------------------------------------------------------------
        elif "ZWAMESSAGE" in tables and "ZWACHATSESSION" in tables:
            push_names_ios: Dict[str, str] = {}
            if "ZWAPROFILEPUSHNAME" in tables:
                try:
                    cur.execute("SELECT ZJID, ZPUSHNAME FROM ZWAPROFILEPUSHNAME")
                    for z_jid, p_name in cur.fetchall():
                        if z_jid and p_name:
                            push_names_ios[z_jid] = p_name
                except Exception as exc:
                    logger.debug("Failed reading ZWAPROFILEPUSHNAME: %s", exc)

            chat_sessions_ios: Dict[int, Tuple[str, Optional[str]]] = {}
            cur.execute("SELECT Z_PK, ZCONTACTJID, ZPARTNERNAME FROM ZWACHATSESSION")
            for z_pk, c_jid, p_name in cur.fetchall():
                chat_sessions_ios[z_pk] = (c_jid or "", p_name)

            cur.execute("""
                SELECT Z_PK, ZCHATSESSION, ZISFROMME, ZFROMJID, ZTOJID,
                       ZMESSAGEDATE, ZTEXT, ZMESSAGETYPE, ZSTANZAID
                FROM ZWAMESSAGE
            """)
            for (
                z_pk, z_session, is_from_me, from_jid, to_jid,
                msg_date, z_text, msg_type, stanza_id
            ) in cur.fetchall():
                c_jid, p_name = chat_sessions_ios.get(z_session, ("", None))
                direction = (MessageDirection.OUTGOING_SENT if is_from_me == 1
                             else MessageDirection.INCOMING_RECEIVED if is_from_me == 0 else MessageDirection.UNKNOWN)

                # Convert Cocoa timestamp to Unix ms
                unix_sec = (msg_date + COCOA_EPOCH_OFFSET) if msg_date else 0.0
                sent_ns = int(unix_sec * 1_000_000_000)
                sent_iso = _format_utc_iso(unix_sec, is_ms=False)

                key_id = stanza_id or f"IOS_{z_pk}"
                is_revoked = 1 if msg_type == 14 else 0
                cat = MessageTypeCategory.REVOKED_DELETED_FOR_EVERYONE if is_revoked else MessageTypeCategory.TEXT

                sender_phone = None
                push_name = None
                if from_jid:
                    push_name = push_names_ios.get(from_jid)
                    digits = "".join(c for c in from_jid.split("@")[0] if c.isdigit())
                    sender_phone = f"+{digits}" if digits else from_jid

                rec = WhatsAppMessageRecord(
                    app_instance_id=app_instance_id,
                    source_vfs_file_id=source_vfs_file_id,
                    chat_jid=c_jid,
                    chat_display_title=p_name,
                    message_key_id=key_id,
                    sent_utc_ns=sent_ns,
                    sent_utc_iso=sent_iso,
                    direction=direction,
                    sender_resolved_phone_jid=sender_phone,
                    sender_push_and_saved_name=push_name,
                    message_type_category=cat,
                    message_text_or_caption=z_text,
                    is_revoked_deleted_for_everyone=is_revoked,
                )
                messages.append(rec)

        conn.close()
        return messages

    def extract_companion_devices(
        self, db_path: str, app_instance_id: int = 1
    ) -> List[WhatsAppCompanionDeviceRecord]:
        """Audits linked companion devices (WhatsApp Web / Desktop / Companion phone)."""
        companions: List[WhatsAppCompanionDeviceRecord] = []
        if not os.path.exists(db_path):
            return companions

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}

        if "companion_devices" in tables:
            try:
                cur.execute(
                    "SELECT device_id, device_os, platform_type, login_time, last_active, logout_time FROM companion_devices"
                )
                for dev_id, dev_os, plat, l_time, la_time, lo_time in cur.fetchall():
                    # Format timestamps (handle ms vs s)
                    login_iso = None
                    if l_time:
                        login_iso = _format_utc_iso(l_time, is_ms=(l_time > 10_000_000_000))

                    last_active_iso = None
                    if la_time:
                        last_active_iso = _format_utc_iso(la_time, is_ms=(la_time > 10_000_000_000))

                    rec = WhatsAppCompanionDeviceRecord(
                        app_instance_id=app_instance_id,
                        companion_device_jid=dev_id or "",
                        companion_os_and_browser=dev_os or f"Platform {plat}",
                        paired_login_utc_iso=login_iso,
                        last_active_utc_iso=last_active_iso,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    )
                    companions.append(rec)
            except Exception as exc:
                logger.debug("Failed extracting companion devices: %s", exc)

        conn.close()
        return companions
