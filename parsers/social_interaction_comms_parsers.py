"""
Bharat-PA Forensics — Social, Interaction, and Cross-Border Communication App Parsers.
Additive forensic engine covering 15+ modern messaging, social networking, cybercrime,
and Indian market interaction platforms conforming strictly to the 28-column Categorized Schema.

Supported Platforms:
1. Facebook & Facebook Messenger (Legacy threads_db2, Msys/Armadillo E2EE, and contacts_db2)
2. Discord (SQLite Room discord.db, kv_storage, LevelDB / HTTP disk caches)
3. Skype & Microsoft Teams (main.db, s4l-*.db, Teams SQLite caches)
4. Viber, WeChat, LINE, IMO & KakaoTalk (Cross-border syndicate messengers)
5. X (Twitter) DMs, Threads, Reddit Chat & LinkedIn (voyager.db)
6. Indian Cybercrime Interaction Apps:
   - Truecaller (msg.db, tc.db, spam/fraud identity caller tags)
   - OLX India (olx_chat.db, buyer/seller lures, UPI QR payment requests)
   - ShareChat & Moj (chatroom and DM SQLite tables)
"""

from __future__ import annotations
from src.core.sqlite_uri import ro_uri

import binascii
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from parsers import is_safe_sqlite_table_name, quote_sqlite_identifier
from parsers.chat_social_privacy_parsers import (
    CATEGORIZED_FORENSIC_COLUMNS,
    make_categorized_dataframe,
    normalize_iso_ist,
)

logger = logging.getLogger(__name__)
IST = timezone(timedelta(hours=5, minutes=30))


def _safe_str(val: Any) -> str:
    """Returns safe string without raw Python repr prefixes."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(val).strip()


def _extract_json_safe(val: Any) -> Optional[Union[Dict[str, Any], List[Any]]]:
    """Safely extracts JSON object or array from str/bytes."""
    if val is None:
        return None
    s = _safe_str(val)
    if not s or not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _clean_xml_text(text: str) -> str:
    """Strips XML/HTML tags from Skype/Teams message payloads."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


# ==============================================================================
# 1. FACEBOOK & FACEBOOK MESSENGER PARSER
# ==============================================================================

def parse_facebook_messenger_database(
    db_path: str,
    owner_identifiers: Optional[List[str]] = None,
) -> pd.DataFrame:
    """
    Parses Facebook Messenger databases:
    - Legacy & standard Android/iOS: threads_db2 (messages + threads + thread_participants)
    - Modern Msys / Armadillo E2EE: msys_database_*.db, reverb.db, crypto_mailbox.db
    """
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    file_size = os.path.getsize(db_path)

    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Discover tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r["name"] for r in cur.fetchall()]
        tables_low = {t.lower(): t for t in tables}

        # ----------------------------------------------------------------------
        # A. Legacy / Standard threads_db2
        # ----------------------------------------------------------------------
        if "messages" in tables_low and ("threads" in tables_low or "thread_participants" in tables_low):
            msg_tbl = tables_low["messages"]
            thread_tbl = tables_low.get("threads")

            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(msg_tbl)});")
            m_cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            # Build query
            id_col = m_cols.get("msg_id", m_cols.get("message_id", "rowid"))
            thread_col = m_cols.get("thread_key", m_cols.get("thread_id", "''"))
            text_col = m_cols.get("text", m_cols.get("body", "''"))
            sender_col = m_cols.get("sender", "''")
            ts_col = m_cols.get("timestamp_ms", m_cols.get("timestamp", m_cols.get("timestamp_sent_ms", "0")))
            type_col = m_cols.get("msg_type", m_cols.get("message_type", "''"))
            unsent_col = m_cols.get("is_unsent", m_cols.get("is_deleted", "0"))
            attach_col = m_cols.get("attachments", "''")
            shares_col = m_cols.get("shares", "''")

            query = f"""
                SELECT
                    rowid AS _rowid,
                    {quote_sqlite_identifier(id_col)} AS _msg_id,
                    {quote_sqlite_identifier(thread_col)} AS _thread_key,
                    {quote_sqlite_identifier(text_col)} AS _text,
                    {quote_sqlite_identifier(sender_col)} AS _sender,
                    {quote_sqlite_identifier(ts_col)} AS _ts,
                    {quote_sqlite_identifier(type_col)} AS _type,
                    {quote_sqlite_identifier(unsent_col)} AS _unsent,
                    {quote_sqlite_identifier(attach_col)} AS _attachments,
                    {quote_sqlite_identifier(shares_col)} AS _shares
                FROM {quote_sqlite_identifier(msg_tbl)}
                ORDER BY {quote_sqlite_identifier(ts_col)} ASC
            """
            cur.execute(query)
            for row in cur.fetchall():
                raw_text = _safe_str(row["_text"])
                sender_raw = _safe_str(row["_sender"])
                sender_id = ""
                sender_name = ""
                is_from_me = False

                # Parse JSON sender object: {"user_key":"FACEBOOK:1000...","name":"Rajesh"}
                s_json = _extract_json_safe(sender_raw)
                if isinstance(s_json, dict):
                    sender_id = _safe_str(s_json.get("user_key", s_json.get("id", "")))
                    sender_name = _safe_str(s_json.get("name", ""))
                elif sender_raw:
                    sender_id = sender_raw
                    sender_name = sender_raw

                if owner_identifiers:
                    for oid in owner_identifiers:
                        if oid and oid in sender_id:
                            is_from_me = True
                            break

                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(row["_ts"], "auto")
                is_unsent = bool(row["_unsent"] and int(row["_unsent"]) == 1)

                # Check attachments or shares
                attach_raw = _safe_str(row["_attachments"])
                attach_path = ""
                attach_mime = ""
                if attach_raw:
                    att_json = _extract_json_safe(attach_raw)
                    if isinstance(att_json, list) and len(att_json) > 0:
                        first = att_json[0]
                        if isinstance(first, dict):
                            attach_path = _safe_str(first.get("filename", first.get("src", first.get("id", ""))))
                            attach_mime = _safe_str(first.get("mime_type", first.get("type", "")))

                records.append({
                    "Artifact_ID": f"FB_MSG_{row['_msg_id'] or row['_rowid']}",
                    "Source_App": "Facebook Messenger",
                    "Chat_Type": "1-on-1" if "GROUP" not in str(row["_thread_key"]).upper() else "Group",
                    "Thread_ID": _safe_str(row["_thread_key"]),
                    "Thread_Title": _safe_str(row["_thread_key"]),
                    "Message_Text": raw_text or ("[Media Attachment]" if attach_path else ""),
                    "Message_Type": "UNSENT" if is_unsent else (_safe_str(row["_type"]) or "Text"),
                    "Direction": "Outgoing" if is_from_me else "Incoming",
                    "Status": "Unsent / Recalled" if is_unsent else "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": sender_id,
                    "Sender_Name": sender_name,
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": is_unsent,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": is_unsent,
                    "Timestamp_Raw": _safe_str(row["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": attach_path,
                    "Attachment_MIME": attach_mime,
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": msg_tbl,
                    "Row_ID": row["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "ACTIVE_SQLITE (unsent flag set)" if is_unsent else "ACTIVE_SQLITE",
                })

        # ----------------------------------------------------------------------
        # B. Modern Messenger Msys / Armadillo E2EE
        # ----------------------------------------------------------------------
        msys_msg_candidates = [t for t in tables if any(k in t.lower() for k in ["cql_messages", "msys_messages", "armadillo_messages"])]
        if not msys_msg_candidates and "messages" in tables_low:
            # Check if Msys table columns exist
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(tables_low['messages'])});")
            cols = [r["name"].lower() for r in cur.fetchall()]
            if "message_id" in cols and ("thread_key" in cols or "thread_pk" in cols):
                msys_msg_candidates.append(tables_low["messages"])

        for tname in msys_msg_candidates:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(tname)});")
            col_map = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            id_col = col_map.get("message_id", col_map.get("id", "rowid"))
            thread_col = col_map.get("thread_key", col_map.get("thread_pk", "''"))
            text_col = col_map.get("text", col_map.get("snippet", "''"))
            sender_col = col_map.get("sender_id", col_map.get("sender_pk", "''"))
            ts_col = col_map.get("timestamp_ms", col_map.get("timestamp", "0"))
            unsent_col = col_map.get("is_unsent", col_map.get("unsent", "0"))

            q = f"""
                SELECT
                    rowid AS _rowid,
                    {quote_sqlite_identifier(id_col)} AS _id,
                    {quote_sqlite_identifier(thread_col)} AS _thread,
                    {quote_sqlite_identifier(text_col)} AS _text,
                    {quote_sqlite_identifier(sender_col)} AS _sender,
                    {quote_sqlite_identifier(ts_col)} AS _ts,
                    {quote_sqlite_identifier(unsent_col)} AS _unsent
                FROM {quote_sqlite_identifier(tname)}
            """
            cur.execute(q)
            for row in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(row["_ts"], "auto")
                is_unsent = bool(row["_unsent"] and int(row["_unsent"]) == 1)

                records.append({
                    "Artifact_ID": f"FB_MSYS_{row['_id'] or row['_rowid']}",
                    "Source_App": "Facebook Messenger (Msys E2EE)",
                    "Chat_Type": "E2EE Chat",
                    "Thread_ID": _safe_str(row["_thread"]),
                    "Thread_Title": _safe_str(row["_thread"]),
                    "Message_Text": _safe_str(row["_text"]),
                    "Message_Type": "E2EE Message",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unsent" if is_unsent else "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(row["_sender"]),
                    "Sender_Name": _safe_str(row["_sender"]),
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": is_unsent,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": is_unsent,
                    "Timestamp_Raw": _safe_str(row["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": tname,
                    "Row_ID": row["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "E2EE_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_facebook_contacts_database(db_path: str) -> pd.DataFrame:
    """Parses Facebook contacts_db2 database contacts table."""
    if not os.path.exists(db_path):
        return pd.DataFrame()

    contacts: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%contact%';")
        tables = [r["name"] for r in cur.fetchall()]

        for tname in tables:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(tname)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            fbid_col = cols.get("fbid", cols.get("user_id", cols.get("id", "rowid")))
            name_col = cols.get("display_name", cols.get("name", "''"))
            pic_col = cols.get("huge_picture_url", cols.get("small_picture_url", "''"))

            cur.execute(f"SELECT rowid AS _rowid, {fbid_col} AS _id, {name_col} AS _name, {pic_col} AS _pic FROM {quote_sqlite_identifier(tname)};")
            for r in cur.fetchall():
                contacts.append({
                    "Contact_ID": f"FB_{r['_id']}",
                    "Source_App": "Facebook",
                    "Display_Name": _safe_str(r["_name"]),
                    "Identifier": _safe_str(r["_id"]),
                    "Avatar_URL": _safe_str(r["_pic"]),
                    "Source_Table": tname,
                })
        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return pd.DataFrame(contacts)


# ==============================================================================
# 2. DISCORD PARSER
# ==============================================================================

def parse_discord_database(db_path_or_dir: str) -> pd.DataFrame:
    """
    Parses Discord Room / SQLite databases (discord.db, kv_storage) and
    LevelDB / disk cache records for messages, embeds, webhooks, and attachments.
    """
    records: List[Dict[str, Any]] = []

    def _parse_sqlite(path: str):
        try:
            conn = sqlite3.connect(ro_uri(os.path.abspath(path)), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r["name"] for r in cur.fetchall()]

            for t in tables:
                t_low = t.lower()
                cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(t)});")
                cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

                # Case A: messages table
                if "content" in cols and ("author" in cols or "author_id" in cols or "channel_id" in cols):
                    c_col = cols["content"]
                    auth_col = cols.get("author", cols.get("author_id", "''"))
                    ch_col = cols.get("channel_id", "''")
                    id_col = cols.get("id", "rowid")
                    ts_col = cols.get("timestamp", "0")

                    cur.execute(f"""
                        SELECT rowid AS _rowid, {id_col} AS _id, {ch_col} AS _ch, {c_col} AS _c,
                               {auth_col} AS _auth, {ts_col} AS _ts
                        FROM {quote_sqlite_identifier(t)}
                    """)
                    for r in cur.fetchall():
                        utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                        auth_str = _safe_str(r["_auth"])
                        auth_json = _extract_json_safe(auth_str)
                        author_name = auth_str
                        author_id = ""
                        if isinstance(auth_json, dict):
                            author_name = auth_json.get("username", auth_str)
                            author_id = auth_json.get("id", "")

                        records.append({
                            "Artifact_ID": f"DISCORD_{r['_id'] or r['_rowid']}",
                            "Source_App": "Discord",
                            "Chat_Type": "Channel / DM",
                            "Thread_ID": _safe_str(r["_ch"]),
                            "Thread_Title": f"Discord Channel {_safe_str(r['_ch'])}",
                            "Message_Text": _safe_str(r["_c"]),
                            "Message_Type": "Discord Message",
                            "Direction": "Unknown",  # no sent/received column is read (review R-13)
                            "Status": "Unknown",
                            "Quoted_Message_Text": "",
                            "Sender_ID": author_id or author_name,
                            "Sender_Name": author_name,
                            "Recipient_ID": _safe_str(r["_ch"]),
                            "Recipient_Name": "",
                            "Is_Ephemeral": False,
                            "Ephemeral_Duration_Seconds": 0,
                            "Ephemeral_Expire_Timestamp": None,
                            "Forwarding_Score": 0,
                            "Is_Starred": False,
                            "Is_Deleted": False,
                            "Timestamp_Raw": _safe_str(r["_ts"]),
                            "Timestamp_UTC": utc_ts,
                            "Timestamp_IST": ist_ts,
                            "Epoch_MS": epoch_ms,
                            "Attachment_Path": "",
                            "Attachment_MIME": "",
                            "Attachment_Size": 0,
                            "Attachment_Hash": "",
                            "Latitude": None,
                            "Longitude": None,
                            "Location_Name": "",
                            "Source_File": os.path.basename(path),
                            "Source_Table": t,
                            "Row_ID": r["_rowid"],
                            "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                            "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                            "Recovery_Method": "ROOM_SQLITE",
                        })

                # Case B: kv_storage JSON payload table
                elif "key" in cols and "value" in cols:
                    cur.execute(f"SELECT rowid AS _rowid, key, value FROM {quote_sqlite_identifier(t)} WHERE key LIKE '%message%' OR value LIKE '%\"content\"%' LIMIT 500;")
                    for r in cur.fetchall():
                        val_json = _extract_json_safe(r["value"])
                        if isinstance(val_json, dict) and "content" in val_json:
                            auth = val_json.get("author", {})
                            author_name = auth.get("username", "") if isinstance(auth, dict) else ""
                            utc_ts, ist_ts, epoch_ms = normalize_iso_ist(val_json.get("timestamp"), "auto")
                            records.append({
                                "Artifact_ID": f"DISCORD_KV_{val_json.get('id', r['_rowid'])}",
                                "Source_App": "Discord",
                                "Chat_Type": "Channel Message",
                                "Thread_ID": _safe_str(val_json.get("channel_id", "")),
                                "Thread_Title": f"Discord Channel {_safe_str(val_json.get('channel_id', ''))}",
                                "Message_Text": _safe_str(val_json.get("content", "")),
                                "Message_Type": "KV Discord Message",
                                "Direction": "Unknown",  # no sent/received column is read (review R-13)
                                "Status": "Unknown",
                                "Quoted_Message_Text": "",
                                "Sender_ID": _safe_str(auth.get("id", "")) if isinstance(auth, dict) else "",
                                "Sender_Name": author_name,
                                "Recipient_ID": "",
                                "Recipient_Name": "",
                                "Is_Ephemeral": False,
                                "Ephemeral_Duration_Seconds": 0,
                                "Ephemeral_Expire_Timestamp": None,
                                "Forwarding_Score": 0,
                                "Is_Starred": False,
                                "Is_Deleted": False,
                                "Timestamp_Raw": _safe_str(val_json.get("timestamp")),
                                "Timestamp_UTC": utc_ts,
                                "Timestamp_IST": ist_ts,
                                "Epoch_MS": epoch_ms,
                                "Attachment_Path": "",
                                "Attachment_MIME": "",
                                "Attachment_Size": 0,
                                "Attachment_Hash": "",
                                "Latitude": None,
                                "Longitude": None,
                                "Location_Name": "",
                                "Source_File": os.path.basename(path),
                                "Source_Table": t,
                                "Row_ID": r["_rowid"],
                                "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                                "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                                "Recovery_Method": "KV_CACHE_SQLITE",
                            })
            conn.close()
        except Exception:
            pass

    if os.path.isfile(db_path_or_dir):
        _parse_sqlite(db_path_or_dir)
    elif os.path.isdir(db_path_or_dir):
        for root, _, files in os.walk(db_path_or_dir):
            for f in files:
                if f.endswith((".db", ".sqlite", ".sqlite3")) and "discord" in f.lower():
                    _parse_sqlite(os.path.join(root, f))

    return make_categorized_dataframe(records)


# ==============================================================================
# 3. SKYPE & MICROSOFT TEAMS PARSER
# ==============================================================================

def parse_skype_teams_database(db_path: str) -> pd.DataFrame:
    """
    Parses Skype (main.db, s4l-*.db) and Microsoft Teams SQLite databases.
    Strips XML tags and extracts skypename/mri, call durations, and file transfers.
    """
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r["name"] for r in cur.fetchall()]
        tables_low = {t.lower(): t for t in tables}

        # ----------------------------------------------------------------------
        # A. Skype Messages (Messages, MessagesV12, conversationsv14)
        # ----------------------------------------------------------------------
        skype_msg_tbl = None
        for cand in ["messagesv12", "messages", "message"]:
            if cand in tables_low:
                skype_msg_tbl = tables_low[cand]
                break

        if skype_msg_tbl:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(skype_msg_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            id_col = cols.get("id", cols.get("msg_id", "rowid"))
            chat_col = cols.get("chatmsg_key", cols.get("conversation_id", cols.get("convo_id", "''")))
            author_col = cols.get("author", cols.get("from_handle", cols.get("creator", "''")))
            dispname_col = cols.get("from_dispname", cols.get("author_display_name", cols.get("display_name", author_col)))
            body_col = cols.get("body_xml", cols.get("content", cols.get("body", "''")))
            ts_col = cols.get("timestamp", cols.get("composetime", cols.get("created_time", "0")))

            cur.execute(f"""
                SELECT rowid AS _rowid, {id_col} AS _id, {chat_col} AS _chat, {author_col} AS _author,
                       {dispname_col} AS _dispname, {body_col} AS _body, {ts_col} AS _ts
                FROM {quote_sqlite_identifier(skype_msg_tbl)}
                ORDER BY {ts_col} ASC
            """)
            for r in cur.fetchall():
                clean_body = _clean_xml_text(_safe_str(r["_body"]))
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")

                records.append({
                    "Artifact_ID": f"SKYPE_{r['_id'] or r['_rowid']}",
                    "Source_App": "Skype",
                    "Chat_Type": "1-on-1 / Group",
                    "Thread_ID": _safe_str(r["_chat"]),
                    "Thread_Title": _safe_str(r["_chat"]),
                    "Message_Text": clean_body,
                    "Message_Type": "Skype Message",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_author"]),
                    "Sender_Name": _safe_str(r["_dispname"]) or _safe_str(r["_author"]),
                    "Recipient_ID": _safe_str(r["_chat"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": skype_msg_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "SKYPE_SQLITE",
                })

        # ----------------------------------------------------------------------
        # B. Microsoft Teams Messages
        # ----------------------------------------------------------------------
        teams_tbl = None
        for cand in ["reply_chains", "teams_messages", "chat_messages", "conversations"]:
            if cand in tables_low:
                teams_tbl = tables_low[cand]
                break

        if teams_tbl and not skype_msg_tbl:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(teams_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            content_col = cols.get("content", cols.get("body", "''"))
            creator_col = cols.get("creator", cols.get("author", "''"))
            ts_col = cols.get("composetime", cols.get("created_time", cols.get("timestamp", "0")))

            cur.execute(f"SELECT rowid AS _rowid, {content_col} AS _content, {creator_col} AS _creator, {ts_col} AS _ts FROM {quote_sqlite_identifier(teams_tbl)};")
            for r in cur.fetchall():
                clean_body = _clean_xml_text(_safe_str(r["_content"]))
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                records.append({
                    "Artifact_ID": f"TEAMS_{r['_rowid']}",
                    "Source_App": "Microsoft Teams",
                    "Chat_Type": "Enterprise Chat",
                    "Thread_ID": "",
                    "Thread_Title": "Teams Channel",
                    "Message_Text": clean_body,
                    "Message_Type": "Teams Chat",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_creator"]),
                    "Sender_Name": _safe_str(r["_creator"]),
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": teams_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "TEAMS_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


# ==============================================================================
# 4. CROSS-BORDER SYNDICATE MESSENGERS: VIBER, WECHAT, LINE, IMO & KAKAOTALK
# ==============================================================================

def parse_viber_database(db_path: str) -> pd.DataFrame:
    """Parses Viber VoIP and messaging database (viber_messages, viber_data)."""
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        if "messages" in tables_low:
            msg_tbl = tables_low["messages"]
            part_tbl = tables_low.get("participants_info")

            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(msg_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            body_col = cols.get("body", "''")
            date_col = cols.get("msg_date", cols.get("date", "0"))
            send_type = cols.get("send_type", "0")
            extra_mime = cols.get("extra_mime", "0")
            lat_col = cols.get("location_lat", "0")
            lng_col = cols.get("location_lng", "0")
            conv_col = cols.get("conversation_id", "''")

            query = f"""
                SELECT rowid AS _rowid,
                    {body_col} AS _body,
                    {date_col} AS _date,
                    {send_type} AS _send_type,
                    {extra_mime} AS _mime,
                    {lat_col} AS _lat,
                    {lng_col} AS _lng,
                    {conv_col} AS _conv
                FROM {quote_sqlite_identifier(msg_tbl)}
            """
            cur.execute(query)
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_date"], "auto")
                is_out = str(r["_send_type"]) == "1"

                lat = float(r["_lat"]) / 1e6 if r["_lat"] and abs(float(r["_lat"])) > 1000 else (float(r["_lat"]) if r["_lat"] else None)
                lng = float(r["_lng"]) / 1e6 if r["_lng"] and abs(float(r["_lng"])) > 1000 else (float(r["_lng"]) if r["_lng"] else None)

                records.append({
                    "Artifact_ID": f"VIBER_{r['_rowid']}",
                    "Source_App": "Viber",
                    "Chat_Type": "VoIP / Chat",
                    "Thread_ID": _safe_str(r["_conv"]),
                    "Thread_Title": f"Viber Conversation {_safe_str(r['_conv'])}",
                    "Message_Text": _safe_str(r["_body"]),
                    "Message_Type": "VoIP Message" if str(r["_mime"]) != "0" else "Text",
                    "Direction": "Outgoing" if is_out else "Incoming",
                    "Status": "Sent" if is_out else "Received",
                    "Quoted_Message_Text": "",
                    "Sender_ID": "Me" if is_out else "Counterparty",
                    "Sender_Name": "Me" if is_out else "Counterparty",
                    "Recipient_ID": _safe_str(r["_conv"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_date"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": _safe_str(r["_mime"]),
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": lat if lat and lat != 0 else None,
                    "Longitude": lng if lng and lng != 0 else None,
                    "Location_Name": f"Viber Pin: {lat}, {lng}" if lat and lng and lat != 0 else "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": msg_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "VIBER_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_wechat_database(db_path: str) -> pd.DataFrame:
    """Parses WeChat EnMicroMsg.db / WCDB_Contact.sqlite messages and WeChat Pay transfers."""
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        if "message" in tables_low:
            msg_tbl = tables_low["message"]
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(msg_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            id_col = cols.get("msgid", cols.get("msgsvrid", "rowid"))
            talker_col = cols.get("talker", "''")
            content_col = cols.get("content", "''")
            ts_col = cols.get("createtime", "0")
            issend_col = cols.get("issend", "0")
            type_col = cols.get("type", "1")

            cur.execute(f"""
                SELECT rowid AS _rowid, {id_col} AS _id, {talker_col} AS _talker, {content_col} AS _content,
                       {ts_col} AS _ts, {issend_col} AS _issend, {type_col} AS _type
                FROM {quote_sqlite_identifier(msg_tbl)}
            """)
            for r in cur.fetchall():
                content = _safe_str(r["_content"])
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                is_out = str(r["_issend"]) == "1"

                # Check for WeChat Pay red packet / transfer XML: <wcpayinfo>
                is_wcpay = "<wcpayinfo>" in content
                msg_type = "WeChat Pay Transfer" if is_wcpay else "Chat Message"

                records.append({
                    "Artifact_ID": f"WECHAT_{r['_id'] or r['_rowid']}",
                    "Source_App": "WeChat",
                    "Chat_Type": "Group" if "@chatroom" in _safe_str(r["_talker"]) else "1-on-1",
                    "Thread_ID": _safe_str(r["_talker"]),
                    "Thread_Title": _safe_str(r["_talker"]),
                    "Message_Text": _clean_xml_text(content) if is_wcpay else content,
                    "Message_Type": msg_type,
                    "Direction": "Outgoing" if is_out else "Incoming",
                    "Status": "Sent" if is_out else "Received",
                    "Quoted_Message_Text": "",
                    "Sender_ID": "Self" if is_out else _safe_str(r["_talker"]),
                    "Sender_Name": "Self" if is_out else _safe_str(r["_talker"]),
                    "Recipient_ID": _safe_str(r["_talker"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "application/x-wcpay" if is_wcpay else "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": msg_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "WECHAT_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_line_database(db_path: str) -> pd.DataFrame:
    """Parses LINE naver_line chat_history database."""
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        if "chat_history" in tables_low:
            ch_tbl = tables_low["chat_history"]
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(ch_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            id_col = cols.get("id", "rowid")
            chat_id = cols.get("chat_id", "''")
            from_mid = cols.get("from_mid", "''")
            content_col = cols.get("content", "''")
            ts_col = cols.get("created_time", "0")
            lat_col = cols.get("location_latitude", "0")
            lng_col = cols.get("location_longitude", "0")

            cur.execute(f"""
                SELECT rowid AS _rowid, {id_col} AS _id, {chat_id} AS _chat, {from_mid} AS _from,
                       {content_col} AS _content, {ts_col} AS _ts,
                       {lat_col} AS _lat, {lng_col} AS _lng
                FROM {quote_sqlite_identifier(ch_tbl)}
            """)
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                lat = float(r["_lat"]) if r["_lat"] and float(r["_lat"]) != 0 else None
                lng = float(r["_lng"]) if r["_lng"] and float(r["_lng"]) != 0 else None

                records.append({
                    "Artifact_ID": f"LINE_{r['_id'] or r['_rowid']}",
                    "Source_App": "LINE",
                    "Chat_Type": "1-on-1 / Group",
                    "Thread_ID": _safe_str(r["_chat"]),
                    "Thread_Title": f"LINE Chat {_safe_str(r['_chat'])}",
                    "Message_Text": _safe_str(r["_content"]),
                    "Message_Type": "LINE Chat",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_from"]),
                    "Sender_Name": _safe_str(r["_from"]),
                    "Recipient_ID": _safe_str(r["_chat"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": lat,
                    "Longitude": lng,
                    "Location_Name": f"LINE Pin: {lat}, {lng}" if lat and lng else "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": ch_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "LINE_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_imo_kakaotalk_database(db_path: str) -> pd.DataFrame:
    """Parses IMO (imodb.db) and KakaoTalk (KakaoTalk.db) chat databases."""
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        # IMO
        if "immessages" in tables_low or ("messages" in tables_low and "friends" in tables_low):
            tbl = tables_low.get("immessages", tables_low.get("messages"))
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            msg_col = cols.get("message", cols.get("body", "''"))
            ts_col = cols.get("timestamp", cols.get("time", "0"))
            peer_col = cols.get("buid", cols.get("peer_uid", "''"))

            cur.execute(f"SELECT rowid AS _rowid, {msg_col} AS _msg, {ts_col} AS _ts, {peer_col} AS _peer FROM {quote_sqlite_identifier(tbl)};")
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                records.append({
                    "Artifact_ID": f"IMO_{r['_rowid']}",
                    "Source_App": "IMO",
                    "Chat_Type": "IMO Chat",
                    "Thread_ID": _safe_str(r["_peer"]),
                    "Thread_Title": f"IMO {_safe_str(r['_peer'])}",
                    "Message_Text": _safe_str(r["_msg"]),
                    "Message_Type": "IMO Message",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_peer"]),
                    "Sender_Name": _safe_str(r["_peer"]),
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "IMO_SQLITE",
                })

        # KakaoTalk
        if "chat_logs" in tables_low:
            tbl = tables_low["chat_logs"]
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            msg_col = cols.get("message", "''")
            ts_col = cols.get("created_at", "0")
            user_col = cols.get("user_id", "''")
            chat_id = cols.get("chat_id", "''")

            cur.execute(f"SELECT rowid AS _rowid, {msg_col} AS _msg, {ts_col} AS _ts, {user_col} AS _user, {chat_id} AS _chat FROM {quote_sqlite_identifier(tbl)};")
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                records.append({
                    "Artifact_ID": f"KAKAO_{r['_rowid']}",
                    "Source_App": "KakaoTalk",
                    "Chat_Type": "KakaoTalk Chat",
                    "Thread_ID": _safe_str(r["_chat"]),
                    "Thread_Title": f"KakaoTalk {_safe_str(r['_chat'])}",
                    "Message_Text": _safe_str(r["_msg"]),
                    "Message_Type": "KakaoTalk Log",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_user"]),
                    "Sender_Name": _safe_str(r["_user"]),
                    "Recipient_ID": _safe_str(r["_chat"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "KAKAOTALK_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


# ==============================================================================
# 5. X (TWITTER) DMS, THREADS, REDDIT CHAT & LINKEDIN PARSER
# ==============================================================================

def parse_twitter_threads_reddit_linkedin(db_path: str) -> pd.DataFrame:
    """
    Parses Twitter DMs (<uid>-65.db), Threads DMs, Reddit chat tables,
    and LinkedIn voyager.db conversations.
    """
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    base_name = os.path.basename(db_path).lower()

    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        # ----------------------------------------------------------------------
        # A. Twitter DMs (conversation_entries)
        # ----------------------------------------------------------------------
        if "conversation_entries" in tables_low or "conversations" in tables_low:
            t = tables_low.get("conversation_entries", tables_low.get("conversations"))
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(t)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            data_col = cols.get("data", cols.get("entry_id", "rowid"))
            ts_col = cols.get("created_at", cols.get("time", "0"))

            cur.execute(f"SELECT rowid AS _rowid, {data_col} AS _data, {ts_col} AS _ts FROM {quote_sqlite_identifier(t)};")
            for r in cur.fetchall():
                data_val = _safe_str(r["_data"])
                d_json = _extract_json_safe(data_val)
                text = ""
                sender = ""
                if isinstance(d_json, dict):
                    msg_obj = d_json.get("message", d_json)
                    text = msg_obj.get("text", "")
                    sender = msg_obj.get("sender_id", "")
                else:
                    text = data_val

                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                records.append({
                    "Artifact_ID": f"X_DM_{r['_rowid']}",
                    "Source_App": "X (Twitter)",
                    "Chat_Type": "Direct Message",
                    "Thread_ID": sender,
                    "Thread_Title": f"X DM {sender}",
                    "Message_Text": text,
                    "Message_Type": "Twitter DM",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": sender,
                    "Sender_Name": sender,
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": t,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "TWITTER_SQLITE",
                })

        # ----------------------------------------------------------------------
        # B. LinkedIn Voyager (messages, conversations)
        # ----------------------------------------------------------------------
        if "voyager" in base_name or "messages" in tables_low and "conversations" in tables_low:
            t = tables_low.get("messages")
            if t:
                cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(t)});")
                cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
                body_col = cols.get("body", cols.get("text", "''"))
                from_col = cols.get("from_participant", cols.get("sender", "''"))
                ts_col = cols.get("created_at", cols.get("timestamp", "0"))

                cur.execute(f"SELECT rowid AS _rowid, {body_col} AS _body, {from_col} AS _from, {ts_col} AS _ts FROM {quote_sqlite_identifier(t)};")
                for r in cur.fetchall():
                    utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                    records.append({
                        "Artifact_ID": f"LINKEDIN_{r['_rowid']}",
                        "Source_App": "LinkedIn",
                        "Chat_Type": "InMail / Chat",
                        "Thread_ID": _safe_str(r["_from"]),
                        "Thread_Title": f"LinkedIn Conversation",
                        "Message_Text": _safe_str(r["_body"]),
                        "Message_Type": "LinkedIn Message",
                        "Direction": "Unknown",  # no sent/received column is read (review R-13)
                        "Status": "Unknown",
                        "Quoted_Message_Text": "",
                        "Sender_ID": _safe_str(r["_from"]),
                        "Sender_Name": _safe_str(r["_from"]),
                        "Recipient_ID": "",
                        "Recipient_Name": "",
                        "Is_Ephemeral": False,
                        "Ephemeral_Duration_Seconds": 0,
                        "Ephemeral_Expire_Timestamp": None,
                        "Forwarding_Score": 0,
                        "Is_Starred": False,
                        "Is_Deleted": False,
                        "Timestamp_Raw": _safe_str(r["_ts"]),
                        "Timestamp_UTC": utc_ts,
                        "Timestamp_IST": ist_ts,
                        "Epoch_MS": epoch_ms,
                        "Attachment_Path": "",
                        "Attachment_MIME": "",
                        "Attachment_Size": 0,
                        "Attachment_Hash": "",
                        "Latitude": None,
                        "Longitude": None,
                        "Location_Name": "",
                        "Source_File": os.path.basename(db_path),
                        "Source_Table": t,
                        "Row_ID": r["_rowid"],
                        "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                        "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                        "Recovery_Method": "LINKEDIN_SQLITE",
                    })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


# ==============================================================================
# 6. INDIAN CYBERCRIME APPS: TRUECALLER, OLX INDIA, SHARECHAT & MOJ
# ==============================================================================

def parse_truecaller_database(db_path: str) -> pd.DataFrame:
    """
    Parses Truecaller msg.db and tc.db:
    Recovers messages, caller-ID spam/fraud score, tagged Indian names, and call history.
    Crucial for identifying unknown mobile numbers in Indian cybercrime investigations.
    """
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        # ----------------------------------------------------------------------
        # A. Truecaller Messages (msg.db -> msg_messages / messages)
        # ----------------------------------------------------------------------
        msg_tbl = tables_low.get("msg_messages", tables_low.get("messages"))
        if msg_tbl:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(msg_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            text_col = cols.get("text", cols.get("message", "''"))
            ts_col = cols.get("date", cols.get("timestamp", "0"))
            peer_col = cols.get("participant_id", cols.get("address", cols.get("sender", "''")))
            type_col = cols.get("type", cols.get("message_type", "0"))

            cur.execute(f"""
                SELECT rowid AS _rowid, {text_col} AS _text, {ts_col} AS _ts,
                       {peer_col} AS _peer, {type_col} AS _type
                FROM {quote_sqlite_identifier(msg_tbl)}
            """)
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                peer_raw = _safe_str(r["_peer"])
                is_out = str(r["_type"]) in ("2", "outgoing")

                records.append({
                    "Artifact_ID": f"TC_MSG_{r['_rowid']}",
                    "Source_App": "Truecaller",
                    "Chat_Type": "SMS / Chat",
                    "Thread_ID": peer_raw,
                    "Thread_Title": f"Truecaller Contact {peer_raw}",
                    "Message_Text": _safe_str(r["_text"]),
                    "Message_Type": "Truecaller SMS/Chat",
                    "Direction": "Outgoing" if is_out else "Incoming",
                    "Status": "Sent" if is_out else "Received",
                    "Quoted_Message_Text": "",
                    "Sender_ID": "Me" if is_out else peer_raw,
                    "Sender_Name": "Me" if is_out else peer_raw,
                    "Recipient_ID": peer_raw if is_out else "Me",
                    "Recipient_Name": peer_raw if is_out else "Me",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": msg_tbl,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "TRUECALLER_SQLITE",
                })

        # ----------------------------------------------------------------------
        # B. Truecaller Aggregated Contacts & Spam Scores (tc.db)
        # ----------------------------------------------------------------------
        contact_tbl = tables_low.get("aggregated_contact", tables_low.get("contact_phone_numbers"))
        if contact_tbl:
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(contact_tbl)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}
            name_col = cols.get("name", cols.get("contact_name", "''"))
            num_col = cols.get("phone_number", cols.get("number", "''"))
            spam_col = cols.get("spam_score", cols.get("spam_type", "0"))

            cur.execute(f"SELECT rowid AS _rowid, {name_col} AS _name, {num_col} AS _num, {spam_col} AS _spam FROM {quote_sqlite_identifier(contact_tbl)} LIMIT 500;")
            for r in cur.fetchall():
                name = _safe_str(r["_name"])
                num = _safe_str(r["_num"])
                spam = _safe_str(r["_spam"])
                if name or num:
                    records.append({
                        "Artifact_ID": f"TC_IDENT_{r['_rowid']}",
                        "Source_App": "Truecaller",
                        "Chat_Type": "Caller-ID Dossier",
                        "Thread_ID": num,
                        "Thread_Title": f"Caller ID: {name} ({num})",
                        "Message_Text": f"[TRUECALLER IDENTIFIED] Name: {name} | Number: {num} | Spam/Fraud Score: {spam}",
                        "Message_Type": "Caller Identity",
                        "Direction": "Unknown",  # no sent/received column is read (review R-13)
                        "Status": "Spam / Fraud Tagged" if str(spam) not in ("0", "") else "Identified",
                        "Quoted_Message_Text": "",
                        "Sender_ID": num,
                        "Sender_Name": name,
                        "Recipient_ID": "",
                        "Recipient_Name": "",
                        "Is_Ephemeral": False,
                        "Ephemeral_Duration_Seconds": 0,
                        "Ephemeral_Expire_Timestamp": None,
                        "Forwarding_Score": 0,
                        "Is_Starred": False,
                        "Is_Deleted": False,
                        "Timestamp_Raw": "",
                        "Timestamp_UTC": "",
                        "Timestamp_IST": "",
                        "Epoch_MS": 0,
                        "Attachment_Path": "",
                        "Attachment_MIME": "",
                        "Attachment_Size": 0,
                        "Attachment_Hash": "",
                        "Latitude": None,
                        "Longitude": None,
                        "Location_Name": "",
                        "Source_File": os.path.basename(db_path),
                        "Source_Table": contact_tbl,
                        "Row_ID": r["_rowid"],
                        "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                        "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                        "Recovery_Method": "TRUECALLER_CALLER_ID",
                    })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_olx_database(db_path: str) -> pd.DataFrame:
    """
    Parses OLX India chat database (olx_chat.db / chat.db):
    Recovers buyer/seller chat lures and shared UPI QR payment requests.
    """
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        if "messages" in tables_low or "chat_messages" in tables_low:
            t = tables_low.get("messages", tables_low.get("chat_messages"))
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(t)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            text_col = cols.get("message", cols.get("text", cols.get("body", "''")))
            ts_col = cols.get("created_at", cols.get("timestamp", cols.get("date", "0")))
            sender_col = cols.get("sender_id", cols.get("from_id", "''"))
            thread_col = cols.get("thread_id", cols.get("ad_id", "''"))

            cur.execute(f"""
                SELECT rowid AS _rowid, {text_col} AS _text, {ts_col} AS _ts,
                       {sender_col} AS _sender, {thread_col} AS _thread
                FROM {quote_sqlite_identifier(t)}
            """)
            for r in cur.fetchall():
                text = _safe_str(r["_text"])
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")

                # Detect UPI or QR lure keywords
                is_upi_lure = bool(re.search(r"@\w+|qr code|upi|paytm|phonepe|gpay|advance|booking", text, re.I))

                records.append({
                    "Artifact_ID": f"OLX_{r['_rowid']}",
                    "Source_App": "OLX India",
                    "Chat_Type": "Buyer-Seller Chat",
                    "Thread_ID": _safe_str(r["_thread"]),
                    "Thread_Title": f"OLX Ad Thread {_safe_str(r['_thread'])}",
                    "Message_Text": text,
                    "Message_Type": "UPI Lure / Payment Request" if is_upi_lure else "OLX Message",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Flagged UPI Lure" if is_upi_lure else "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_sender"]),
                    "Sender_Name": _safe_str(r["_sender"]),
                    "Recipient_ID": _safe_str(r["_thread"]),
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": is_upi_lure,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": t,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "OLX_CYBERCRIME_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


def parse_sharechat_moj_database(db_path: str) -> pd.DataFrame:
    """Parses Indian regional social app databases (ShareChat and Moj chatrooms)."""
    if not os.path.exists(db_path):
        return make_categorized_dataframe([])

    records: List[Dict[str, Any]] = []
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables_low = {r["name"].lower(): r["name"] for r in cur.fetchall()}

        if "messages" in tables_low or "chat_messages" in tables_low:
            t = tables_low.get("messages", tables_low.get("chat_messages"))
            cur.execute(f"PRAGMA table_info({quote_sqlite_identifier(t)});")
            cols = {r["name"].lower(): r["name"] for r in cur.fetchall()}

            msg_col = cols.get("message", cols.get("text", "''"))
            ts_col = cols.get("timestamp", cols.get("time", "0"))
            user_col = cols.get("sender_id", cols.get("user_id", "''"))

            cur.execute(f"SELECT rowid AS _rowid, {msg_col} AS _msg, {ts_col} AS _ts, {user_col} AS _user FROM {quote_sqlite_identifier(t)};")
            for r in cur.fetchall():
                utc_ts, ist_ts, epoch_ms = normalize_iso_ist(r["_ts"], "auto")
                records.append({
                    "Artifact_ID": f"SHARECHAT_{r['_rowid']}",
                    "Source_App": "ShareChat / Moj",
                    "Chat_Type": "Direct / Chatroom",
                    "Thread_ID": _safe_str(r["_user"]),
                    "Thread_Title": f"ShareChat Room",
                    "Message_Text": _safe_str(r["_msg"]),
                    "Message_Type": "ShareChat Message",
                    "Direction": "Unknown",  # no sent/received column is read (review R-13)
                    "Status": "Unknown",
                    "Quoted_Message_Text": "",
                    "Sender_ID": _safe_str(r["_user"]),
                    "Sender_Name": _safe_str(r["_user"]),
                    "Recipient_ID": "",
                    "Recipient_Name": "",
                    "Is_Ephemeral": False,
                    "Ephemeral_Duration_Seconds": 0,
                    "Ephemeral_Expire_Timestamp": None,
                    "Forwarding_Score": 0,
                    "Is_Starred": False,
                    "Is_Deleted": False,
                    "Timestamp_Raw": _safe_str(r["_ts"]),
                    "Timestamp_UTC": utc_ts,
                    "Timestamp_IST": ist_ts,
                    "Epoch_MS": epoch_ms,
                    "Attachment_Path": "",
                    "Attachment_MIME": "",
                    "Attachment_Size": 0,
                    "Attachment_Hash": "",
                    "Latitude": None,
                    "Longitude": None,
                    "Location_Name": "",
                    "Source_File": os.path.basename(db_path),
                    "Source_Table": t,
                    "Row_ID": r["_rowid"],
                    "Page_Number": 0,  # page unknown: no B-tree walk (review R-13)
                    "Byte_Offset": None,  # no B-tree walk: offset unknown (C-09)
                    "Recovery_Method": "SHARECHAT_SQLITE",
                })

        conn.close()
    except Exception as exc:  # do not lose the failure silently
        logger.warning("parse failed for %s: %s", db_path, exc)

    return make_categorized_dataframe(records)


# ==============================================================================
# MANIFESTS FOR PLUGIN LOADER (BUILTIN_MANIFESTS EXTENSION)
# ==============================================================================

SOCIAL_INTERACTION_MANIFESTS: List[Dict[str, Any]] = [
    # 1. Facebook & Facebook Messenger
    {
        "app_name": "Facebook Messenger",
        "category": "social",
        "bundle_ids": ["com.facebook.Messenger", "com.facebook.Facebook"],
        "android_pkgs": ["com.facebook.orca", "com.facebook.katana", "com.facebook.mlite"],
        "aliases": ["messenger", "fb_messenger", "orca", "katana"],
        "preferred_tables": ["messages", "cql_messages", "threads", "contacts"],
        "amount_cols": [],
        "date_cols": ["timestamp_ms", "timestamp", "timestamp_sent_ms"],
        "counterparty_cols": ["sender", "sender_id", "thread_key"],
        "txid_cols": ["msg_id", "message_id"],
        "status_cols": ["is_unsent", "msg_type"],
        "blob_cols": ["attachments", "shares"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 2. Discord
    {
        "app_name": "Discord",
        "category": "social",
        "bundle_ids": ["com.hammerandchisel.discord"],
        "android_pkgs": ["com.discord"],
        "aliases": ["discord"],
        "preferred_tables": ["messages", "kv_storage", "channels"],
        "amount_cols": [],
        "date_cols": ["timestamp"],
        "counterparty_cols": ["author", "author_id", "channel_id"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["attachments", "embeds"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 3. Skype
    {
        "app_name": "Skype",
        "category": "social",
        "bundle_ids": ["com.skype.skype"],
        "android_pkgs": ["com.skype.raider"],
        "aliases": ["skype"],
        "preferred_tables": ["messagesv12", "messages", "conversationsv14"],
        "amount_cols": [],
        "date_cols": ["timestamp", "composetime"],
        "counterparty_cols": ["author", "chatmsg_key"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["body_xml"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 4. Microsoft Teams
    {
        "app_name": "Microsoft Teams",
        "category": "social",
        "bundle_ids": ["com.microsoft.skype.teams"],
        "android_pkgs": ["com.microsoft.teams"],
        "aliases": ["teams", "msteams"],
        "preferred_tables": ["reply_chains", "teams_messages", "conversations"],
        "amount_cols": [],
        "date_cols": ["composetime", "created_time"],
        "counterparty_cols": ["creator"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["content"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 5. Viber
    {
        "app_name": "Viber",
        "category": "social",
        "bundle_ids": ["com.viber"],
        "android_pkgs": ["com.viber.voip"],
        "aliases": ["viber"],
        "preferred_tables": ["messages", "viber_messages", "participants_info"],
        "amount_cols": [],
        "date_cols": ["msg_date", "date"],
        "counterparty_cols": ["conversation_id"],
        "txid_cols": ["msg_id"],
        "status_cols": ["send_type"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 6. WeChat
    {
        "app_name": "WeChat",
        "category": "social",
        "bundle_ids": ["com.tencent.xin"],
        "android_pkgs": ["com.tencent.mm"],
        "aliases": ["wechat", "weixin"],
        "preferred_tables": ["message", "rcontact"],
        "amount_cols": [],
        "date_cols": ["createtime"],
        "counterparty_cols": ["talker"],
        "txid_cols": ["msgid", "msgsvrid"],
        "status_cols": ["issend", "type"],
        "blob_cols": ["content"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 7. LINE
    {
        "app_name": "LINE",
        "category": "social",
        "bundle_ids": ["jp.naver.line"],
        "android_pkgs": ["jp.naver.line.android"],
        "aliases": ["line"],
        "preferred_tables": ["chat_history", "contacts"],
        "amount_cols": [],
        "date_cols": ["created_time"],
        "counterparty_cols": ["chat_id", "from_mid"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["content"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 8. IMO
    {
        "app_name": "IMO",
        "category": "social",
        "bundle_ids": ["com.imo.imodesktop"],
        "android_pkgs": ["com.imo.android.imoim"],
        "aliases": ["imo"],
        "preferred_tables": ["immessages", "messages", "friends"],
        "amount_cols": [],
        "date_cols": ["timestamp"],
        "counterparty_cols": ["buid", "peer_uid"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 9. KakaoTalk
    {
        "app_name": "KakaoTalk",
        "category": "social",
        "bundle_ids": ["com.iwilab.KakaoTalk"],
        "android_pkgs": ["com.kakao.talk"],
        "aliases": ["kakaotalk", "kakao"],
        "preferred_tables": ["chat_logs", "friends"],
        "amount_cols": [],
        "date_cols": ["created_at"],
        "counterparty_cols": ["user_id", "chat_id"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["message"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 10. X (Twitter)
    {
        "app_name": "X (Twitter)",
        "category": "social",
        "bundle_ids": ["com.atebits.Tweetie2"],
        "android_pkgs": ["com.twitter.android"],
        "aliases": ["twitter", "x"],
        "preferred_tables": ["conversation_entries", "conversations"],
        "amount_cols": [],
        "date_cols": ["created_at"],
        "counterparty_cols": ["sender_id"],
        "txid_cols": ["entry_id"],
        "status_cols": [],
        "blob_cols": ["data"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 11. Threads
    {
        "app_name": "Threads",
        "category": "social",
        "bundle_ids": ["com.burbn.threads"],
        "android_pkgs": ["com.instagram.barcelona"],
        "aliases": ["threads", "barcelona"],
        "preferred_tables": ["messages", "direct_threads"],
        "amount_cols": [],
        "date_cols": ["timestamp"],
        "counterparty_cols": ["sender"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 12. LinkedIn
    {
        "app_name": "LinkedIn",
        "category": "social",
        "bundle_ids": ["com.linkedin.LinkedIn"],
        "android_pkgs": ["com.linkedin.android"],
        "aliases": ["linkedin", "voyager"],
        "preferred_tables": ["messages", "conversations"],
        "amount_cols": [],
        "date_cols": ["created_at", "timestamp"],
        "counterparty_cols": ["from_participant"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["body"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 13. Truecaller
    {
        "app_name": "Truecaller",
        "category": "social",
        "bundle_ids": ["com.truesoftware.TrueCaller"],
        "android_pkgs": ["com.truecaller"],
        "aliases": ["truecaller"],
        "preferred_tables": ["msg_messages", "messages", "aggregated_contact"],
        "amount_cols": [],
        "date_cols": ["date", "timestamp"],
        "counterparty_cols": ["participant_id", "address"],
        "txid_cols": ["id"],
        "status_cols": ["type"],
        "blob_cols": [],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 14. OLX India
    {
        "app_name": "OLX India",
        "category": "social",
        "bundle_ids": ["com.olx.olx"],
        "android_pkgs": ["com.olx.southasia"],
        "aliases": ["olx", "olx_india"],
        "preferred_tables": ["messages", "chat_messages", "threads"],
        "amount_cols": [],
        "date_cols": ["created_at", "timestamp"],
        "counterparty_cols": ["sender_id", "thread_id"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["message"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
    # 15. ShareChat & Moj
    {
        "app_name": "ShareChat",
        "category": "social",
        "bundle_ids": ["in.mohalla.sharechat"],
        "android_pkgs": ["in.mohalla.sharechat", "in.mohalla.video"],
        "aliases": ["sharechat", "moj"],
        "preferred_tables": ["messages", "chat_messages"],
        "amount_cols": [],
        "date_cols": ["timestamp", "time"],
        "counterparty_cols": ["sender_id", "user_id"],
        "txid_cols": ["id"],
        "status_cols": [],
        "blob_cols": ["message"],
        "amount_divisor": 1.0,
        "json_amount_divisor": 1.0,
        "timestamp_epoch": "auto"
    },
]
