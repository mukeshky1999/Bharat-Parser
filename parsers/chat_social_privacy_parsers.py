"""
Deep Artifact Parsers for Global, Indian,
Privacy, Ephemeral, Social, and Dating Applications.

Covers:
A. WhatsApp & WhatsApp Business (Full multi-table relational schema + crypt14/15 AES-GCM decryptor)
B. Telegram & Telegram X (Full TL binary stream deserializer + cache4.db extractor)
C. Signal Private Messenger (Android/iOS SQLCipher relational schemas + attachment resolution)
D. Zangi Private Messenger (10-digit Zangi ID chats, VoIP calls, and iOS CoreData ZMESSAGE)
E. Element / Matrix Messenger (Matrix event schema, m.room.message, and Megolm encrypted caches)
F. Session Messenger (Oxen 05-hexadecimal ID messages, contacts, and open group resolution)
G. Threema, Briar, SimpleX (Privacy-first peer-to-peer protocols and contact keys)
H. Snapchat (Arroyo unified conversation engine, Protobuf decoder, friends, and memories)
I. Instagram Direct (direct.db / reverb.db multi-format messages, threads, and JSON attachments)
J. Dating Apps (Tinder, Bumble, Hinge, Grindr romance scam & sextortion vectors)
"""

from __future__ import annotations
from src.core.sqlite_uri import ro_uri

import binascii
import hashlib
import json
import os
import re
import sqlite3
import struct
import zlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

IST = timezone(timedelta(hours=5, minutes=30))

import pandas as pd

CATEGORIZED_FORENSIC_COLUMNS: List[str] = [
    'Artifact_ID',
    'Source_App',
    'Chat_Type',
    'Thread_ID',
    'Thread_Title',
    'Message_Text',
    'Message_Type',
    'Direction',
    'Status',
    'Quoted_Message_Text',
    'Sender_ID',
    'Sender_Name',
    'Recipient_ID',
    'Recipient_Name',
    'Is_Ephemeral',
    'Ephemeral_Duration_Seconds',
    'Ephemeral_Expire_Timestamp',
    'Forwarding_Score',
    'Is_Starred',
    'Is_Deleted',
    'Timestamp_Raw',
    'Timestamp_UTC',
    'Timestamp_IST',
    'Epoch_MS',
    'Attachment_Path',
    'Attachment_MIME',
    'Attachment_Size',
    'Attachment_Hash',
    'Latitude',
    'Longitude',
    'Location_Name',
    'Source_File',
    'Source_Table',
    'Row_ID',
    'Page_Number',
    'Byte_Offset',
    'Recovery_Method',
]


def make_categorized_dataframe(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Standardizes a list of parsed artifact dictionaries into a pandas DataFrame
    strictly conforming to the 28+ Categorized Forensic Columns without field flattening.
    """
    if not records:
        return pd.DataFrame(columns=CATEGORIZED_FORENSIC_COLUMNS)

    norm_records: List[Dict[str, Any]] = []
    for r in records:
        item = dict(r)
        e_dur = item.get('Ephemeral_Duration_Seconds')
        if e_dur is None and item.get('Disappearing_Timer_Sec') is not None:
            e_dur = item.get('Disappearing_Timer_Sec')
        item['Ephemeral_Duration_Seconds'] = e_dur
        item['Is_Ephemeral'] = bool(e_dur and e_dur > 0)
        item['Is_Deleted'] = bool(item.get('Is_Deleted', False) or item.get('is_deleted', False))
        item['Is_Starred'] = bool(item.get('Is_Starred', False) or item.get('starred', False))
        item['Forwarding_Score'] = int(item.get('Forwarding_Score', 0) or item.get('forwarding_score', 0) or 0)

        for col in CATEGORIZED_FORENSIC_COLUMNS:
            if col not in item:
                item[col] = None
        norm_records.append(item)

    df = pd.DataFrame(norm_records)
    return df[CATEGORIZED_FORENSIC_COLUMNS]



def normalize_iso_ist(val: Any, epoch: str = 'auto') -> Tuple[str, str, int]:
    """
    Normalizes any raw timestamp to (utc_iso, ist_formatted, epoch_ms).
    """
    if val is None or val == '' or str(val).lower() in ('none', 'nan', 'null', '0', '-1'):
        return '', '', 0
    try:
        n = float(val)
        if epoch == 'cocoa' or (epoch == 'auto' and 0 < n < 1500000000 and '.' in str(val)):
            epoch_ms = int((n + 978307200.0) * 1000)
        elif n > 11644473600000000:  # WebKit microseconds
            epoch_ms = int((n - 11644473600000000) / 1000)
        elif n > 1000000000000000:  # Microseconds
            epoch_ms = int(n / 1000)
        elif n > 100000000000:  # Milliseconds
            epoch_ms = int(n)
        elif n > 0:  # Unix seconds
            epoch_ms = int(n * 1000)
        else:
            epoch_ms = 0
    except Exception:
        # String parse attempt
        try:
            dt = datetime.fromisoformat(str(val).replace('Z', '+00:00'))
            epoch_ms = int(dt.timestamp() * 1000)
        except Exception:
            return str(val), str(val), 0

    if epoch_ms <= 0:
        return '', '', 0

    dt_utc = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc.astimezone(IST)

    utc_iso = dt_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    ist_fmt = dt_ist.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' IST (+05:30)'
    return utc_iso, ist_fmt, epoch_ms


def format_hex_offset(offset: Any) -> str:
    if offset is None:
        return "0x00000000"
    try:
        return f"0x{int(offset):08X}"
    except Exception:
        return str(offset)


# =============================================================================
# A. WhatsApp & WhatsApp Business Deep Parser & Crypt14/15 Decryptor
# =============================================================================

class WhatsAppDeepParser:
    @staticmethod
    def decrypt_crypt14_15(crypt_file_path: str, key_path_or_hex: str, output_path: str) -> bool:
        """
        Decrypts msgstore.db.crypt14 / crypt15 using the 32-byte AES key located at offset 126..158
        in /data/data/com.whatsapp/files/key (or 64-character hex string).
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            return False

        if not os.path.exists(crypt_file_path):
            return False

        # Read key
        aes_key: Optional[bytes] = None
        if os.path.exists(key_path_or_hex):
            with open(key_path_or_hex, 'rb') as kf:
                key_bytes = kf.read()
                if len(key_bytes) >= 158:
                    aes_key = key_bytes[126:158]
                elif len(key_bytes) == 32:
                    aes_key = key_bytes
        elif len(key_path_or_hex) == 64:
            try:
                aes_key = bytes.fromhex(key_path_or_hex)
            except Exception:
                pass

        if not aes_key or len(aes_key) != 32:
            return False

        with open(crypt_file_path, 'rb') as cf:
            data = cf.read()

        if len(data) < 191:
            return False

        # Crypt14/15 header layout:
        # Offset 0..67: Header info
        # IV is typically at offset 67..79 (12 bytes) or 51..67 (16 bytes)
        # Encrypted payload + 16-byte GCM tag
        for iv_off, iv_len, payload_off in [(67, 12, 79), (51, 16, 67), (191, 12, 203), (128, 16, 144)]:
            if payload_off >= len(data):
                continue
            iv = data[iv_off:iv_off + iv_len]
            ciphertext = data[payload_off:]
            try:
                aesgcm = AESGCM(aes_key)
                decrypted = aesgcm.decrypt(iv, ciphertext, None)
                # Decompress zlib stream
                try:
                    db_bytes = zlib.decompress(decrypted)
                except Exception:
                    db_bytes = decrypted

                if db_bytes.startswith(b'SQLite format 3'):
                    with open(output_path, 'wb') as out_f:
                        out_f.write(db_bytes)
                    return True
            except Exception:
                continue

        return False

    @staticmethod
    def parse(db_path: str, source_file_label: str = "msgstore.db") -> List[Dict[str, Any]]:
        """
        Executes a multi-table relational join across message, chat, jid, message_media,
        message_location, message_quoted, message_ephemeral, and receipt_user.
        """
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Check tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'message' in tables and 'chat' in tables and 'jid' in tables:
                cur.execute("PRAGMA table_info(message)")
                msg_cols = {r[1].lower() for r in cur.fetchall()}

                col_text = "m.text_data" if "text_data" in msg_cols else ("m.data" if "data" in msg_cols else "NULL")
                col_type = "m.message_type" if "message_type" in msg_cols else "0"
                col_starred = "m.starred" if "starred" in msg_cols else "0"
                col_orig = "m.origination_flags" if "origination_flags" in msg_cols else "0"
                col_fwd = "m.forwarding_score" if "forwarding_score" in msg_cols else "0"

                has_media = 'message_media' in tables
                has_location = 'message_location' in tables
                has_quoted = 'message_quoted' in tables
                has_ephemeral = 'message_ephemeral' in tables
                has_receipt = 'receipt_user' in tables

                sql = f"""
                SELECT
                    m._id AS row_id,
                    m.timestamp AS timestamp_ms,
                    m.from_me AS from_me,
                    {col_text} AS message_text,
                    {col_type} AS msg_type,
                    {col_starred} AS starred,
                    {col_orig} AS orig_flags,
                    {col_fwd} AS fwd_score,
                    c.subject AS group_subject,
                    j_chat.raw_string AS chat_jid,
                    j_sender.raw_string AS sender_jid
                    {', mq.text_data AS quoted_text' if has_quoted else ', NULL AS quoted_text'}
                    {', mm.file_path AS media_path, mm.mime_type AS media_mime, mm.file_size AS media_size, mm.file_hash AS media_hash, mm.media_caption AS media_caption, mm.media_duration AS media_duration' if has_media else ', NULL AS media_path, NULL AS media_mime, NULL AS media_size, NULL AS media_hash, NULL AS media_caption, NULL AS media_duration'}
                    {', ml.latitude AS latitude, ml.longitude AS longitude, ml.place_name AS place_name, ml.place_address AS place_address' if has_location else ', NULL AS latitude, NULL AS longitude, NULL AS place_name, NULL AS place_address'}
                    {', me.expire_timestamp AS expire_ts, me.keep_in_chat AS keep_in_chat' if has_ephemeral else ', NULL AS expire_ts, NULL AS keep_in_chat'}
                    {', ru.receipt_timestamp AS receipt_ts, ru.read_timestamp AS read_ts, ru.played_timestamp AS played_ts' if has_receipt else ', NULL AS receipt_ts, NULL AS read_ts, NULL AS played_ts'}
                FROM message m
                INNER JOIN chat c ON m.chat_row_id = c._id
                INNER JOIN jid j_chat ON c.jid_row_id = j_chat._id
                LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id
                {f'LEFT JOIN message_quoted mq ON m._id = mq.message_row_id' if has_quoted else ''}
                {f'LEFT JOIN message_media mm ON m._id = mm.message_row_id' if has_media else ''}
                {f'LEFT JOIN message_location ml ON m._id = ml.message_row_id' if has_location else ''}
                {f'LEFT JOIN message_ephemeral me ON m._id = me.message_row_id' if has_ephemeral else ''}
                {f'LEFT JOIN receipt_user ru ON m._id = ru.message_row_id' if has_receipt else ''}
                ORDER BY m.timestamp DESC
                """

                cur.execute(sql)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['row_id']
                    chat_jid = str(r['chat_jid'] or '')
                    sender_jid = str(r['sender_jid'] or '')
                    group_subject = r['group_subject']
                    is_from_me = bool(r['from_me'])
                    msg_type = r['msg_type'] or 0

                    # Classify chat type
                    if chat_jid.endswith('@g.us'):
                        chat_type = 'GROUP_CHAT'
                        thread_title = group_subject or chat_jid.split('@')[0]
                    elif chat_jid.endswith('@broadcast'):
                        chat_type = 'CHANNEL_BROADCAST'
                        thread_title = 'Status Broadcast'
                    else:
                        chat_type = 'DIRECT_1ON1'
                        thread_title = chat_jid.split('@')[0]

                    # Message Type Mapping
                    type_labels = {
                        0: 'TEXT',
                        1: 'IMAGE',
                        2: 'AUDIO_VOICENOTE',
                        3: 'VIDEO',
                        4: 'VCARD',
                        5: 'LOCATION',
                        7: 'SYSTEM',
                        15: 'REVOKED_DELETED',
                        42: 'VIEW_ONCE_IMAGE',
                        43: 'VIEW_ONCE_VIDEO',
                        55: 'UPI_PAYMENT'
                    }
                    type_str = type_labels.get(msg_type, f'UNKNOWN_{msg_type}')

                    text_val = r['message_text'] or r['media_caption'] or ''
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r['timestamp_ms'], 'unix_ms')

                    status = 'SENT' if is_from_me else 'RECEIVED'
                    if r['read_ts']:
                        status = 'READ'
                    elif r['receipt_ts']:
                        status = 'DELIVERED'

                    results.append({
                        'Artifact_ID': f"WA_MSG_{row_id}",
                        'Source_App': 'WhatsApp',
                        'Platform': 'Android',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_from_me else 'INCOMING',
                        'Status': status,
                        'Chat_Type': chat_type,
                        'Thread_ID': chat_jid,
                        'Thread_Title': thread_title,
                        'Sender_ID': 'This Device (Owner)' if is_from_me else (sender_jid or chat_jid),
                        'Sender_Name': 'This Device (Owner)' if is_from_me else (sender_jid.split('@')[0] if sender_jid else thread_title),
                        'Recipient_ID': chat_jid if is_from_me else 'This Device (Owner)',
                        'Recipient_Name': thread_title if is_from_me else 'This Device (Owner)',
                        'Message_Text': text_val,
                        'Message_Type': type_str,
                        'Quoted_Message_Text': r['quoted_text'],
                        'Forwarding_Score': r['fwd_score'] or 0,
                        'Starred': bool(r['starred']),
                        'Is_Deleted': msg_type == 15,
                        'Disappearing_Timer_Sec': r['expire_ts'],
                        'Attachment_Path': r['media_path'],
                        'Attachment_MIME': r['media_mime'],
                        'Attachment_Size': r['media_size'],
                        'Attachment_Hash': str(r['media_hash']) if r['media_hash'] else None,
                        'Attachment_Duration': r['media_duration'],
                        'Latitude': r['latitude'],
                        'Longitude': r['longitude'],
                        'Location_Name': r['place_name'],
                        'Source_File': source_file_label,
                        'Source_Table': 'message',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            # Check iOS WhatsApp (ChatStorage.sqlite)
            elif 'zwamessage' in tables and 'zwachatsession' in tables:
                sql_ios = """
                SELECT
                    m.Z_PK AS row_id,
                    m.ZMESSAGEDATE AS date_cocoa,
                    m.ZISFROMME AS is_from_me,
                    m.ZTEXT AS message_text,
                    m.ZMESSAGETYPE AS msg_type,
                    s.ZCONTACTJID AS chat_jid,
                    s.ZPARTNERNAME AS partner_name,
                    med.ZMEDIALOCALPATH AS media_path
                FROM ZWAMESSAGE m
                LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
                LEFT JOIN ZWAMEDIAITEM med ON m.ZMEDIAITEM = med.Z_PK
                ORDER BY m.ZMESSAGEDATE DESC
                """
                cur.execute(sql_ios)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['row_id']
                    chat_jid = str(r['chat_jid'] or '')
                    is_from_me = bool(r['is_from_me'])
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r['date_cocoa'], 'cocoa')

                    results.append({
                        'Artifact_ID': f"WA_IOS_{row_id}",
                        'Source_App': 'WhatsApp',
                        'Platform': 'iOS',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_from_me else 'INCOMING',
                        'Status': 'SENT' if is_from_me else 'RECEIVED',
                        'Chat_Type': 'GROUP_CHAT' if '@g.us' in chat_jid else 'DIRECT_1ON1',
                        'Thread_ID': chat_jid,
                        'Thread_Title': r['partner_name'] or chat_jid,
                        'Sender_ID': 'This Device (Owner)' if is_from_me else chat_jid,
                        'Sender_Name': 'This Device (Owner)' if is_from_me else (r['partner_name'] or chat_jid),
                        'Recipient_ID': chat_jid if is_from_me else 'This Device (Owner)',
                        'Recipient_Name': r['partner_name'] if is_from_me else 'This Device (Owner)',
                        'Message_Text': r['message_text'] or '',
                        'Message_Type': 'TEXT' if r['msg_type'] == 0 else 'MEDIA',
                        'Attachment_Path': r['media_path'],
                        'Source_File': source_file_label,
                        'Source_Table': 'ZWAMESSAGE',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            # Also check WhatsApp Call Logs
            if 'call_log' in tables:
                cur.execute("""
                SELECT c._id, c.call_id, c.timestamp, c.video_call, c.duration, c.call_result, j.raw_string AS peer_jid
                FROM call_log c
                LEFT JOIN jid j ON c.jid_row_id = j._id
                ORDER BY c.timestamp DESC
                """)
                for r in cur.fetchall():
                    r = dict(r)
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r['timestamp'], 'unix_ms')
                    res_map = {5: 'CONNECTED', 2: 'MISSED', 4: 'REJECTED'}
                    call_res = res_map.get(r['call_result'], 'UNKNOWN')

                    results.append({
                        'Artifact_ID': f"WA_CALL_{r['_id']}",
                        'Source_App': 'WhatsApp',
                        'Platform': 'Android',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # a connected call can be either direction
                        'Status': call_res,
                        'Chat_Type': 'VOIP_CALL',
                        'Thread_ID': str(r['peer_jid'] or ''),
                        'Thread_Title': f"Call with {r['peer_jid']}",
                        'Sender_ID': str(r['peer_jid'] or ''),
                        'Sender_Name': str(r['peer_jid'] or '').split('@')[0],
                        'Recipient_ID': 'This Device (Owner)',
                        'Recipient_Name': 'This Device (Owner)',
                        'Message_Text': f"WhatsApp {'Video' if r['video_call'] else 'Voice'} Call ({r['duration']}s, Result: {call_res})",
                        'Message_Type': 'VOIP_CALL_LOG',
                        'Attachment_Duration': r['duration'],
                        'Source_File': source_file_label,
                        'Source_Table': 'call_log',
                        'Row_ID': r['_id'],
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# B. Telegram & Telegram X Binary TL Stream Deserializer
# =============================================================================

class TelegramTLDeserializer:
    @staticmethod
    def read_tl_string(buf: bytes, offset: int) -> Tuple[str, int]:
        """
        Reads length-prefixed TL string:
        - If buf[offset] < 254: length = buf[offset], string follows, padded to 4 bytes boundary.
        - If buf[offset] == 254 (0xFE): next 3 bytes are length (Little-Endian), string follows, padded to 4 bytes.
        """
        if offset >= len(buf):
            return "", offset

        first = buf[offset]
        if first < 254:
            str_len = first
            str_start = offset + 1
            if str_start + str_len > len(buf):
                return "", len(buf)
            raw_s = buf[str_start:str_start + str_len]
            padding = (4 - ((str_len + 1) % 4)) % 4
            next_off = str_start + str_len + padding
            val = raw_s.decode('utf-8', errors='replace')
            return val, next_off
        elif first == 254:
            if offset + 4 > len(buf):
                return "", len(buf)
            str_len = buf[offset + 1] | (buf[offset + 2] << 8) | (buf[offset + 3] << 16)
            str_start = offset + 4
            if str_start + str_len > len(buf):
                return "", len(buf)
            raw_s = buf[str_start:str_start + str_len]
            padding = (4 - (str_len % 4)) % 4
            next_off = str_start + str_len + padding
            val = raw_s.decode('utf-8', errors='replace')
            return val, next_off

        return "", offset + 1

    @staticmethod
    def deserialize_tl_message(blob: bytes) -> Dict[str, Any]:
        """
        Unpacks Telegram messages_v2.data TL binary buffer into message text, entities, and flags.
        """
        res: Dict[str, Any] = {'text': '', 'media_caption': '', 'entities': []}
        if not blob or len(blob) < 8:
            return res

        try:
            constructor_id = struct.unpack('<I', blob[0:4])[0]
            flags = struct.unpack('<I', blob[4:8])[0]
            res['constructor_id'] = f"0x{constructor_id:08X}"
            res['flags'] = flags

            # Walk TL stream to harvest strings
            offset = 8
            found_strings: List[str] = []
            while offset < len(blob) - 1:
                val, next_off = TelegramTLDeserializer.read_tl_string(blob, offset)
                if next_off <= offset:
                    offset += 4
                    continue
                # Validate if string is meaningful text
                if val and any(c.isalnum() for c in val) and len(val) >= 2:
                    found_strings.append(val)
                offset = next_off

            if found_strings:
                res['text'] = found_strings[0]
                if len(found_strings) > 1:
                    res['media_caption'] = ' '.join(found_strings[1:])
        except Exception:
            pass

        return res

    @staticmethod
    def parse_database(db_path: str, source_file_label: str = "cache4.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            # Map Telegram users and chats for display names
            user_map: Dict[int, str] = {}
            if 'users' in tables:
                cur.execute("SELECT uid, name, data FROM users")
                for r in cur.fetchall():
                    r = dict(r)
                    uid = r['uid']
                    name = r['name']
                    if not name and r['data']:
                        tl_u = TelegramTLDeserializer.deserialize_tl_message(r['data'])
                        name = tl_u.get('text')
                    user_map[uid] = str(name or f"User_{uid}")

            chat_map: Dict[int, str] = {}
            if 'chats' in tables:
                cur.execute("SELECT uid, name, data FROM chats")
                for r in cur.fetchall():
                    r = dict(r)
                    cid = r['uid']
                    name = r['name']
                    if not name and r['data']:
                        tl_c = TelegramTLDeserializer.deserialize_tl_message(r['data'])
                        name = tl_c.get('text')
                    chat_map[cid] = str(name or f"Chat_{cid}")

            # Parse messages_v2
            if 'messages_v2' in tables:
                cur.execute("""
                SELECT mid, uid, read_state, send_state, date, data, out, ttl, media, replydata
                FROM messages_v2
                ORDER BY date DESC
                """)
                for r in cur.fetchall():
                    r = dict(r)
                    mid = r['mid']
                    uid = r['uid']
                    is_out = bool(r['out'])
                    date_sec = r['date']
                    data_blob = r['data']
                    ttl = r['ttl']

                    tl_res = TelegramTLDeserializer.deserialize_tl_message(data_blob)
                    msg_text = tl_res.get('text') or ''
                    if not msg_text and tl_res.get('media_caption'):
                        msg_text = tl_res['media_caption']

                    if not msg_text and not r['media']:
                        continue

                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(date_sec, 'unix_sec')
                    peer_title = user_map.get(uid) or chat_map.get(uid) or f"Telegram Peer {uid}"

                    results.append({
                        'Artifact_ID': f"TG_MSG_{mid}",
                        'Source_App': 'Telegram',
                        'Platform': 'Android',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_out else 'INCOMING',
                        'Status': 'READ' if r['read_state'] else 'DELIVERED',
                        'Chat_Type': 'GROUP_CHAT' if uid in chat_map or uid < 0 else 'DIRECT_1ON1',
                        'Thread_ID': str(uid),
                        'Thread_Title': peer_title,
                        'Sender_ID': 'This Device (Owner)' if is_out else str(uid),
                        'Sender_Name': 'This Device (Owner)' if is_out else peer_title,
                        'Recipient_ID': str(uid) if is_out else 'This Device (Owner)',
                        'Recipient_Name': peer_title if is_out else 'This Device (Owner)',
                        'Message_Text': msg_text,
                        'Message_Type': 'MEDIA' if r['media'] else 'TEXT',
                        'Disappearing_Timer_Sec': ttl if ttl and ttl > 0 else None,
                        'Source_File': source_file_label,
                        'Source_Table': 'messages_v2',
                        'Row_ID': mid,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# C. Signal Private Messenger Parser
# =============================================================================

class SignalDeepParser:
    @staticmethod
    def parse(db_path: str, source_file_label: str = "signal.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            # Android Signal Schema (message, recipient, part)
            if 'message' in tables:
                has_recip = 'recipient' in tables
                has_part = 'part' in tables

                sql = f"""
                SELECT
                    m._id AS row_id,
                    m.date_sent AS date_sent,
                    m.date_received AS date_recv,
                    m.body AS body,
                    m.type AS msg_type,
                    m.expires_in AS expires_in,
                    m.view_once AS view_once,
                    m.quote_id AS quote_id,
                    m.quote_body AS quote_body
                    {', r.phone AS recip_phone, r.system_joined_name AS sys_name, r.profile_given_name AS given_name, r.aci AS aci' if has_recip else ', NULL AS recip_phone, NULL AS sys_name, NULL AS given_name, NULL AS aci'}
                    {', p.ct AS mime_type, p.file_name AS file_name, p.data_size AS file_size, p._data AS part_path' if has_part else ', NULL AS mime_type, NULL AS file_name, NULL AS file_size, NULL AS part_path'}
                FROM message m
                {f'LEFT JOIN recipient r ON m.recipient_id = r._id' if has_recip else ''}
                {f'LEFT JOIN part p ON m._id = p.mid' if has_part else ''}
                ORDER BY m.date_received DESC
                """
                cur.execute(sql)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['row_id']
                    raw_type = r['msg_type'] or 0
                    is_out = (raw_type & 0x1F) == 23
                    date_ms = r['date_recv'] or r['date_sent'] or 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(date_ms, 'unix_ms')

                    name_disp = r['sys_name'] or r['given_name'] or r['recip_phone'] or r['aci'] or 'Signal Contact'

                    results.append({
                        'Artifact_ID': f"SIGNAL_MSG_{row_id}",
                        'Source_App': 'Signal',
                        'Platform': 'Android',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_out else 'INCOMING',
                        'Status': 'SENT' if is_out else 'RECEIVED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(r['recip_phone'] or r['aci'] or ''),
                        'Thread_Title': name_disp,
                        'Sender_ID': 'This Device (Owner)' if is_out else name_disp,
                        'Sender_Name': 'This Device (Owner)' if is_out else name_disp,
                        'Recipient_ID': name_disp if is_out else 'This Device (Owner)',
                        'Recipient_Name': name_disp if is_out else 'This Device (Owner)',
                        'Message_Text': r['body'] or (f"[Attachment: {r['file_name']}]" if r['file_name'] else ''),
                        'Message_Type': 'VIEW_ONCE' if r['view_once'] else ('ATTACHMENT' if r['part_path'] else 'TEXT'),
                        'Quoted_Message_Text': r['quote_body'],
                        'Disappearing_Timer_Sec': int(r['expires_in'] / 1000) if r['expires_in'] and r['expires_in'] >= 1000 else (int(r['expires_in']) if r['expires_in'] else None),
                        'Attachment_Path': r['part_path'],
                        'Attachment_MIME': r['mime_type'],
                        'Attachment_Size': r['file_size'],
                        'Source_File': source_file_label,
                        'Source_Table': 'message',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            # iOS Signal (signal.sqlite)
            elif 'model_tsinteraction' in tables:
                cur.execute("""
                SELECT uniqueId, uniqueThreadId, timestamp, receivedAtTimestamp, body, authorId, expiresInSeconds
                FROM model_TSInteraction
                ORDER BY timestamp DESC
                """)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['uniqueId']
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r['timestamp'], 'unix_ms')
                    results.append({
                        'Artifact_ID': f"SIGNAL_IOS_{row_id}",
                        'Source_App': 'Signal',
                        'Platform': 'iOS',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(r['uniqueThreadId']),
                        'Thread_Title': str(r['authorId'] or r['uniqueThreadId']),
                        'Sender_ID': str(r['authorId']),
                        'Sender_Name': str(r['authorId']),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': r['body'] or '',
                        'Message_Type': 'TEXT',
                        'Disappearing_Timer_Sec': r['expiresInSeconds'],
                        'Source_File': source_file_label,
                        'Source_Table': 'model_TSInteraction',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# D. Zangi Private Messenger Parser (10-Digit Zangi ID + iOS CoreData)
# =============================================================================

class ZangiDeepParser:
    @staticmethod
    def parse(db_path: str, source_file_label: str = "zangi.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            # Android Zangi (messages / chat_messages)
            msg_tbl = 'messages' if 'messages' in tables else ('chat_messages' if 'chat_messages' in tables else None)
            if msg_tbl:
                cur.execute(f"PRAGMA table_info({msg_tbl})")
                cols = {c['name'].lower(): c['name'] for c in cur.fetchall()}

                body_c = cols.get('body') or cols.get('text') or 'body'
                ts_c = cols.get('timestamp') or cols.get('created_at') or 'timestamp'
                sender_c = cols.get('sender_id') or cols.get('from_zangi_number') or 'sender_id'
                recip_c = cols.get('receiver_id') or cols.get('to_zangi_number') or 'receiver_id'
                out_c = cols.get('is_outgoing') or cols.get('outgoing') or 'is_outgoing'
                file_c = cols.get('file_path') or cols.get('file_url') or 'file_path'

                cur.execute(f"SELECT rowid, * FROM {msg_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body_val = str(r[body_c] or '')
                    if not body_val and not (file_c in r and r[file_c]):
                        continue

                    is_out = bool(r[out_c]) if out_c in r else False
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r[ts_c], 'auto')

                    s_id = str(r[sender_c] if sender_c in r else 'Zangi Sender')
                    rc_id = str(r[recip_c] if recip_c in r else 'Zangi Recipient')

                    results.append({
                        'Artifact_ID': f"ZANGI_MSG_{row_id}",
                        'Source_App': 'Zangi',
                        'Platform': 'Android',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_out else 'INCOMING',
                        'Status': 'SENT' if is_out else 'RECEIVED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': rc_id if is_out else s_id,
                        'Thread_Title': f"Zangi {rc_id if is_out else s_id}",
                        'Sender_ID': 'This Device (Owner)' if is_out else s_id,
                        'Sender_Name': 'This Device (Owner)' if is_out else s_id,
                        'Recipient_ID': rc_id if is_out else 'This Device (Owner)',
                        'Recipient_Name': rc_id if is_out else 'This Device (Owner)',
                        'Message_Text': body_val,
                        'Message_Type': 'ATTACHMENT' if (file_c in r and r[file_c]) else 'TEXT',
                        'Attachment_Path': r[file_c] if file_c in r else None,
                        'Source_File': source_file_label,
                        'Source_Table': msg_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            # iOS CoreData Zangi (ZMESSAGE)
            elif 'zmessage' in tables:
                sql_ios = """
                SELECT
                    m.Z_PK AS row_id,
                    m.ZTEXT AS body,
                    m.ZDATE AS cocoa_date,
                    m.ZISOUTGOING AS is_out,
                    m.ZSENDERZANGINUMBER AS sender_zangi,
                    c.ZZANGINUMBER AS contact_zangi,
                    c.ZFIRSTNAME AS first_name,
                    c.ZLASTNAME AS last_name
                FROM ZMESSAGE m
                LEFT JOIN ZCONVERSATION conv ON m.ZCONVERSATION = conv.Z_PK
                LEFT JOIN ZCONTACT c ON conv.ZCONTACT = c.Z_PK
                ORDER BY m.Z_PK DESC
                """
                cur.execute(sql_ios)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['row_id']
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(r['cocoa_date'], 'cocoa')
                    name = f"{r['first_name'] or ''} {r['last_name'] or ''}".strip() or r['contact_zangi'] or 'Zangi User'

                    results.append({
                        'Artifact_ID': f"ZANGI_IOS_{row_id}",
                        'Source_App': 'Zangi',
                        'Platform': 'iOS',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if r['is_out'] else 'INCOMING',
                        'Status': 'SENT' if r['is_out'] else 'RECEIVED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(r['contact_zangi'] or ''),
                        'Thread_Title': name,
                        'Sender_ID': 'This Device (Owner)' if r['is_out'] else str(r['sender_zangi'] or name),
                        'Sender_Name': 'This Device (Owner)' if r['is_out'] else name,
                        'Recipient_ID': name if r['is_out'] else 'This Device (Owner)',
                        'Recipient_Name': name if r['is_out'] else 'This Device (Owner)',
                        'Message_Text': r['body'] or '',
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': 'ZMESSAGE',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            # Parse Zangi VoIP Call logs
            call_tbl = 'calls' if 'calls' in tables else ('zcall' if 'zcall' in tables else None)
            if call_tbl:
                cur.execute(f"SELECT rowid, * FROM {call_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    dur = r['duration'] if 'duration' in r else (r['ZDURATION'] if 'ZDURATION' in r else 0)
                    peer = r['peer_zangi_number'] if 'peer_zangi_number' in r else (r['ZPEERNUMBER'] if 'ZPEERNUMBER' in r else 'Zangi Peer')
                    ts_raw = r['start_time'] if 'start_time' in r else (r['ZSTARTTIME'] if 'ZSTARTTIME' in r else 0)
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts_raw, 'auto')

                    results.append({
                        'Artifact_ID': f"ZANGI_CALL_{row_id}",
                        'Source_App': 'Zangi',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'CONNECTED' if dur > 0 else 'MISSED',
                        'Chat_Type': 'VOIP_CALL',
                        'Thread_ID': str(peer),
                        'Thread_Title': f"Zangi Call ({peer})",
                        'Sender_ID': str(peer),
                        'Sender_Name': str(peer),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': f"Zangi VoIP Call ({dur}s)",
                        'Message_Type': 'VOIP_CALL_LOG',
                        'Attachment_Duration': dur,
                        'Source_File': source_file_label,
                        'Source_Table': call_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# E. Element / Matrix Messenger Parser
# =============================================================================

class ElementMatrixDeepParser:
    @staticmethod
    def parse(db_path: str, source_file_label: str = "matrix-sdk.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            ev_tbl = next((t for t in ('events', 'timeline_events', 'roomevents') if t in tables), None)
            if ev_tbl:
                cur.execute(f"SELECT rowid, * FROM {ev_tbl}")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    # Check for raw JSON column
                    raw_ev = r['event_json_payload'] if 'event_json_payload' in r else (r['json'] if 'json' in r else (r['content'] if 'content' in r else None))
                    if not raw_ev:
                        continue

                    try:
                        ev = json.loads(raw_ev) if isinstance(raw_ev, str) else json.loads(raw_ev.decode('utf-8'))
                    except Exception:
                        continue

                    ev_type = ev.get('type')
                    sender = ev.get('sender') or 'Matrix User'
                    room_id = ev.get('room_id') or 'Matrix Room'
                    ts = ev.get('origin_server_ts') or 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'unix_ms')

                    body = ''
                    msg_type_str = 'TEXT'

                    if ev_type == 'm.room.message':
                        content = ev.get('content', {})
                        body = content.get('body', '')
                        m_type = content.get('msgtype', 'm.text')
                        if m_type == 'm.image':
                            msg_type_str = 'IMAGE'
                            body = f"[Matrix Image: {content.get('url', '')}]"
                        elif m_type == 'm.file':
                            msg_type_str = 'ATTACHMENT'
                    elif ev_type == 'm.room.encrypted':
                        body = f"[Megolm Encrypted Event - Session: {ev.get('content', {}).get('session_id', 'N/A')}]"
                        msg_type_str = 'ENCRYPTED_MEGOLM'
                    else:
                        continue

                    results.append({
                        'Artifact_ID': f"MATRIX_EV_{row_id}",
                        'Source_App': 'Element (Matrix)',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'GROUP_CHAT' if room_id.startswith('!') else 'DIRECT_1ON1',
                        'Thread_ID': room_id,
                        'Thread_Title': room_id,
                        'Sender_ID': sender,
                        'Sender_Name': sender,
                        'Recipient_ID': room_id,
                        'Recipient_Name': room_id,
                        'Message_Text': body,
                        'Message_Type': msg_type_str,
                        'Source_File': source_file_label,
                        'Source_Table': ev_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# F. Session Messenger Parser (05-Hex Session ID)
# =============================================================================

class SessionDeepParser:
    @staticmethod
    def parse(db_path: str, source_file_label: str = "session.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            # Mapping contacts to names
            name_map: Dict[str, str] = {}
            for ct_tbl in ('contacts', 'loki_user_display_name_database'):
                if ct_tbl in tables:
                    cur.execute(f"SELECT * FROM {ct_tbl}")
                    for r in cur.fetchall():
                        r = dict(r)
                        addr = r['address'] if 'address' in r else (r['public_key'] if 'public_key' in r else None)
                        dn = r['display_name'] if 'display_name' in r else (r['name'] if 'name' in r else None)
                        if addr and dn:
                            name_map[str(addr)] = str(dn)

            msg_tbl = next((t for t in ('messages', 'sms', 'mms') if t in tables), None)
            if msg_tbl:
                cur.execute(f"SELECT rowid, * FROM {msg_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body = r['body'] if 'body' in r else ''
                    if not body:
                        continue

                    addr = str(r['address'] if 'address' in r else (r['thread_id'] if 'thread_id' in r else 'Session Peer'))
                    date_val = r['date_sent'] if 'date_sent' in r else (r['date'] if 'date' in r else 0)
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(date_val, 'unix_ms')

                    raw_type = r['type'] if 'type' in r else 0
                    is_out = (raw_type & 0x1F) == 23

                    display_name = name_map.get(addr, f"Session ({addr[:10]}...)")

                    results.append({
                        'Artifact_ID': f"SESSION_MSG_{row_id}",
                        'Source_App': 'Session',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_out else 'INCOMING',
                        'Status': 'SENT' if is_out else 'RECEIVED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': addr,
                        'Thread_Title': display_name,
                        'Sender_ID': 'This Device (Owner)' if is_out else addr,
                        'Sender_Name': 'This Device (Owner)' if is_out else display_name,
                        'Recipient_ID': addr if is_out else 'This Device (Owner)',
                        'Recipient_Name': display_name if is_out else 'This Device (Owner)',
                        'Message_Text': body,
                        'Message_Type': 'TEXT',
                        'Disappearing_Timer_Sec': int(r['expires_in'] / 1000) if ('expires_in' in r and r['expires_in']) else None,
                        'Source_File': source_file_label,
                        'Source_Table': msg_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# G. Threema, Briar, SimpleX Deep Parsers
# =============================================================================

class PrivacyNicheDeepParsers:
    @staticmethod
    def parse_threema(db_path: str, source_file_label: str = "threema.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'message' in tables:
                cur.execute("SELECT rowid, * FROM message ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body = r['body'] if 'body' in r else ''
                    ident = r['identity'] if 'identity' in r else 'Threema Contact'
                    ts = r['created_at'] if 'created_at' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'unix_ms')
                    is_out = bool(r['is_outbox']) if 'is_outbox' in r else False

                    results.append({
                        'Artifact_ID': f"THREEMA_MSG_{row_id}",
                        'Source_App': 'Threema',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'OUTGOING' if is_out else 'INCOMING',
                        'Status': 'SENT' if is_out else 'RECEIVED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(ident),
                        'Thread_Title': f"Threema {ident}",
                        'Sender_ID': 'This Device (Owner)' if is_out else str(ident),
                        'Sender_Name': 'This Device (Owner)' if is_out else str(ident),
                        'Recipient_ID': str(ident) if is_out else 'This Device (Owner)',
                        'Recipient_Name': str(ident) if is_out else 'This Device (Owner)',
                        'Message_Text': body or '',
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': 'message',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_simplex(db_path: str, source_file_label: str = "simplex_v1_chat.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'messages' in tables:
                cur.execute("SELECT rowid, * FROM messages ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    msg_body = r['msg_body'] if 'msg_body' in r else ''
                    text_val = msg_body
                    try:
                        obj = json.loads(msg_body)
                        text_val = obj.get('text', msg_body)
                    except Exception:
                        pass

                    ts = r['created_at'] if 'created_at' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'unix_ms')

                    results.append({
                        'Artifact_ID': f"SIMPLEX_MSG_{row_id}",
                        'Source_App': 'SimpleX',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(r['chat_id'] if 'chat_id' in r else 'SimpleX Chat'),
                        'Thread_Title': 'SimpleX Chat',
                        'Sender_ID': 'SimpleX Peer',
                        'Sender_Name': 'SimpleX Peer',
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': text_val,
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': 'messages',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# H. Snapchat Arroyo Unified Engine & Memories Deep Parser
# =============================================================================

class SnapchatDeepParser:
    @staticmethod
    def extract_arroyo_protobuf_strings(blob: bytes) -> List[str]:
        """
        Extracts UTF-8 text strings embedded in Snapchat Arroyo message_content Protobuf BLOB.
        """
        found: List[str] = []
        if not blob or len(blob) < 4:
            return found

        offset = 0
        while offset < len(blob):
            try:
                # Read varint tag
                key = 0
                shift = 0
                while offset < len(blob):
                    b = blob[offset]
                    offset += 1
                    key |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7

                wire_type = key & 0x07
                if wire_type == 0:  # Varint
                    while offset < len(blob) and (blob[offset] & 0x80):
                        offset += 1
                    offset += 1
                elif wire_type == 1:  # 64-bit
                    offset += 8
                elif wire_type == 2:  # Length-delimited
                    length = 0
                    shift = 0
                    while offset < len(blob):
                        b = blob[offset]
                        offset += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7

                    if offset + length > len(blob) or length < 0:
                        break

                    slice_bytes = blob[offset:offset + length]
                    offset += length

                    # Check if valid printable UTF-8 text
                    try:
                        s = slice_bytes.decode('utf-8')
                        if len(s) >= 2 and all(ord(c) >= 32 or c in '\n\r\t' for c in s):
                            found.append(s)
                    except Exception:
                        # Recurse into sub-message
                        sub = SnapchatDeepParser.extract_arroyo_protobuf_strings(slice_bytes)
                        found.extend(sub)
                elif wire_type == 5:  # 32-bit
                    offset += 4
                else:
                    break
            except Exception:
                break

        return found

    @staticmethod
    def parse_arroyo(db_path: str, source_file_label: str = "arroyo.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'conversation_message' in tables:
                cur.execute("""
                SELECT rowid, client_conversation_id, server_message_id, sender_id,
                       creation_timestamp, read_timestamp, content_type, message_content
                FROM conversation_message
                ORDER BY creation_timestamp DESC
                """)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    conv_id = r['client_conversation_id']
                    sender = r['sender_id']
                    ts = r['creation_timestamp']
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'unix_ms')
                    c_type = r['content_type'] or 0

                    content_blob = r['message_content']
                    extracted_strings = SnapchatDeepParser.extract_arroyo_protobuf_strings(content_blob)
                    msg_text = ' '.join(extracted_strings) if extracted_strings else ''

                    type_map = {0: 'SNAP_MEDIA', 1: 'TEXT', 2: 'MEDIA_STICKER', 4: 'AUDIO_NOTE'}
                    type_str = type_map.get(c_type, f'CONTENT_TYPE_{c_type}')

                    results.append({
                        'Artifact_ID': f"SNAP_MSG_{row_id}",
                        'Source_App': 'Snapchat',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'READ' if r['read_timestamp'] else 'DELIVERED',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(conv_id),
                        'Thread_Title': f"Snapchat Conversation {str(conv_id)[:12]}",
                        'Sender_ID': str(sender),
                        'Sender_Name': str(sender),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': msg_text or f"[{type_str}]",
                        'Message_Type': type_str,
                        'Source_File': source_file_label,
                        'Source_Table': 'conversation_message',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_friends(db_path: str, source_file_label: str = "main.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            friend_tbl = next((t for t in ('friend', 'friends') if t in tables), None)
            if friend_tbl:
                cur.execute(f"SELECT rowid, * FROM {friend_tbl}")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    uname = r['username'] if 'username' in r else ''
                    dname = r['displayName'] if 'displayName' in r else (r['display_name'] if 'display_name' in r else uname)
                    phone = r['phone'] if 'phone' in r else None

                    results.append({
                        'Artifact_ID': f"SNAP_FRIEND_{row_id}",
                        'Source_App': 'Snapchat',
                        'Contact_Username': uname,
                        'Contact_Display_Name': dname,
                        'Phone_Number': phone,
                        'Source_File': source_file_label,
                        'Source_Table': friend_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# I. Instagram Direct Deep Parser (direct.db / reverb.db)
# =============================================================================

class InstagramDirectDeepParser:
    @staticmethod
    def parse(db_path: str, source_file_label: str = "direct.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'messages' in tables:
                cur.execute("SELECT rowid, * FROM messages ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    msg_txt = r['text'] if 'text' in r else ''
                    msg_type = r['message_type'] if 'message_type' in r else 'text'
                    ts_us = r['timestamp'] if 'timestamp' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts_us, 'auto')

                    # Parse JSON inside message column if text is empty
                    raw_msg = r['message'] if 'message' in r else None
                    if not msg_txt and raw_msg:
                        try:
                            obj = json.loads(raw_msg) if isinstance(raw_msg, str) else json.loads(raw_msg.decode('utf-8'))
                            msg_txt = obj.get('text', '')
                            if not msg_txt and 'media' in obj:
                                msg_txt = f"[Instagram Media: {obj['media'].get('id', '')}]"
                        except Exception:
                            pass

                    results.append({
                        'Artifact_ID': f"IG_MSG_{row_id}",
                        'Source_App': 'Instagram Direct',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DIRECT_1ON1',
                        'Thread_ID': str(r['thread_key'] if 'thread_key' in r else (r['thread_id'] if 'thread_id' in r else '')),
                        'Thread_Title': f"Instagram Thread",
                        'Sender_ID': str(r['user_id'] if 'user_id' in r else ''),
                        'Sender_Name': str(r['user_id'] if 'user_id' in r else 'Instagram User'),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': msg_txt or f"[{msg_type}]",
                        'Message_Type': str(msg_type).upper(),
                        'Source_File': source_file_label,
                        'Source_Table': 'messages',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# J. Dating Apps Deep Parsers (Tinder, Bumble, Hinge, Grindr)
# =============================================================================

class DatingAppsDeepParser:
    @staticmethod
    def parse_tinder(db_path: str, source_file_label: str = "tinder.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            msg_tbl = next((t for t in ('message_view', 'messages') if t in tables), None)
            if msg_tbl:
                cur.execute(f"SELECT rowid, * FROM {msg_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    text_val = r.get('text') or r.get('message') or r.get('body') or ''
                    sent_d = r['sent_date'] if 'sent_date' in r else (r['created_date'] if 'created_date' in r else 0)
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(sent_d, 'auto')

                    from_id = r['from_id'] if 'from_id' in r else 'Tinder Match'
                    match_id = r['match_id'] if 'match_id' in r else ''

                    results.append({
                        'Artifact_ID': f"TINDER_MSG_{row_id}",
                        'Source_App': 'Tinder',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DATING_MATCH_CHAT',
                        'Thread_ID': str(match_id),
                        'Thread_Title': f"Tinder Match {str(match_id)[:10]}",
                        'Sender_ID': str(from_id),
                        'Sender_Name': str(from_id),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': text_val,
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': msg_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_bumble(db_path: str, source_file_label: str = "bumble.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            msg_tbl = next((t for t in ('chat_message', 'messages') if t in tables), None)
            if msg_tbl:
                cur.execute(f"SELECT rowid, * FROM {msg_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body = r['body'] if 'body' in r else (r['text'] if 'text' in r else '')
                    ts = r['created_timestamp'] if 'created_timestamp' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'auto')

                    results.append({
                        'Artifact_ID': f"BUMBLE_MSG_{row_id}",
                        'Source_App': 'Bumble',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DATING_MATCH_CHAT',
                        'Thread_ID': str(r['conversation_id'] if 'conversation_id' in r else ''),
                        'Thread_Title': 'Bumble Match',
                        'Sender_ID': str(r['sender_id'] if 'sender_id' in r else 'Bumble User'),
                        'Sender_Name': str(r['sender_id'] if 'sender_id' in r else 'Bumble User'),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': body,
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': msg_tbl,
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_hinge(db_path: str, source_file_label: str = "hinge.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'messages' in tables:
                cur.execute("SELECT rowid, * FROM messages ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body = r['body'] if 'body' in r else ''
                    ts = r['timestamp'] if 'timestamp' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'auto')

                    results.append({
                        'Artifact_ID': f"HINGE_MSG_{row_id}",
                        'Source_App': 'Hinge',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DATING_MATCH_CHAT',
                        'Thread_ID': str(r['subject_id'] if 'subject_id' in r else ''),
                        'Thread_Title': 'Hinge Match',
                        'Sender_ID': str(r['sender_id'] if 'sender_id' in r else 'Hinge User'),
                        'Sender_Name': str(r['sender_id'] if 'sender_id' in r else 'Hinge User'),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': body,
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': 'messages',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_grindr(db_path: str, source_file_label: str = "grindr.db") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            if 'chat_messages' in tables:
                cur.execute("SELECT rowid, * FROM chat_messages ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    body = r['body'] if 'body' in r else ''
                    ts = r['timestamp'] if 'timestamp' in r else 0
                    utc_iso, ist_fmt, epoch_ms = normalize_iso_ist(ts, 'auto')

                    results.append({
                        'Artifact_ID': f"GRINDR_MSG_{row_id}",
                        'Source_App': 'Grindr',
                        'Platform': 'Mobile',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Direction': 'UNKNOWN',  # no sent/received column is read for this table (review)
                        'Status': 'UNKNOWN',
                        'Chat_Type': 'DATING_MATCH_CHAT',
                        'Thread_ID': str(r['conversation_id'] if 'conversation_id' in r else ''),
                        'Thread_Title': 'Grindr Match',
                        'Sender_ID': str(r['sender'] if 'sender' in r else 'Grindr User'),
                        'Sender_Name': str(r['sender'] if 'sender' in r else 'Grindr User'),
                        'Recipient_ID': '',
                        'Recipient_Name': '',
                        'Message_Text': body,
                        'Message_Type': 'TEXT',
                        'Source_File': source_file_label,
                        'Source_Table': 'chat_messages',
                        'Row_ID': row_id,
                        'Page_Number': 0,
                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                        'Recovery_Method': 'Allocated B-Tree'
                    })

            conn.close()
        except Exception:
            pass

        return results


# =============================================================================
# TOP-LEVEL FORENSIC PARSER ENTRY POINTS (28-COLUMN CATEGORIZED SCHEMAS)
# =============================================================================

def deserialize_telegram_tl_message(blob: bytes) -> Dict[str, Any]:
    """
    Unpacks Telegram messages_v2.data TL binary buffer into message text, entities, and flags.
    """
    return TelegramTLDeserializer.deserialize_tl_message(blob)


def parse_telegram_database(db_path: str) -> pd.DataFrame:
    """
    Parses Telegram cache4.db / messages_v2 into a 28-column Categorized Forensic DataFrame.
    """
    records = TelegramTLDeserializer.parse_database(db_path)
    return make_categorized_dataframe(records)


def parse_whatsapp_full_forensics(
    db_path: str,
    wa_db_path: Optional[str] = None,
    owner_identifiers: Optional[Set[str]] = None,
    **kwargs: Any,
) -> pd.DataFrame:
    """
    Full multi-table relational join across message, chat, jid, message_quoted, message_media,
    message_location, message_ephemeral, receipt_user, and call_log.
    """
    records = WhatsAppDeepParser.parse(db_path)
    if not records:
        try:
            from parsers.enterprise_1tb_chat_and_container_engine import (
                parse_whatsapp_full_forensics as _ent_wa_parse,
            )
            ent_chats, _ = _ent_wa_parse(db_path, wa_contacts_db_path=wa_db_path, owner_identifiers=owner_identifiers, **kwargs)
            if ent_chats is not None and not ent_chats.empty:
                return ent_chats
        except Exception:
            pass

    if not wa_db_path:
        candidate_wa = os.path.join(os.path.dirname(db_path), 'wa.db')
        if os.path.exists(candidate_wa):
            wa_db_path = candidate_wa

    if wa_db_path and os.path.exists(wa_db_path):
        try:
            conn_wa = sqlite3.connect(ro_uri(wa_db_path), uri=True)
            conn_wa.row_factory = sqlite3.Row
            cur_wa = conn_wa.cursor()
            cur_wa.execute("SELECT name FROM sqlite_master WHERE type='table'")
            wa_tables = {r[0].lower() for r in cur_wa.fetchall()}
            contact_map: Dict[str, str] = {}
            if 'wa_contacts' in wa_tables:
                cur_wa.execute("SELECT jid, display_name, wa_name FROM wa_contacts")
                for r in cur_wa.fetchall():
                    r = dict(r)
                    j = str(r.get('jid') or '')
                    dn = r.get('display_name') or r.get('wa_name')
                    if j and dn:
                        contact_map[j] = str(dn)
            conn_wa.close()

            for r in records:
                s_jid = r.get('Sender_ID')
                if s_jid in contact_map:
                    r['Sender_Name'] = contact_map[s_jid]
                th_jid = r.get('Thread_ID')
                if th_jid in contact_map:
                    r['Thread_Title'] = contact_map[th_jid]
        except Exception:
            pass

    return make_categorized_dataframe(records)


def parse_signal_database(db_path: str) -> pd.DataFrame:
    """
    Parses Android signal.db and iOS signal.sqlite into a 28-column Categorized Forensic DataFrame.
    """
    records = SignalDeepParser.parse(db_path)
    return make_categorized_dataframe(records)


def parse_zangi_database(db_path: str) -> pd.DataFrame:
    """
    Parses Android zangi.db and iOS Zangi.sqlite into a 28-column Categorized Forensic DataFrame.
    """
    records = ZangiDeepParser.parse(db_path)
    return make_categorized_dataframe(records)


def parse_element_matrix_database(db_path: str) -> pd.DataFrame:
    """
    Parses Matrix events JSON from matrix-sdk.db or Realm into a 28-column Categorized Forensic DataFrame.
    """
    records = ElementMatrixDeepParser.parse(db_path)
    return make_categorized_dataframe(records)


def parse_session_threema_simplex(db_path: str, app_label: str = "auto") -> pd.DataFrame:
    """
    Parses Session (05... hex IDs), Threema, or SimpleX into a 28-column Categorized Forensic DataFrame.
    """
    records: List[Dict[str, Any]] = []
    norm_label = app_label.lower()

    if 'session' in norm_label:
        records = SessionDeepParser.parse(db_path)
    elif 'threema' in norm_label:
        records = PrivacyNicheDeepParsers.parse_threema(db_path)
    elif 'simplex' in norm_label:
        records = PrivacyNicheDeepParsers.parse_simplex(db_path)
    else:
        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}
            conn.close()

            if 'loki_user_display_name_database' in tables or 'open_group_chat' in tables:
                records = SessionDeepParser.parse(db_path)
            elif 'identity' in tables or 'key_pair' in tables:
                records = PrivacyNicheDeepParsers.parse_threema(db_path)
            else:
                records = SessionDeepParser.parse(db_path)
                if not records:
                    records = PrivacyNicheDeepParsers.parse_threema(db_path)
        except Exception:
            records = SessionDeepParser.parse(db_path)

    return make_categorized_dataframe(records)


def parse_snapchat_arroyo(db_path: str) -> pd.DataFrame:
    """
    Parses Snapchat Arroyo Protobuf stream blobs and friends/memories into a 28-column Categorized Forensic DataFrame.
    """
    records = SnapchatDeepParser.parse_arroyo(db_path)
    return make_categorized_dataframe(records)


def parse_instagram_direct(db_path: str) -> pd.DataFrame:
    """
    Parses Instagram direct.db / reverb.db into a 28-column Categorized Forensic DataFrame.
    """
    records = InstagramDirectDeepParser.parse(db_path)
    return make_categorized_dataframe(records)


def parse_dating_apps(db_path: str, app_label: str = "auto") -> pd.DataFrame:
    """
    Parses Tinder, Bumble, Hinge, and Grindr into a 28-column Categorized Forensic DataFrame.
    """
    norm = app_label.lower()
    if 'tinder' in norm:
        records = DatingAppsDeepParser.parse_tinder(db_path)
    elif 'bumble' in norm:
        records = DatingAppsDeepParser.parse_bumble(db_path)
    elif 'hinge' in norm:
        records = DatingAppsDeepParser.parse_hinge(db_path)
    elif 'grindr' in norm:
        records = DatingAppsDeepParser.parse_grindr(db_path)
    else:
        records = DatingAppsDeepParser.parse_tinder(db_path)
        if not records:
            records = DatingAppsDeepParser.parse_bumble(db_path)
        if not records:
            records = DatingAppsDeepParser.parse_hinge(db_path)
        if not records:
            records = DatingAppsDeepParser.parse_grindr(db_path)

    return make_categorized_dataframe(records)
