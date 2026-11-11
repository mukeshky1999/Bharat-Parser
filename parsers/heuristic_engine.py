"""
Forensic SQLite Heuristic Engine (Cellebrite Chat & Clean Contact Edition).
Fixes:
- Eliminates raw Python bytes repr (`b'\\n\\x00\\x12...'`) and internal sync keys
  (`a:conversation_info_fetch:...`, `a:offers_rewards:...`) from In-App Chats.
- Joins WhatsApp `message` + `chat` + `jid` tables so 1-on-1 and Group Chats show real
  phone numbers and group titles.
- Blocks Base64 Protobuf tokens (`CgI0MRAD`, `CgI0MhAD`) from Saved Contacts.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
import json
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np
import pandas as pd

from parsers import is_safe_sqlite_table_name, quote_sqlite_identifier
from parsers.app_overrides import (
    PROMO_SPAM_RE,
    extract_date_from_phonepe_tid,
    extract_from_blob,
    format_counterparty_display,
    get_app_override,
    is_valid_counterparty,
    is_valid_txid,
    matches_owner_identity,
    normalize_timestamp_value,
    parse_indian_financial_text,
    resolve_payer_payee_counterparty,
)
from parsers.corrupt_db_carver import carve_corrupted_sqlite_file
from parsers.freelist_carver import KNOWN_UPI_SUFFIXES, carve_sqlite_freelists
from parsers.npci_storage_carver import NPCI_TXID_REGEX, parse_npci_upi_uri
from parsers.protobuf_decoder import (
    ProtobufSchemaSynthesizer,
    decode_protobuf_stream,
)
from parsers.vpa_harvester import (
    UPI_HANDLE_DIRECTORY,
    clean_and_validate_vpa,
    is_valid_indian_mobile,
)
from parsers.wal_rollback_analyzer import analyze_wal_revisions
from parsers.chat_social_privacy_parsers import (
    CATEGORIZED_FORENSIC_COLUMNS,
    deserialize_telegram_tl_message,
    make_categorized_dataframe,
    parse_dating_apps,
    parse_element_matrix_database,
    parse_instagram_direct,
    parse_session_threema_simplex,
    parse_signal_database,
    parse_snapchat_arroyo,
    parse_telegram_database,
    parse_zangi_database,
)
from parsers.enterprise_1tb_chat_and_container_engine import (
    parse_whatsapp_full_forensics,
)
try:
    from parsers.social_interaction_comms_parsers import (
        parse_facebook_messenger_database,
        parse_discord_database,
        parse_skype_teams_database,
        parse_viber_database,
        parse_wechat_database,
        parse_line_database,
        parse_imo_kakaotalk_database,
        parse_twitter_threads_reddit_linkedin,
        parse_truecaller_database,
        parse_olx_database,
        parse_sharechat_moj_database,
    )
except Exception:
    pass


AMOUNT_PATTERNS = [
    'amount', 'amt', 'txnamount', 'transamount', 'paidamount', 'totalamount',
    'receivedamount', 'debitamount', 'creditamount', 'billamount', 'transferamount',
    'netamount', 'inramount', 'paymentamount', 'zamount', 'amount1000', 'zamount1000',
    'amountpaise', 'amountminor', 'amountmicros', 'amountcent', 'amountinpaise',
    'amountinpaisa', 'principal', 'settlementamount', 'tranamt', 'withdrawalamt', 'depositamt',
]

DATE_PATTERNS = [
    'date', 'time', 'timestamp', 'created', 'initiat', 'booking', 'sentat',
    'receivedat', 'txndate', 'txntime', 'transactiontime', 'bookingdate',
    'ztimestamp', 'zcreatedat', 'zdate', 'zbookingdate', 'zmessagedate', 'ts',
    'postdate', 'valdate', 'valuedate', 'mtime', 'createdtime', 'paymenttime',
    'inittimestamp', 'receivedtimestamp', 'posttime', 'updatedat', 'lastmodified',
]

PAYER_COL_PATTERNS = [
    'payervpa', 'sendervpa', 'fromvpa', 'remittervpa', 'zpayervpa', 'zfromjid',
    'payername', 'sendername', 'fromname', 'payer', 'sender', 'remitter', 'senderjid',
]

PAYEE_COL_PATTERNS = [
    'payeevpa', 'receivervpa', 'recipientvpa', 'tovpa', 'beneficiaryvpa', 'zpayeevpa',
    'ztojid', 'payeename', 'receivername', 'recipientname', 'beneficiaryname',
    'merchantname', 'zpayeename', 'payee', 'receiver', 'recipient', 'beneficiary',
    'merchant', 'receiverjid',
]

CPTY_PATTERNS = [
    'counterparty', 'payeevpa', 'payervpa', 'payee', 'receiver', 'recipient',
    'sender', 'beneficiary', 'payer', 'merchant', 'vpa', 'upiid', 'upihandle',
    'narration', 'zpayeename', 'zpayeevpa', 'zcounterparty', 'zrecipient',
    'payeename', 'receivername', 'merchantname', 'payername', 'contactname',
    'toname', 'fromname', 'particulars', 'remarks', 'title', 'subtitle',
    'symbol', 'market', 'pair', 'coin', 'asset', 'currency', 'biller', 'operator', 'store',
]

TXID_PATTERNS = [
    'txid', 'txnid', 'transactionid', 'transid', 'orderno', 'orderid',
    'referenceid', 'refid', 'bankrefno', 'utr', 'ztransactionid',
    'ztransactionreferenceid', 'zentityid', 'keyid', 'serialno', 'banktransactionid',
    'tx_id', 'upi_txn_id', 'ref_no', 'refnum', 'journal_no', 'cheque_no',
    'bank_txn_id', 'payment_id', 'tranid', 'chqrefno',
]

STATUS_PATTERNS = [
    'status', 'state', 'txnstatus', 'orderstatus', 'zstatus', 'zstate',
    'responsecode', 'result', 'paymentstatus', 'txstatus', 'transactionstatus',
]

TYPE_PATTERNS = [
    'type', 'txntype', 'transactiontype', 'paymenttype', 'flow', 'direction',
    'drcr', 'crdr', 'ztype', 'zflow', 'iscredit', 'isdebit', 'txnflow',
]

BLOB_PATTERNS = [
    'blob', 'proto', 'payload', 'data', 'bytes', 'item', 'feedpayload',
    'syncpayload', 'zdata', 'zdetails', 'contentblob', 'feeditem',
    'transactiondata', 'responsedata', 'metadata', 'futuredata', 'zpayload',
    'entityproto', 'protobytes', 'serialized', 'rawdata', 'value',
]

CHAT_PATTERNS = [
    'message', 'body', 'text', 'ztext', 'zmessage', 'payloadtext', 'note',
    'content', 'snippet',
]

CHAT_FROM_ME_PATTERNS = [
    'keyfromme', 'fromme', 'zisfromme', 'isfromme', 'out', 'issent',
    'isoutgoing', 'issender', 'isowner',
]

CHAT_SENDER_PATTERNS = [
    'sender', 'senderid', 'sendervpa', 'sendername', 'from', 'fromid',
    'fromjid', 'zfromjid', 'fromvpa', 'author', 'origin', 'creator', 'participantjid',
]

CHAT_RECIPIENT_PATTERNS = [
    'recipient', 'recipientid', 'recipientvpa', 'receiver', 'receiverid',
    'receivervpa', 'to', 'toid', 'tojid', 'ztojid', 'tovpa', 'destination',
]

CHAT_THREAD_PATTERNS = [
    'keyremotejid', 'remotejid', 'chatid', 'threadid', 'conversationid',
    'peerid', 'address', 'zchatsession', 'zpartnername', 'counterparty',
]

NOTIF_TITLE_PATTERNS = ['title', 'header', 'ztitle', 'subject', 'app_name', 'pkg']
NOTIF_BODY_PATTERNS = ['body', 'desc', 'description', 'zbody', 'message', 'text', 'content', 'details', 'ticker_text']

_EXCLUDE_AMOUNT_SUFFIXES = (
    '_id', 'id', '_no', 'no', '_num', 'num', '_count', 'count',
    '_code', 'code', '_token', 'token', '_status', 'status',
    '_type', 'type', '_date', 'date', '_time', 'time', 'timestamp', 'flags', 'version',
)

_AMOUNT_MAX_ABS = 5_000_000.0

_ALL_VALID_UPI_HANDLES = tuple(sorted(set(UPI_HANDLE_DIRECTORY.keys()) | set(KNOWN_UPI_SUFFIXES), key=len, reverse=True))
_VPA_CONTENT_RE = re.compile(
    r'\b[a-zA-Z0-9.\-_]{3,64}@(' + '|'.join(_ALL_VALID_UPI_HANDLES) + r')\b',
    re.IGNORECASE,
)

_WHATSAPP_NON_PAYMENT_TABLES = {
    'message', 'messages', 'message_view', 'available_message_view', 'chat', 'chat_view',
    'jid', 'jid_map', 'lid_chat_state', 'lid_display_name', 'receipt_user', 'receipt_device',
    'message_media', 'message_quoted', 'message_system', 'message_vcard', 'call_log',
    'group_participant_user', 'wa_contacts', 'wa_vnames', 'zwamessage', 'zwachatssession',
}

# Blocks internal sync keys, RPC IDs, and Base64 Protobuf tokens (e.g. a:conversation_info_fetch:..., CgI0MRAD)
_INTERNAL_SYNC_NOISE_RE = re.compile(
    r'^(?:'
    r'a:[a-z0-9_]+:|'
    r'sync_|workspec|androidx\.|com\.google\.|java\.lang\.|'
    r'Cg[A-Za-z0-9+/=]{4,24}$|'
    r'[0-9a-f]{24,64}$|'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    r')',
    re.IGNORECASE,
)

_CHAT_PROMO_NOISE_RE = re.compile(
    r'('
    r'scratch,\s*pick\s*and\s*redeem|reward\s+needs\s+your\s+action|'
    r'conversation_info_fetch|offers_rewards|'
    r'\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}|'
    r'^b[\'"]\\n'
    r')',
    re.IGNORECASE,
)


def _match_column(
    col_map: Dict[str, str],
    patterns: List[str],
    exclude_suffixes: Tuple[str, ...] = (),
) -> Optional[str]:
    for p in patterns:
        p_norm = re.sub(r'[^a-zA-Z0-9]', '', p.lower())
        for norm_col, orig_col in col_map.items():
            if norm_col == p_norm:
                if not any(norm_col.endswith(sfx) for sfx in exclude_suffixes):
                    return orig_col

    for p in patterns:
        p_norm = re.sub(r'[^a-zA-Z0-9]', '', p.lower())
        for norm_col, orig_col in col_map.items():
            if norm_col.endswith(p_norm) or norm_col.startswith(p_norm):
                if not any(norm_col.endswith(sfx) for sfx in exclude_suffixes):
                    return orig_col

    for p in patterns:
        p_norm = re.sub(r'[^a-zA-Z0-9]', '', p.lower())
        for norm_col, orig_col in col_map.items():
            if p_norm in norm_col:
                if not any(norm_col.endswith(sfx) for sfx in exclude_suffixes):
                    return orig_col
    return None


def _is_valid_human_contact(name_val: Any, id_val: Any = None) -> bool:
    """
    Validates Saved Contacts and Conversation Partners so Base64 Protobuf tokens (`CgI0MRAD`),
    internal sync keys (`a:conversation_info_fetch:...`), and numeric flags are rejected.
    """
    if name_val is None or pd.isna(name_val):
        return False
    s = str(name_val).strip()
    if len(s) < 2 or len(s) > 85:
        return False
    if s.lower() in ('none', 'nan', 'null', 'n/a', 'unknown', 'true', 'false', '0', '-1', 'counterparty', 'user'):
        return False
    if _INTERNAL_SYNC_NOISE_RE.search(s) or _CHAT_PROMO_NOISE_RE.search(s):
        return False
    if id_val is not None and not pd.isna(id_val):
        id_s = str(id_val).strip()
        if _INTERNAL_SYNC_NOISE_RE.search(id_s):
            return False
    # Reject single random CamelCase/Base64 tokens without spaces unless they are a valid VPA or 10-digit mobile
    if ' ' not in s and '@' not in s and not s.startswith('+91'):
        digits = re.sub(r'\D', '', s)
        if len(digits) == 10 and is_valid_indian_mobile(digits):
            return True
        if (re.match(r'^[A-Z][a-z]+[0-9]+[A-Za-z0-9]*$', s) or re.match(r'^[A-Za-z0-9+/=]{6,16}$', s)) and any(c.isdigit() for c in s) and any(c.isupper() for c in s):
            return False
    return True


def _format_chat_participant(raw_val: Any) -> Tuple[str, str]:
    """
    Formats raw JIDs, phone numbers, and VPAs into (clean_label, chat_type).
    chat_type is either '👥 Group Chat' or '👤 Direct (1-on-1)'.
    """
    if raw_val is None or pd.isna(raw_val):
        return '', '👤 Direct (1-on-1)'
    s = str(raw_val).strip()
    if not s or s.lower() in ('none', 'nan', 'null', 'n/a', 'unknown', 'counterparty', '0', '-1'):
        return '', '👤 Direct (1-on-1)'
    if s.endswith('@broadcast') or 'status@' in s.lower() or _INTERNAL_SYNC_NOISE_RE.search(s):
        return '', '👤 Direct (1-on-1)'

    if s.endswith('@g.us') or 'group' in s.lower():
        grp_id = s.split('@')[0]
        return f"Group Chat ({grp_id[:16]})", '👥 Group Chat'
    if s.endswith(('@s.whatsapp.net', '@c.us')):
        num = s.split('@')[0]
        if len(num) == 12 and num.startswith('91') and num[2:].isdigit():
            return f"+91 {num[2:]}", '👤 Direct (1-on-1)'
        return num, '👤 Direct (1-on-1)'
    if s.endswith('@lid'):
        return f"Contact #{s.split('@')[0][:10]}", '👤 Direct (1-on-1)'
    if re.match(r'^[6-9]\d{9}$', s):
        return f"+91 {s}", '👤 Direct (1-on-1)'
    return s[:75], '👤 Direct (1-on-1)'


def _unpack_chat_message_content(raw_msg: Any) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Unpacks chat message payloads while strictly rejecting binary Protobuf dumps (`b'\\n\\x00...'`),
    hex escape sequences, and promotional scratch-card notifications.
    """
    if raw_msg is None or pd.isna(raw_msg):
        return '', None, None, None

    if isinstance(raw_msg, (bytes, bytearray)):
        # Never turn raw binary into "b'\x00...'"! Only accept clean UTF-8 text or JSON
        try:
            s = raw_msg.decode('utf-8').strip()
        except UnicodeDecodeError:
            return '', None, None, None
    else:
        s = str(raw_msg).strip()

    if not s or len(s) < 1 or s.lower() in ('none', 'nan', 'null'):
        return '', None, None, None

    # Reject stringified Python byte literals `b'...'` or `b"..."` and escaped binary blobs
    if (s.startswith(("b'", 'b"')) and ('\\x' in s or '\\n' in s)) or '\\x00' in s:
        return '', None, None, None
    if _CHAT_PROMO_NOISE_RE.search(s) or _INTERNAL_SYNC_NOISE_RE.search(s):
        return '', None, None, None

    # Reject strings with excessive non-printable control characters
    non_printable = sum(1 for c in s if ord(c) < 32 and c not in ('\n', '\r', '\t'))
    if non_printable > 0:
        return '', None, None, None

    if s.startswith('{') and s.endswith('}'):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                msg_parts = []
                for k in ('text', 'message', 'body', 'note', 'description', 'title', 'heading', 'subText'):
                    if obj.get(k) and isinstance(obj[k], (str, int, float)):
                        val_k = str(obj[k]).strip()
                        if val_k and not _CHAT_PROMO_NOISE_RE.search(val_k):
                            msg_parts.append(val_k)
                amt = obj.get('amount') or obj.get('amountInPaise')
                if amt is not None:
                    try:
                        amt_f = float(amt) / 100.0 if 'paise' in str(obj.keys()).lower() else float(amt)
                        if amt_f > 0:
                            msg_parts.append(f"💸 [Payment: ₹{amt_f:,.2f}]")
                    except Exception:
                        pass
                emb_sender = obj.get('senderId') or obj.get('senderVpa') or obj.get('from') or obj.get('payerVpa')
                emb_recip = obj.get('receiverId') or obj.get('receiverVpa') or obj.get('to') or obj.get('payeeVpa')
                emb_dir = obj.get('direction') or obj.get('type')
                clean_text = ' — '.join(dict.fromkeys(p for p in msg_parts if p))
                if clean_text:
                    return (
                        clean_text,
                        (str(emb_sender) if emb_sender else None),
                        (str(emb_recip) if emb_recip else None),
                        (str(emb_dir) if emb_dir else None),
                    )
                return '', None, None, None
        except Exception:
            pass

    return s, None, None, None


def _try_extract_whatsapp_joined_chats(
    conn: sqlite3.Connection,
    tables: List[str],
    local_owners: Set[str],
) -> Optional[pd.DataFrame]:
    """
    If the database is a modern Android/iOS WhatsApp `msgstore.db` or `ChatStorage.sqlite`,
    executes a direct SQL JOIN across `message`, `chat`, and `jid` so 1-on-1 and Group Chats
    have exact contact phone numbers, group subjects, and group member senders.
    """
    tables_low = {t.lower(): t for t in tables}
    out_cols = ['Timestamp', 'Chat_Type', 'Direction', 'Contact_Thread', 'Sender', 'Recipient', 'Message']

    # Modern Android WhatsApp (`message` + `chat` + `jid`)
    if 'message' in tables_low and 'chat' in tables_low and 'jid' in tables_low:
        q = """
        SELECT
            m.timestamp AS ts,
            m.from_me AS from_me,
            m.text_data AS body,
            c.subject AS group_subject,
            j_chat.raw_string AS chat_jid,
            j_sender.raw_string AS sender_jid
        FROM message m
        INNER JOIN chat c ON m.chat_row_id = c._id
        INNER JOIN jid j_chat ON c.jid_row_id = j_chat._id
        LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id
        WHERE m.text_data IS NOT NULL AND length(trim(m.text_data)) > 0
        ORDER BY m.timestamp DESC
        LIMIT 20000
        """
        try:
            df = pd.read_sql_query(q, conn)
            if not df.empty:
                rows: List[Dict[str, Any]] = []
                for _, r in df.iterrows():
                    raw_chat_jid = str(r.get('chat_jid', '') or '')
                    if 'broadcast' in raw_chat_jid or 'status@' in raw_chat_jid:
                        continue
                    body_txt, _, _, _ = _unpack_chat_message_content(r.get('body'))
                    if not body_txt:
                        continue

                    ts_str = normalize_timestamp_value(r.get('ts'), 'unix_ms') or ''
                    is_sent = str(r.get('from_me', '0')).strip() in ('1', '1.0', 'true', 'True')
                    direction = 'SENT' if is_sent else 'RECEIVED'

                    thread_label, chat_type = _format_chat_participant(raw_chat_jid)
                    grp_subj = str(r.get('group_subject', '') or '').strip()
                    if grp_subj and grp_subj.lower() not in ('none', 'null', ''):
                        thread_label = f"{grp_subj} ({thread_label})"
                        chat_type = '👥 Group Chat'

                    if not thread_label:
                        continue

                    sender_jid_raw = str(r.get('sender_jid', '') or '')
                    member_label, _ = _format_chat_participant(sender_jid_raw)

                    if direction == 'SENT':
                        sender_disp = 'This Phone (Owner)'
                        recip_disp = thread_label
                    else:
                        sender_disp = f"{member_label} [in {thread_label}]" if (chat_type == '👥 Group Chat' and member_label) else thread_label
                        recip_disp = 'This Phone (Owner)'

                    rows.append({
                        'Timestamp': ts_str,
                        'Chat_Type': chat_type,
                        'Direction': direction,
                        'Contact_Thread': thread_label,
                        'Sender': sender_disp,
                        'Recipient': recip_disp,
                        'Message': body_txt[:4000],
                    })
                if rows:
                    return pd.DataFrame(rows, columns=out_cols)
        except Exception:
            pass
    return None


def _normalize_chat_dataframe(
    raw_c: pd.DataFrame,
    col_map: Dict[str, str],
    date_col: Optional[str],
    msg_col: str,
    cparty_col: Optional[str],
    epoch: str,
    local_owners: Set[str],
) -> pd.DataFrame:
    """
    Builds a clean, Cellebrite-Reader-ready Chat DataFrame with columns:
    ['Timestamp', 'Chat_Type', 'Direction', 'Contact_Thread', 'Sender', 'Recipient', 'Message']
    """
    out_cols = ['Timestamp', 'Chat_Type', 'Direction', 'Contact_Thread', 'Sender', 'Recipient', 'Message']
    if raw_c is None or raw_c.empty or msg_col not in raw_c.columns:
        return pd.DataFrame(columns=out_cols)

    from_me_col = _match_column(col_map, CHAT_FROM_ME_PATTERNS)
    sender_col = _match_column(col_map, CHAT_SENDER_PATTERNS)
    recipient_col = _match_column(col_map, CHAT_RECIPIENT_PATTERNS)
    thread_col = _match_column(col_map, CHAT_THREAD_PATTERNS) or cparty_col
    type_col = _match_column(col_map, TYPE_PATTERNS)

    chat_owners: Set[str] = set(local_owners) if local_owners else set()

    if sender_col and recipient_col and sender_col != recipient_col and len(raw_c) >= 4:
        all_parties = (
            list(raw_c[sender_col].dropna().astype(str))
            + list(raw_c[recipient_col].dropna().astype(str))
        )
        valid_parties = [
            p.strip().lower() for p in all_parties
            if p.strip() and p.strip().lower() not in ('none', 'nan', 'null', 'unknown', 'counterparty', '0')
        ]
        if valid_parties:
            top_p, top_cnt = Counter(valid_parties).most_common(1)[0]
            if top_cnt >= len(raw_c) * 0.45:
                chat_owners.add(top_p)

    rows: List[Dict[str, Any]] = []
    for _, r in raw_c.iterrows():
        msg_text, emb_sender, emb_recip, emb_dir = _unpack_chat_message_content(r.get(msg_col))
        if len(msg_text) < 1:
            continue

        ts_str = normalize_timestamp_value(r.get(date_col), epoch=epoch) if date_col else None

        s_raw = r.get(sender_col) if sender_col else emb_sender
        rec_raw = r.get(recipient_col) if recipient_col else emb_recip
        thr_raw = r.get(thread_col) if thread_col else None

        # Reject rows whose sender/thread is an internal sync key (e.g. a:conversation_info_fetch:...)
        if any(_INTERNAL_SYNC_NOISE_RE.search(str(x or '')) for x in (s_raw, rec_raw, thr_raw)):
            continue

        s_clean, s_type = _format_chat_participant(s_raw)
        rec_clean, rec_type = _format_chat_participant(rec_raw)
        thr_clean, thr_type = _format_chat_participant(thr_raw)

        chat_type = '👥 Group Chat' if '👥 Group Chat' in (s_type, rec_type, thr_type) else '👤 Direct (1-on-1)'

        direction: Optional[str] = None
        if from_me_col and pd.notna(r.get(from_me_col)):
            fm_val = str(r.get(from_me_col)).strip().lower()
            if fm_val in ('1', '1.0', 'true', 't', 'yes', 'out', 'sent'):
                direction = 'SENT'
            elif fm_val in ('0', '0.0', 'false', 'f', 'no', 'in', 'received'):
                direction = 'RECEIVED'

        if direction is None and type_col and pd.notna(r.get(type_col)):
            t_val = str(r.get(type_col)).strip().upper()
            if t_val in ('2', '2.0', 'SENT', 'OUT', 'OUTGOING', 'SEND', 'DEBIT'):
                direction = 'SENT'
            elif t_val in ('1', '1.0', 'INBOX', 'RECEIVED', 'IN', 'INCOMING', 'RECV', 'CREDIT'):
                direction = 'RECEIVED'

        if direction is None and emb_dir:
            ed_up = emb_dir.strip().upper()
            if any(k in ed_up for k in ('SENT', 'OUT', 'DEBIT', 'SEND')):
                direction = 'SENT'
            elif any(k in ed_up for k in ('RECV', 'RECEIVED', 'IN', 'CREDIT')):
                direction = 'RECEIVED'

        if direction is None:
            s_is_owner = (
                matches_owner_identity(s_raw, chat_owners)
                or any(w in s_clean.lower() for w in ('local device', 'this phone', 'me', 'self'))
            )
            rec_is_owner = (
                matches_owner_identity(rec_raw, chat_owners)
                or any(w in rec_clean.lower() for w in ('local device', 'this phone', 'me', 'self'))
            )
            if s_is_owner and not rec_is_owner:
                direction = 'SENT'
            elif rec_is_owner and not s_is_owner:
                direction = 'RECEIVED'
            elif s_clean and rec_clean and s_clean != rec_clean:
                direction = 'SENT'
            else:
                direction = 'RECEIVED'

        candidates = [thr_clean, rec_clean, s_clean] if chat_type == '👥 Group Chat' else (
            [rec_clean, thr_clean, s_clean] if direction == 'SENT' else [s_clean, thr_clean, rec_clean]
        )
        external_contact = ''
        for cand in candidates:
            if (
                cand
                and not matches_owner_identity(cand, chat_owners)
                and not any(w in cand.lower() for w in ('local device', 'this phone', 'counterparty', 'unknown'))
                and not _INTERNAL_SYNC_NOISE_RE.search(cand)
            ):
                external_contact = cand
                break

        # Skip unanchored system/notification rows that have no valid conversation partner and no timestamp
        if not external_contact:
            if not ts_str:
                continue
            external_contact = 'In-App Payment Chat'

        if direction == 'SENT':
            sender_display = 'This Phone (Owner)'
            recipient_display = external_contact
        else:
            sender_display = f"{s_clean} [in {external_contact}]" if (chat_type == '👥 Group Chat' and s_clean and s_clean != external_contact) else external_contact
            recipient_display = 'This Phone (Owner)'

        raw_ts_val = r.get(date_col) if date_col else None
        ts_utc_val = ts_str or ''
        epoch_ms_val = None
        try:
            if raw_ts_val is not None:
                numeric_ts = float(raw_ts_val)
                if numeric_ts > 1e11:
                    epoch_ms_val = int(numeric_ts)
                elif numeric_ts > 1e8:
                    epoch_ms_val = int(numeric_ts * 1000)
        except Exception:
            pass

        rows.append({
            'Artifact_ID': f"GEN_CHAT_{len(rows) + 1}",
            'Source_App': 'Generic Chat DB',
            'Chat_Type': chat_type,
            'Thread_ID': external_contact,
            'Thread_Title': external_contact,
            'Message_Text': msg_text[:4000],
            'Message_Type': 'TEXT',
            'Direction': direction,
            'Status': 'READ',
            'Quoted_Message_Text': None,
            'Sender_ID': sender_display,
            'Sender_Name': sender_display,
            'Recipient_ID': recipient_display,
            'Recipient_Name': recipient_display,
            'Is_Ephemeral': False,
            'Ephemeral_Duration_Seconds': None,
            'Ephemeral_Expire_Timestamp': None,
            'Forwarding_Score': 0,
            'Is_Starred': False,
            'Is_Deleted': False,
            'Timestamp_Raw': str(raw_ts_val or ''),
            'Timestamp_UTC': ts_utc_val,
            'Timestamp_IST': ts_utc_val,
            'Epoch_MS': epoch_ms_val,
            'Attachment_Path': None,
            'Attachment_MIME': None,
            'Attachment_Size': None,
            'Attachment_Hash': None,
            'Latitude': None,
            'Longitude': None,
            'Location_Name': None,
            'Source_File': 'database.sqlite',
            'Source_Table': 'messages',
            'Row_ID': len(rows) + 1,
            'Page_Number': 1,
            'Byte_Offset': 0,
            'Recovery_Method': 'Allocated B-Tree',
            'Timestamp': ts_str or '',
            'Contact_Thread': external_contact,
            'Sender': sender_display,
            'Recipient': recipient_display,
            'Message': msg_text[:4000],
        })

    if not rows:
        return pd.DataFrame(columns=CATEGORIZED_FORENSIC_COLUMNS + out_cols)
    return pd.DataFrame(rows).drop_duplicates()


def _classify_columns_by_content(df: pd.DataFrame) -> Dict[str, str]:
    inferred: Dict[str, str] = {}
    if df is None or df.empty or len(df.columns) < 2:
        return inferred

    sample = df.head(200)
    used_cols: set = set()

    for col in sample.columns:
        s_vals = sample[col].dropna().astype(str)
        if s_vals.empty:
            continue
        vpa_hits = s_vals.apply(lambda x: bool(_VPA_CONTENT_RE.search(x))).mean()
        if vpa_hits >= 0.15:
            inferred['cparty_col'] = col
            used_cols.add(col)
            break

    for col in sample.columns:
        if col in used_cols:
            continue
        s_vals = sample[col].dropna().astype(str).str.strip()
        if s_vals.empty:
            continue
        txid_hits = s_vals.apply(
            lambda x: bool(re.match(r'^[0-9]{12}$', x) or re.match(r'^T\d{18,24}$', x) or NPCI_TXID_REGEX.match(x))
        ).mean()
        if txid_hits >= 0.20:
            inferred['txid_col'] = col
            used_cols.add(col)
            break

    for col in sample.columns:
        if col in used_cols:
            continue
        num_vals = pd.to_numeric(sample[col], errors='coerce').dropna()
        if not num_vals.empty:
            med = num_vals.median()
            if (1.42e9 <= med <= 2.05e9) or (1.42e12 <= med <= 2.05e12) or (4.5e8 <= med <= 1.0e9):
                inferred['date_col'] = col
                used_cols.add(col)
                break
        else:
            s_vals = sample[col].dropna().astype(str)
            if not s_vals.empty and s_vals.str.match(r'^\d{4}-\d{2}-\d{2}').mean() >= 0.4:
                inferred['date_col'] = col
                used_cols.add(col)
                break

    for col in sample.columns:
        if col in used_cols:
            continue
        s_vals = sample[col].dropna().astype(str).str.upper().str.strip()
        if s_vals.empty:
            continue
        if s_vals.isin({'SUCCESS', 'COMPLETED', 'FAILED', 'PENDING', 'INITIATED', 'FAILURE'}).mean() >= 0.35:
            inferred['status_col'] = col
            used_cols.add(col)
        elif s_vals.isin({'DEBIT', 'CREDIT', 'DR', 'CR', 'SENT', 'RECEIVED', 'PAID', 'P2P', 'P2M'}).mean() >= 0.35:
            inferred['type_col'] = col
            used_cols.add(col)

    if 'cparty_col' in inferred or 'txid_col' in inferred:
        for col in sample.columns:
            if col in used_cols:
                continue
            col_low = str(col).lower()
            if any(col_low.endswith(sfx) for sfx in _EXCLUDE_AMOUNT_SUFFIXES):
                continue
            num_vals = pd.to_numeric(sample[col], errors='coerce').dropna()
            if len(num_vals) < 1:
                continue
            if len(num_vals) >= 4 and num_vals.is_monotonic_increasing and (num_vals.diff().dropna() == 1).mean() > 0.8:
                continue
            if (num_vals > 0).mean() >= 0.7 and (num_vals <= 5_000_000).mean() >= 0.8:
                inferred['amt_col'] = col
                used_cols.add(col)
                break

    return inferred


def extract_profile_from_sqlite(db_path: str) -> Dict[str, Any]:
    prof: Dict[str, Any] = {}
    if not os.path.exists(db_path):
        return prof

    from parsers.account_profiler import _inspect_key_val

    conn = None
    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall() if not r[0].startswith(('sqlite_', 'android_'))]

        profile_table_hints = ('user_info', 'user_profile', 'profile', 'account', 'vpa', 'owner', 'customer', 'kyc', 'self', 'rkstorage', 'catalyst')
        skip_contact_hints = ('contact', 'wa_', 'chat', 'message', 'jid', 'participant', 'group', 'call', 'friend', 'peer')
        candidate_tables = [
            t for t in tables
            if any(h in t.lower() for h in profile_table_hints)
            and not any(s in t.lower() for s in skip_contact_hints)
        ]

        for t in candidate_tables[:15]:
            if not is_safe_sqlite_table_name(t):
                continue
            q_t = quote_sqlite_identifier(t)
            try:
                df = pd.read_sql_query(f'SELECT * FROM {q_t} LIMIT 200', conn)
                if df.empty:
                    continue
                cols_low = {str(c).lower(): c for c in df.columns}
                if 'key' in cols_low and 'value' in cols_low:
                    for _, r in df.iterrows():
                        _inspect_key_val(str(r[cols_low['key']]), r[cols_low['value']], prof)
                else:
                    for col in df.columns:
                        for val in df[col].dropna().head(30):
                            if isinstance(val, (bytes, bytearray)):
                                try:
                                    val = val.decode('utf-8', errors='ignore')
                                except Exception:
                                    continue
                            _inspect_key_val(str(col), val, prof)
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return prof


def clean_amount_series(series: pd.Series) -> pd.Series:
    if series.empty:
        return series
    if pd.api.types.is_string_dtype(series) or pd.api.types.is_object_dtype(series):
        cleaned = series.astype(str).str.replace(r'[^\d.\-]', '', regex=True)
        cleaned = cleaned.str.replace(r'\.(?=.*\.)', '', regex=True)
        return pd.to_numeric(cleaned, errors='coerce')
    return pd.to_numeric(series, errors='coerce')


def _column_looks_like_currency(series: pd.Series, col_name: str = '') -> bool:
    if series is None or series.empty:
        return False
    try:
        numeric = clean_amount_series(series).dropna().abs()
    except Exception:
        return False
    if numeric.empty:
        return False
    if numeric.median() > 1e8 and not any(k in col_name.lower() for k in ['amount', 'amt', 'paise', 'minor', '1000', 'micros']):
        return False
    if (numeric > _AMOUNT_MAX_ABS * 100).mean() > 0.5 and not any(k in col_name.lower() for k in ['1000', 'micros']):
        return False
    return True


def _infer_transaction_type(
    status_series: pd.Series,
    type_series: Optional[pd.Series] = None,
    signed_amt_series: Optional[pd.Series] = None,
    counterparty_series: Optional[pd.Series] = None,
) -> pd.Series:
    direction = pd.Series('TRANSFER', index=status_series.index, dtype='object')

    if signed_amt_series is not None and pd.api.types.is_numeric_dtype(signed_amt_series):
        if (signed_amt_series < 0).any():
            direction = direction.mask(signed_amt_series < 0, 'DEBIT')
            direction = direction.mask(signed_amt_series > 0, 'CREDIT')

    if type_series is not None:
        t_str = type_series.astype(str).str.upper()
        direction = direction.mask(
            t_str.str.contains(r'\b(?:DEBIT|DR|SENT|PAID|OUT|WITHDRAW|WITHDRAWAL|EXPENSE|P2M|SEND|PAYMENT|RECHARGE|BILL)\b', na=False, regex=True),
            'DEBIT',
        )
        direction = direction.mask(
            t_str.str.contains(r'\b(?:CREDIT|CR|RECEIVED|IN|DEPOSIT|REFUND|INCOME|COLLECT)\b', na=False, regex=True),
            'CREDIT',
        )

    s_str = status_series.astype(str).str.upper()
    direction = direction.mask(
        s_str.str.contains('DEBIT|SENT|PAID|WITHDRAW', na=False), 'DEBIT'
    )
    direction = direction.mask(
        s_str.str.contains('CREDIT|RECEIVED|REFUND', na=False), 'CREDIT'
    )

    if counterparty_series is not None:
        c_str = counterparty_series.astype(str).str.upper()
        direction = direction.mask(
            c_str.str.contains('PAID TO|SENT TO|TRANSFER TO|DEBITED', na=False), 'DEBIT'
        )
        direction = direction.mask(
            c_str.str.contains('RECEIVED FROM|REFUND FROM|CREDITED', na=False), 'CREDIT'
        )

    return direction


def _carve_rkstorage_kv(raw_df: pd.DataFrame, owner_identifiers: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    cols_lower = {str(c).lower(): c for c in raw_df.columns}
    k_col = cols_lower.get('key')
    v_col = cols_lower.get('value')
    if not k_col or not v_col:
        return []

    tx_rows: List[Dict[str, Any]] = []
    for _, row in raw_df.iterrows():
        val = row.get(v_col)
        if not val:
            continue
        if isinstance(val, str) and 'upi://pay?' in val.lower():
            uri_rec = parse_npci_upi_uri(val)
            if uri_rec and uri_rec.get('Amount'):
                tx_rows.append(uri_rec)
                continue
        extracted = extract_from_blob(val, owner_identifiers=owner_identifiers)
        cparty = extracted.get('Counterparty')
        txid = extracted.get('Transaction_ID')
        if not is_valid_counterparty(cparty) and not is_valid_txid(txid):
            continue
        try:
            amt = float(extracted['Amount']) if extracted.get('Amount') is not None else None
        except (ValueError, TypeError):
            amt = None
        if amt is not None and 0 < amt <= _AMOUNT_MAX_ABS:
            tx_rows.append({
                'Date': normalize_timestamp_value(extracted.get('Date'), 'auto'),
                'Transaction_ID': str(txid) if is_valid_txid(txid) else 'N/A',
                'Amount': amt,
                'Counterparty': str(cparty) if is_valid_counterparty(cparty) else 'Unknown',
                'Status': str(extracted.get('Status') or 'SUCCESS'),
                'Type': str(extracted.get('Type') or 'TRANSFER'),
            })
    return tx_rows


def _txid_namespace(txid: str) -> str:
    if not txid or txid == 'N/A' or txid.startswith(('CARVED_', 'SLACK_', 'PG', 'RAW_', 'WAL_', 'RK_', 'SYNTH_')):
        return 'MISSING'
    if re.match(r'^[0-9]{12}$', txid):
        return 'UTR_12'
    if re.match(r'^T\d{18,24}$', txid):
        return 'PHONEPE_T'
    if re.match(r'^NB\d{18,24}$', txid):
        return 'PHONEPE_NB'
    if NPCI_TXID_REGEX.match(txid):
        return f'NPCI_{txid[:3].upper()}'
    return 'OTHER'


def _are_txids_compatible(id1: str, id2: str) -> bool:
    if id1 == id2:
        return True
    ns1 = _txid_namespace(id1)
    ns2 = _txid_namespace(id2)
    if ns1 == 'MISSING' or ns2 == 'MISSING':
        return True
    if ns1 == ns2:
        return False
    return True


@lru_cache(maxsize=16384)
def _fast_date_to_epoch(d_str: Optional[str]) -> Optional[float]:
    if not d_str or not isinstance(d_str, str):
        return None
    s = d_str.strip()
    if not s or s in ('None', 'nan', 'N/A', 'null'):
        return None
    try:
        return pd.Timestamp(s).timestamp()
    except Exception:
        return None


def _are_dates_compatible(d1: Optional[str], d2: Optional[str]) -> bool:
    if not d1 or not d2:
        return True
    if d1 == d2:
        return True
    t1 = _fast_date_to_epoch(d1)
    t2 = _fast_date_to_epoch(d2)
    if t1 is None or t2 is None:
        return True
    diff_mins = abs(t1 - t2) / 60.0
    return diff_mins <= 15.0 or (315.0 <= diff_mins <= 345.0)


def _is_generic_cpty_label(c: str) -> bool:
    """Returns True if the counterparty is Unknown or a generic fallback label."""
    if not c or c == 'Unknown':
        return True
    low = c.lower().strip()
    return low.startswith((
        'phonepe merchant', 'upi / bank', 'upi counterparty', 'bank a/c ', 'upi transfer',
    ))


def _merge_two_counterparties(c1: str, c2: str) -> str:
    """
    Combines two compatible counterparty strings into the richest representation:
    e.g. 'THUNGA TEJASWARI' + 'tejeswari19@ybl' -> 'THUNGA TEJASWARI (tejeswari19@ybl)'
    """
    from parsers.app_overrides import combine_name_and_vpa

    if _is_generic_cpty_label(c1) and not _is_generic_cpty_label(c2):
        return c2
    if _is_generic_cpty_label(c2) and not _is_generic_cpty_label(c1):
        return c1
    if _is_generic_cpty_label(c1) and _is_generic_cpty_label(c2):
        return c1 if c1 != 'Unknown' else c2

    # Prefer external counterparty over Self / Own Account if both exist
    if c1.startswith('Self / Own Account') and not c2.startswith('Self / Own Account'):
        if '@' not in c2 and '@' in c1:
            v_m = re.search(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', c1)
            if v_m:
                return f"Self / Own Account - {c2} ({v_m.group(0)})"
        return c2
    if c2.startswith('Self / Own Account') and not c1.startswith('Self / Own Account'):
        if '@' not in c1 and '@' in c2:
            v_m = re.search(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', c2)
            if v_m:
                return f"Self / Own Account - {c1} ({v_m.group(0)})"
        return c1

    # If one has a Display Name (no '@') and the other has a VPA ('@'), fuse them into `Name (vpa@bank)`!
    if '@' in c1 and '@' not in c2:
        v_m = re.search(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', c1)
        return combine_name_and_vpa(c2, v_m.group(0) if v_m else c1)
    if '@' in c2 and '@' not in c1:
        v_m = re.search(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', c2)
        return combine_name_and_vpa(c1, v_m.group(0) if v_m else c2)

    # If one already has `Name (vpa@bank)` with both '(' and '@', prefer it
    if '(' in c2 and '@' in c2 and '(' not in c1:
        return c2
    return c1


def _are_counterparties_compatible(c1: str, c2: str) -> bool:
    if _is_generic_cpty_label(c1) or _is_generic_cpty_label(c2):
        return True
    l1, l2 = c1.lower().strip(), c2.lower().strip()
    if l1 == l2:
        return True
    # Compatible if one is a Display Name (no '@') and the other is a VPA ('@') for the same payment
    if ('@' in l1) != ('@' in l2):
        return True
    base1 = l1.split('@')[0].split('-')[0].split('(')[-1]
    base2 = l2.split('@')[0].split('-')[0].split('(')[-1]
    if len(base1) >= 5 and (base1 == base2 or base1 in l2 or base2 in l1):
        return True
    return False


def compute_transaction_risk_badges(df: pd.DataFrame) -> pd.Series:
    if df is None or df.empty:
        return pd.Series(dtype='object')

    badges = pd.Series('🟢 Normal', index=df.index, dtype='object')
    amts = pd.to_numeric(df.get('Amount'), errors='coerce').fillna(0.0)
    ts = pd.to_datetime(df.get('Date'), errors='coerce')

    odd_hour_mask = ts.notna() & (ts.dt.hour >= 0) & (ts.dt.hour < 5) & (amts >= 2000)
    badges = badges.mask(odd_hour_mask, '🟡 Medium (Odd-Hour 12AM–5AM)')

    high_val_mask = amts >= 50000
    badges = badges.mask(high_val_mask, '🟡 Medium (High Value ≥₹50k)')

    struct_mask = (amts >= 45000) & (amts < 50000)
    badges = badges.mask(struct_mask, '🔴 High Risk (Near-₹50k Structuring)')

    return badges


def _normalise_phonepe_tid_and_ts(txid_str: str, current_dt_str: Optional[str]) -> Optional[str]:
    """Extracts timestamp from PhonePe T or NB transaction IDs if timestamp is missing."""
    if current_dt_str or txid_str == 'N/A':
        return current_dt_str
    dt_extracted = extract_date_from_phonepe_tid(txid_str)
    if not dt_extracted and txid_str.startswith('NB2'):
        dt_extracted = extract_date_from_phonepe_tid('T' + txid_str[2:])
    return dt_extracted


def synthesize_and_deduplicate_records(
    df: pd.DataFrame,
    owner_identifiers: Optional[Set[str]] = None,
) -> pd.DataFrame:
    std_cols = ['Date', 'Transaction_ID', 'Linked_Reference_IDs', 'Amount', 'Counterparty', 'Status', 'Type', 'Risk_Level']
    if df is None or df.empty:
        return pd.DataFrame(columns=std_cols)

    out = df.copy()
    out['Amount'] = pd.to_numeric(out['Amount'], errors='coerce').round(2)
    out = out[out['Amount'].notna() & (out['Amount'] > 0) & (out['Amount'] <= _AMOUNT_MAX_ABS)].copy()
    if out.empty:
        return pd.DataFrame(columns=std_cols)

    cleaned_records: List[Dict[str, Any]] = []
    for row in out.to_dict('records'):
        cparty = row.get('Counterparty')
        txid = row.get('Transaction_ID')
        linked = row.get('Linked_Reference_IDs')
        dt = row.get('Date')
        st_val = str(row.get('Status', 'SUCCESS')).strip()
        tp_val = str(row.get('Type', 'TRANSFER')).strip().upper()

        cparty_str = format_counterparty_display(str(cparty).strip()) if is_valid_counterparty(cparty) else 'Unknown'
        if '@' in cparty_str and not cparty_str.startswith('Self / Own Account'):
            vpa_match = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+', cparty_str)
            v_chk = clean_and_validate_vpa(vpa_match.group(0)) if vpa_match else None
            if not v_chk:
                name_prefix = re.sub(r'\(.*?\)', '', cparty_str).strip()
                if is_valid_counterparty(name_prefix) and '@' not in name_prefix:
                    cparty_str = name_prefix
                else:
                    cparty_str = 'Unknown'
            else:
                m_paren = re.match(r'^(.*?)\s*\(([^()]+)\)$', cparty_str)
                if m_paren and is_valid_counterparty(m_paren.group(1)):
                    cparty_str = f"{m_paren.group(1).strip()} ({v_chk})"
                elif '(' not in cparty_str:
                    cparty_str = format_counterparty_display(v_chk)

        if (
            cparty_str != 'Unknown'
            and not cparty_str.startswith('Self / Own Account')
            and matches_owner_identity(cparty_str, owner_identifiers)
        ):
            cparty_str = f"Self / Own Account ({cparty_str})"

        txid_str = str(txid).strip() if is_valid_txid(txid) else 'N/A'
        linked_str = (
            str(linked).strip()
            if pd.notna(linked) and str(linked).strip() not in ('', 'None', 'nan', 'N/A')
            else txid_str
        )
        dt_str = normalize_timestamp_value(dt, 'auto')
        dt_str = _normalise_phonepe_tid_and_ts(txid_str, dt_str)

        # Reject boolean or '0.0' status non-transaction rows where Date is None or TxID is N/A
        if st_val.lower() in ('true', 'false', '0.0', '0') and (dt_str is None or txid_str == 'N/A') and '@' not in cparty_str:
            continue

        # Reject unanchored internal 15+ digit IDs where Counterparty is Unknown
        if cparty_str == 'Unknown' and len(txid_str) >= 15 and txid_str.isdigit():
            continue

        if st_val.lower() in ('none', 'nan', 'null', '', 'true', '0.0', '0'):
            st_val = 'SUCCESS'
        if tp_val not in ('DEBIT', 'CREDIT', 'TRANSFER'):
            tp_val = 'TRANSFER'

        # Outgoing merchant/bill/workflow rows default to DEBIT rather than ambiguous TRANSFER
        if tp_val == 'TRANSFER' and (
            re.match(r'^(?:T|NB)\d{18,24}$', txid_str)
            or any(m in cparty_str.lower() for m in ('swiggy', 'zomato', 'blinkit', 'zepto', 'flipkart', 'amazon', 'store qr', 'credit card', 'bill'))
        ):
            tp_val = 'DEBIT'

        if cparty_str == 'Unknown' and st_val.isdigit() and len(txid_str) >= 15 and txid_str.isdigit():
            continue

        if st_val.lower() in ('none', 'nan', 'null', '', 'true'):
            st_val = 'SUCCESS'
        if tp_val not in ('DEBIT', 'CREDIT', 'TRANSFER'):
            tp_val = 'TRANSFER'

        if tp_val == 'TRANSFER' and re.match(r'^T\d{18,24}$', txid_str):
            tp_val = 'DEBIT'

        cleaned_records.append({
            'Date': dt_str,
            'Transaction_ID': txid_str,
            'Linked_Reference_IDs': linked_str,
            'Amount': row['Amount'],
            'Counterparty': cparty_str,
            'Status': st_val,
            'Type': tp_val,
        })

    if not cleaned_records:
        return pd.DataFrame(columns=std_cols)

    out = pd.DataFrame(cleaned_records)

    def _completeness(r) -> int:
        s = 0
        if pd.notna(r['Date']) and str(r['Date']).strip():
            s += 4
        cp = str(r['Counterparty'])
        if cp != 'Unknown':
            if cp.startswith('Self / Own Account'):
                s += 1
            else:
                s += 4
                if '@' in cp:
                    s += 2
        if r['Transaction_ID'] != 'N/A':
            s += 3
            if re.match(r'^[0-9]{12}$', r['Transaction_ID']) or r['Transaction_ID'].startswith('T2'):
                s += 2
        if r['Type'] in ('DEBIT', 'CREDIT'):
            s += 1
        return s

    out['_score'] = out.apply(_completeness, axis=1)
    out = out.sort_values(by=['Amount', '_score'], ascending=[False, False]).reset_index(drop=True)

    synthesized_rows: List[Dict[str, Any]] = []
    for amt, group in out.groupby('Amount', sort=False):
        clusters: List[Dict[str, Any]] = []
        for _, r in group.iterrows():
            r_dt = r['Date']
            r_cparty = r['Counterparty']
            r_txid = r['Transaction_ID']
            r_linked = r['Linked_Reference_IDs']
            r_status = r['Status']
            r_type = r['Type']

            merged_into_existing = False
            for cl in clusters:
                if {cl['Type'], r_type} == {'DEBIT', 'CREDIT'}:
                    continue

                same_txid = (r_txid != 'N/A' and (cl['Transaction_ID'] == r_txid or r_txid in cl['id_set']))
                txid_ok = _are_txids_compatible(cl['Transaction_ID'], r_txid)
                date_ok = _are_dates_compatible(cl['Date'], r_dt)
                cparty_ok = (
                    _are_counterparties_compatible(cl['Counterparty'], r_cparty)
                    or cl['Counterparty'].startswith('Self / Own Account')
                    or r_cparty.startswith('Self / Own Account')
                )

                if same_txid or (txid_ok and date_ok and cparty_ok):
                    if cl['Date'] is None and r_dt is not None:
                        cl['Date'] = r_dt
                    if r_cparty != 'Unknown':
                        if (
                            cl['Counterparty'] == 'Unknown'
                            or (cl['Counterparty'].startswith('Self / Own Account') and not r_cparty.startswith('Self / Own Account'))
                            or ('@' in r_cparty and '@' not in cl['Counterparty'] and not r_cparty.startswith('Self / Own Account'))
                        ):
                            cl['Counterparty'] = _merge_two_counterparties(cl['Counterparty'], r_cparty)
                    if r_txid != 'N/A' and not r_txid.startswith(('CARVED_', 'SLACK_', 'RAW_')):
                        cl['id_set'].add(r_txid)
                    if r_linked and r_linked != 'N/A':
                        for sub_id in r_linked.split(' | '):
                            if sub_id and sub_id != 'N/A' and not sub_id.startswith(('CARVED_', 'SLACK_', 'RAW_')):
                                cl['id_set'].add(sub_id)
                    if cl['Transaction_ID'] == 'N/A' and r_txid != 'N/A':
                        cl['Transaction_ID'] = r_txid
                    elif (
                        r_txid != 'N/A'
                        and cl['Transaction_ID'] != r_txid
                        and (re.match(r'^[0-9]{12}$', r_txid) or r_txid.startswith('T2'))
                        and not re.match(r'^[0-9]{12}$', cl['Transaction_ID'])
                    ):
                        cl['Transaction_ID'] = r_txid
                    if cl['Status'] in ('SUCCESS', 'None') and r_status not in ('SUCCESS', 'None'):
                        cl['Status'] = r_status
                    if cl['Type'] == 'TRANSFER' and r_type in ('DEBIT', 'CREDIT'):
                        cl['Type'] = r_type
                    merged_into_existing = True
                    break

            if not merged_into_existing:
                id_set = set()
                if r_txid != 'N/A' and not r_txid.startswith(('CARVED_', 'SLACK_', 'RAW_')):
                    id_set.add(r_txid)
                if r_linked and r_linked != 'N/A':
                    for sub_id in r_linked.split(' | '):
                        if sub_id and sub_id != 'N/A' and not sub_id.startswith(('CARVED_', 'SLACK_', 'RAW_')):
                            id_set.add(sub_id)
                clusters.append({
                    'Date': r_dt,
                    'Transaction_ID': r_txid,
                    'id_set': id_set,
                    'Amount': amt,
                    'Counterparty': r_cparty,
                    'Status': r_status,
                    'Type': r_type,
                })

        for cl in clusters:
            id_list = sorted(cl.pop('id_set'))
            cl['Linked_Reference_IDs'] = ' | '.join(id_list) if id_list else cl['Transaction_ID']
            synthesized_rows.append(cl)

    if not synthesized_rows:
        return pd.DataFrame(columns=std_cols)

    final_df = pd.DataFrame(synthesized_rows)
    # Build Name <-> VPA lookup from all rows that already have `Name (vpa@bank)`
    name_to_vpa_map: Dict[str, str] = {}
    for cp_val in final_df['Counterparty'].dropna().astype(str):
        m_pair = re.match(r'^(?:Self / Own Account - )?([^()@]+?)\s*\(([a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+)\)$', cp_val.strip())
        if m_pair:
            n_key = m_pair.group(1).strip().lower()
            v_str = m_pair.group(2).strip().lower()
            if len(n_key) >= 3:
                name_to_vpa_map[n_key] = f"{m_pair.group(1).strip()} ({v_str})"

    for idx, row in final_df.iterrows():
        cp = str(row['Counterparty']).strip()
        tid = str(row['Transaction_ID']).strip()

        # Enrich Name-only rows with their known VPA (`THUNGA TEJASWARI` -> `THUNGA TEJASWARI (tejeswari19@ybl)`)
        if cp != 'Unknown' and '@' not in cp and cp.lower() in name_to_vpa_map:
            final_df.at[idx, 'Counterparty'] = name_to_vpa_map[cp.lower()]
            cp = final_df.at[idx, 'Counterparty']

        # Ensure every valid VPA-anchored row has a concrete Reference ID if UTR column was absent
        if tid == 'N/A' and '@' in cp:
            dt_compact = re.sub(r'\D', '', str(row.get('Date') or ''))[:12] or f"{int(float(row['Amount']) * 100)}"
            synth_id = f"UPI_REF_{dt_compact}"
            final_df.at[idx, 'Transaction_ID'] = synth_id
            final_df.at[idx, 'Linked_Reference_IDs'] = synth_id
            tid = synth_id

        if cp == 'Unknown':
            if re.match(r'^(?:T|NB)\d{18,24}$', tid):
                final_df.at[idx, 'Counterparty'] = 'PhonePe Merchant / Bill Payment'
            elif re.match(r'^[0-9]{12}$', tid):
                final_df.at[idx, 'Counterparty'] = f'UPI / Bank Counterparty (UTR: {tid})'
            elif NPCI_TXID_REGEX.match(tid):
                final_df.at[idx, 'Counterparty'] = f'UPI Counterparty (NPCI ID: {tid[:10]}...)'

    anchored_mask = (
        final_df['Counterparty'].astype(str).str.contains('@', na=False)
        | (
            (final_df['Transaction_ID'] != 'N/A')
            & (~final_df['Transaction_ID'].str.startswith(('CARVED_P', 'SLACK_P', 'RAW_FREELIST')))
        )
        | (
            (final_df['Counterparty'] != 'Unknown')
            & final_df['Date'].notna()
        )
    )
    final_df = final_df[anchored_mask]
    final_df = final_df[~(final_df['Date'].isna() & (final_df['Counterparty'] == 'Unknown'))].reset_index(drop=True)

    for idx, row in final_df.iterrows():
        if row['Counterparty'] == 'Unknown':
            tid = str(row['Transaction_ID'])
            if re.match(r'^T\d{18,24}$', tid):
                final_df.at[idx, 'Counterparty'] = 'PhonePe Merchant / Bill Payment'
            elif re.match(r'^[0-9]{12}$', tid):
                final_df.at[idx, 'Counterparty'] = f'UPI / Bank Counterparty (UTR: {tid})'
            elif NPCI_TXID_REGEX.match(tid):
                final_df.at[idx, 'Counterparty'] = f'UPI Counterparty (NPCI ID: {tid[:10]}...)'

    final_df['Risk_Level'] = compute_transaction_risk_badges(final_df)
    return final_df[std_cols]


def deduplicate_master_timeline(master_df: pd.DataFrame) -> pd.DataFrame:
    if master_df is None or master_df.empty or len(master_df) <= 1:
        return master_df

    work_df = master_df.copy()
    work_df['Amount'] = pd.to_numeric(work_df['Amount'], errors='coerce').round(2)
    work_df = work_df[work_df['Amount'].notna() & (work_df['Amount'] > 0)]
    if work_df.empty:
        return master_df

    cols = list(work_df.columns)
    merged_clusters: List[Dict[str, Any]] = []

    for _, group in work_df.groupby('Amount', sort=False):
        sub_clusters: List[Dict[str, Any]] = []
        for _, r in group.iterrows():
            r_dict = r.to_dict()
            r_txid = str(r_dict.get('Transaction_ID', 'N/A'))
            r_dt = r_dict.get('Date')
            r_cparty = str(r_dict.get('Counterparty', 'Unknown'))
            r_app = str(r_dict.get('Application', 'UPI'))
            r_type = str(r_dict.get('Type', 'TRANSFER'))

            matched = False
            for cl in sub_clusters:
                if {str(cl.get('Type', 'TRANSFER')), r_type} == {'DEBIT', 'CREDIT'}:
                    continue

                cl_txid = str(cl.get('Transaction_ID', 'N/A'))
                same_id = (r_txid != 'N/A' and r_txid == cl_txid)
                txid_ok = _are_txids_compatible(cl_txid, r_txid)
                same_event = (
                    txid_ok
                    and _are_dates_compatible(cl.get('Date'), r_dt)
                    and _are_counterparties_compatible(str(cl.get('Counterparty', 'Unknown')), r_cparty)
                    and (cl.get('Date') is not None and r_dt is not None)
                )
                if same_id or same_event:
                    # Keep Application as a clean single app name (prefer primary UPI app over background SMS bank app)
                    curr_app = str(cl.get('Application', ''))
                    upi_primary = ('PhonePe', 'Google Pay', 'Paytm', 'BHIM UPI', 'Amazon Pay', 'CRED', 'Super.money', 'Slice')
                    if r_app in upi_primary and curr_app not in upi_primary:
                        cl['Application'] = r_app
                    if cl.get('Date') is None and r_dt is not None:
                        cl['Date'] = r_dt
                    cl['Counterparty'] = _merge_two_counterparties(str(cl.get('Counterparty', 'Unknown')), r_cparty)
                    if str(cl.get('Type', 'TRANSFER')) == 'TRANSFER' and r_type in ('DEBIT', 'CREDIT'):
                        cl['Type'] = r_type
                    if re.match(r'^[0-9]{12}$', r_txid) and not re.match(r'^[0-9]{12}$', cl_txid):
                        cl['Transaction_ID'] = r_txid
                    r_linked = str(r_dict.get('Linked_Reference_IDs', '') or r_txid)
                    cl_linked = str(cl.get('Linked_Reference_IDs', '') or cl_txid)
                    for sub_id in r_linked.split(' | '):
                        if sub_id and sub_id != 'N/A' and sub_id not in cl_linked:
                            cl_linked = f"{cl_linked} | {sub_id}".strip(' |')
                    cl['Linked_Reference_IDs'] = cl_linked
                    matched = True
                    break
            if not matched:
                sub_clusters.append(r_dict)
        merged_clusters.extend(sub_clusters)

    out = pd.DataFrame(merged_clusters)
    if 'Risk_Level' not in out.columns:
        out['Risk_Level'] = compute_transaction_risk_badges(out)
    return out[[c for c in cols if c in out.columns]].reset_index(drop=True)


def parse_database_artifacts(
    db_path: str,
    os_type: str = 'android',
    app_label: str = '',
    owner_identifiers: Optional[Set[str]] = None,
    **kwargs,
) -> Dict[str, pd.DataFrame]:
    artifacts: Dict[str, Any] = {
        'transactions': pd.DataFrame(columns=[
            'Date', 'Transaction_ID', 'Linked_Reference_IDs', 'Amount', 'Counterparty', 'Status', 'Type', 'Risk_Level',
        ]),
        'chats': pd.DataFrame(columns=CATEGORIZED_FORENSIC_COLUMNS),
        'contacts': pd.DataFrame(),
        'notifications': pd.DataFrame(),
        'custodial_wallet_records': pd.DataFrame(),
    }

    local_owners: Set[str] = set(owner_identifiers) if owner_identifiers else set()
    is_whatsapp = ('whatsapp' in app_label.lower())

    override = get_app_override(app_label) or {}
    epoch = override.get('timestamp_epoch', 'auto')
    if os_type == 'ios' and epoch == 'auto':
        epoch = 'auto'
    col_divisor = override.get('amount_divisor', 1.0)
    json_divisor = override.get('json_amount_divisor', 1.0)
    json_paths = {
        'amount': override.get('json_path_amount', 'amount'),
        'date': override.get('json_path_date', 'timestamp'),
        'counterparty': override.get('json_path_cpty', 'counterparty'),
        'transaction_id': override.get('json_path_txid', 'transactionId'),
    }

    synthesizer = ProtobufSchemaSynthesizer(message_name=f"{app_label or 'App'}_Payload")

    conn = None
    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = [
            r[0] for r in cursor.fetchall()
            if not r[0].startswith(('sqlite_', 'android_metadata'))
        ]
    except (sqlite3.DatabaseError, sqlite3.OperationalError):
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        carved = carve_corrupted_sqlite_file(db_path)
        if not carved.empty:
            artifacts['transactions'] = synthesize_and_deduplicate_records(carved, owner_identifiers=local_owners)
        return artifacts
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return artifacts

    collected_txs: List[pd.DataFrame] = []
    collected_chats: List[pd.DataFrame] = []
    collected_contacts: List[pd.DataFrame] = []
    collected_notifs: List[pd.DataFrame] = []

    try:
        # Dedicated Deep Parsers for Chat, Privacy, Social & Dating Apps (Phases 6 & 7)
        app_low = (app_label or "").strip().lower()
        db_name_low = os.path.basename(db_path).lower()
        tables_low = {t.lower(): t for t in tables}

        dedicated_chat_df: Optional[pd.DataFrame] = None

        # 1. WhatsApp & WhatsApp Business
        if (
            any(k in app_low for k in ["whatsapp", "w4b"])
            or any(k in db_name_low for k in ["msgstore", "chatstorage"])
            or ("message" in tables_low and "chat" in tables_low and "jid" in tables_low)
            or ("zwamessage" in tables_low and "zwachatsession" in tables_low)
        ):
            try:
                wa_res = parse_whatsapp_full_forensics(db_path, owner_identifiers=local_owners)
                if isinstance(wa_res, tuple):
                    dedicated_chat_df, wa_contacts_df = wa_res
                    if wa_contacts_df is not None and not wa_contacts_df.empty:
                        collected_contacts.append(wa_contacts_df)
                else:
                    dedicated_chat_df = wa_res
            except Exception:
                pass

        # 2. Telegram & Telegram X
        elif (
            any(k in app_low for k in ["telegram", "challegram"])
            or "cache4" in db_name_low
            or ("messages_v2" in tables_low and ("users" in tables_low or "chats" in tables_low))
        ):
            try:
                dedicated_chat_df = parse_telegram_database(db_path)
            except Exception:
                pass

        # 3. Signal Private Messenger
        elif (
            any(k in app_low for k in ["signal", "securesms"])
            or "signal.db" in db_name_low
            or "signal.sqlite" in db_name_low
            or ("recipient" in tables_low and ("mms" in tables_low or "sms" in tables_low or "model_tsinteraction" in tables_low))
        ):
            try:
                dedicated_chat_df = parse_signal_database(db_path)
            except Exception:
                pass

        # 4. Zangi Private Messenger
        elif (
            "zangi" in app_low
            or "zangi" in db_name_low
            or ("messages" in tables_low and "calls" in tables_low and "chat_messages" in tables_low)
            or ("zmessage" in tables_low and "zconversation" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_zangi_database(db_path)
            except Exception:
                pass

        # 5. Element / Matrix Messenger
        elif (
            any(k in app_low for k in ["element", "matrix", "vector", "riot"])
            or "matrix-sdk" in db_name_low
            or ("timeline_events" in tables_low or ("events" in tables_low and "crypto_store" in tables_low))
        ):
            try:
                dedicated_chat_df = parse_element_matrix_database(db_path)
            except Exception:
                pass

        # 6. Session Messenger
        elif (
            any(k in app_low for k in ["session", "loki", "oxen"])
            or "session.db" in db_name_low
            or ("loki_user_display_name_database" in tables_low or "loki_open_group_chat" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_session_threema_simplex(db_path, app_label="session")
            except Exception:
                pass

        # 7. Threema / Briar / SimpleX Chat
        elif (
            any(k in app_low for k in ["threema", "briar", "simplex"])
            or any(k in db_name_low for k in ["threema", "simplex"])
            or ("identity" in tables_low and "key_pair" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_session_threema_simplex(db_path, app_label=app_low or "threema")
            except Exception:
                pass

        # 8. Snapchat
        elif (
            any(k in app_low for k in ["snapchat", "snap", "arroyo"])
            or "arroyo" in db_name_low
            or ("conversation_message" in tables_low and ("friend" in tables_low or "feed" in tables_low))
        ):
            try:
                dedicated_chat_df = parse_snapchat_arroyo(db_path)
            except Exception:
                pass

        # 9. Instagram Direct
        elif (
            any(k in app_low for k in ["instagram", "direct", "reverb"])
            or "direct.db" in db_name_low
            or "reverb.db" in db_name_low
            or ("messages" in tables_low and "threads" in tables_low and "users" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_instagram_direct(db_path)
            except Exception:
                pass

        # 10. Dating Apps (Tinder, Bumble, Hinge, Grindr)
        elif (
            any(k in app_low for k in ["dating", "tinder", "bumble", "hinge", "grindr"])
            or any(k in db_name_low for k in ["tinder", "bumble", "hinge", "grindr"])
            or ("message_view" in tables_low and "match_view" in tables_low)
            or ("chat_message" in tables_low and "connections" in tables_low)
            or ("chat_messages" in tables_low and "matches" in tables_low)
            or ("profiles" in tables_low and "conversation_id" in [c.lower() for c in tables_low])
        ):
            try:
                dedicated_chat_df = parse_dating_apps(db_path, app_label=app_low or "dating")
            except Exception:
                pass

        # 11. Facebook & Facebook Messenger
        elif (
            any(k in app_low for k in ["facebook", "messenger", "orca", "katana"])
            or any(k in db_name_low for k in ["threads_db2", "msys", "armadillo", "crypto_mailbox"])
            or ("cql_messages" in tables_low or "thread_participants" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_facebook_messenger_database(db_path, owner_identifiers=local_owners)
            except Exception:
                pass

        # 12. Discord
        elif (
            "discord" in app_low
            or "discord" in db_name_low
            or ("kv_storage" in tables_low and "channels" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_discord_database(db_path)
            except Exception:
                pass

        # 13. Skype & Microsoft Teams
        elif (
            any(k in app_low for k in ["skype", "teams", "msteams"])
            or any(k in db_name_low for k in ["skype", "main.db", "s4l"])
            or ("messagesv12" in tables_low or "reply_chains" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_skype_teams_database(db_path)
            except Exception:
                pass

        # 14. Viber
        elif (
            "viber" in app_low
            or "viber" in db_name_low
            or ("viber_messages" in tables_low or "participants_info" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_viber_database(db_path)
            except Exception:
                pass

        # 15. WeChat
        elif (
            any(k in app_low for k in ["wechat", "weixin", "tencent.mm"])
            or any(k in db_name_low for k in ["enmicromsg", "wcdb"])
            or ("message" in tables_low and "rcontact" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_wechat_database(db_path)
            except Exception:
                pass

        # 16. LINE
        elif (
            "line" in app_low
            or "naver_line" in db_name_low
            or ("chat_history" in tables_low and "chat_id" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_line_database(db_path)
            except Exception:
                pass

        # 17. IMO & KakaoTalk
        elif (
            any(k in app_low for k in ["imo", "kakao", "kakaotalk"])
            or any(k in db_name_low for k in ["imodb", "kakaotalk"])
            or ("immessages" in tables_low or "chat_logs" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_imo_kakaotalk_database(db_path)
            except Exception:
                pass

        # 18. X (Twitter), Threads, Reddit, LinkedIn
        elif (
            any(k in app_low for k in ["twitter", "x", "threads", "barcelona", "reddit", "linkedin", "voyager"])
            or any(k in db_name_low for k in ["voyager", "conversation_entries"])
            or ("conversation_entries" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_twitter_threads_reddit_linkedin(db_path)
            except Exception:
                pass

        # 19. Truecaller
        elif (
            "truecaller" in app_low
            or any(k in db_name_low for k in ["tc.db", "msg.db"])
            or ("msg_messages" in tables_low or "aggregated_contact" in tables_low)
        ):
            try:
                dedicated_chat_df = parse_truecaller_database(db_path)
            except Exception:
                pass

        # 20. OLX India
        elif (
            "olx" in app_low
            or "olx" in db_name_low
        ):
            try:
                dedicated_chat_df = parse_olx_database(db_path)
            except Exception:
                pass

        # 21. ShareChat & Moj
        elif (
            any(k in app_low for k in ["sharechat", "moj"])
            or any(k in db_name_low for k in ["sharechat", "moj"])
        ):
            try:
                dedicated_chat_df = parse_sharechat_moj_database(db_path)
            except Exception:
                pass


        if dedicated_chat_df is not None and not dedicated_chat_df.empty:
            collected_chats.append(dedicated_chat_df)

        # Fallback SQL JOIN for legacy WhatsApp if dedicated parser was not invoked
        if is_whatsapp and (dedicated_chat_df is None or dedicated_chat_df.empty):
            wa_joined_chats = _try_extract_whatsapp_joined_chats(conn, tables, local_owners)
            if wa_joined_chats is not None and not wa_joined_chats.empty:
                collected_chats.append(wa_joined_chats)

        preferred = [t for t in override.get('preferred_tables', []) if t in tables]
        remaining = [t for t in tables if t not in preferred]
        ordered_tables = preferred + remaining

        app_amt_patterns = override.get('amount_cols', []) + AMOUNT_PATTERNS
        app_date_patterns = override.get('date_cols', []) + DATE_PATTERNS
        app_cpty_patterns = override.get('counterparty_cols', []) + CPTY_PATTERNS
        app_txid_patterns = override.get('txid_cols', []) + TXID_PATTERNS
        app_status_patterns = override.get('status_cols', []) + STATUS_PATTERNS
        app_blob_patterns = override.get('blob_cols', []) + BLOB_PATTERNS

        for table in ordered_tables:
            if not is_safe_sqlite_table_name(table):
                continue
            q_table = quote_sqlite_identifier(table)
            t_low = table.lower()
            if any(skip in t_low for skip in ['analytics', 'config', 'string', 'locale', 'template', 'crash', 'metric', 'ab_test', 'experiment', 'sync_entities']):
                if t_low != 'sync_entities':
                    continue

            try:
                cursor.execute(f"PRAGMA table_info({q_table});")
                pragma_rows = cursor.fetchall()
                raw_columns = [r[1] for r in pragma_rows]
                blob_typed_cols = [r[1] for r in pragma_rows if 'BLOB' in str(r[2]).upper()]
                col_map = {
                    re.sub(r'[^a-zA-Z0-9]', '', c.lower()): c for c in raw_columns
                }
            except Exception:
                continue

            if t_low in ('catalystlocalstorage', 'rkstorage') or (
                'key' in col_map and 'value' in col_map and len(raw_columns) <= 4
            ):
                try:
                    kv_df = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 10000', conn)
                    kv_txs = _carve_rkstorage_kv(kv_df, owner_identifiers=local_owners)
                    if kv_txs:
                        collected_txs.append(pd.DataFrame(kv_txs))
                except Exception:
                    pass

            amt_col = _match_column(col_map, app_amt_patterns, exclude_suffixes=_EXCLUDE_AMOUNT_SUFFIXES)
            date_col = _match_column(col_map, app_date_patterns)
            txid_col = _match_column(col_map, app_txid_patterns)
            cparty_col = _match_column(col_map, app_cpty_patterns)
            payer_col = _match_column(col_map, PAYER_COL_PATTERNS)
            payee_col = _match_column(col_map, PAYEE_COL_PATTERNS)
            status_col = _match_column(col_map, app_status_patterns)
            type_col = _match_column(col_map, TYPE_PATTERNS)
            msg_col = _match_column(col_map, CHAT_PATTERNS)
            blob_col = _match_column(col_map, app_blob_patterns) or (blob_typed_cols[0] if blob_typed_cols else None)

            debit_col = _match_column(col_map, ['debit', 'withdrawal', 'dramt', 'debitamount', 'withdrawalamt'])
            credit_col = _match_column(col_map, ['credit', 'deposit', 'cramt', 'creditamount', 'depositamt'])

            # ---------------- 1. In-App Chats & SMS Financial Mining ----------------
            if msg_col and date_col and not amt_col and not (debit_col and credit_col):
                if not (is_whatsapp and collected_chats) and (dedicated_chat_df is None or dedicated_chat_df.empty):
                    try:
                        raw_c = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 15000', conn)
                        if not raw_c.empty and raw_c[msg_col].dropna().count() > 0:
                            ch = _normalize_chat_dataframe(
                                raw_c=raw_c,
                                col_map=col_map,
                                date_col=date_col,
                                msg_col=msg_col,
                                cparty_col=cparty_col,
                                epoch=epoch,
                                local_owners=local_owners,
                            )
                            if not ch.empty:
                                collected_chats.append(ch)

                            sms_txs: List[Dict[str, Any]] = []
                            for _, m_row in ch.iterrows():
                                msg_text = str(m_row['Message'])
                                if 'upi://pay?' in msg_text.lower():
                                    uri_tx = parse_npci_upi_uri(msg_text)
                                    if uri_tx and uri_tx.get('Amount'):
                                        uri_tx['Date'] = m_row['Timestamp']
                                        sms_txs.append(uri_tx)
                                        continue
                                parsed_sms = parse_indian_financial_text(
                                    msg_text,
                                    default_date=m_row['Timestamp'],
                                    sender=str(m_row['Contact_Thread']),
                                )
                                if parsed_sms:
                                    sms_txs.append(parsed_sms)
                            if sms_txs:
                                collected_txs.append(pd.DataFrame(sms_txs))
                    except Exception:
                        pass

            if is_whatsapp and (t_low in _WHATSAPP_NON_PAYMENT_TABLES or 'pay' not in t_low):
                continue

            if not amt_col and not (debit_col and credit_col) and not msg_col and not blob_col:
                try:
                    probe_df = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 200', conn)
                    blind_map = _classify_columns_by_content(probe_df)
                    if blind_map.get('amt_col'):
                        amt_col = blind_map['amt_col']
                        date_col = date_col or blind_map.get('date_col')
                        txid_col = txid_col or blind_map.get('txid_col')
                        cparty_col = cparty_col or blind_map.get('cparty_col')
                        status_col = status_col or blind_map.get('status_col')
                        type_col = type_col or blind_map.get('type_col')
                except Exception:
                    pass

    # ---------------- 2. Contacts / Beneficiaries / Saved Payees ----------------
            is_contact_table = any(
                k in t_low for k in ('contact', 'beneficiar', 'payee', 'vpa', 'user', 'peer', 'recipient', 'remitter', 'friend', 'roster', 'address_book')
            )
            if (cparty_col or payer_col or payee_col or is_contact_table) and not amt_col and not (debit_col and credit_col) and not msg_col:
                try:
                    raw_cnt = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 5000', conn)
                    if not raw_cnt.empty:
                        name_col = _match_column(col_map, ['name', 'displayname', 'contactname', 'payeename', 'beneficiaryname', 'username', 'fullname', 'vname', 'title']) or cparty_col
                        id_col = _match_column(col_map, ['vpa', 'upiid', 'payeevpa', 'phone', 'mobile', 'number', 'jid', 'handle', 'accountno', 'identifier']) or payee_col or payer_col or txid_col
                        if name_col or id_col:
                            cnt_rows = []
                            for _, cr in raw_cnt.iterrows():
                                n_val = str(cr.get(name_col, '') or '').strip() if name_col else ''
                                i_val = str(cr.get(id_col, '') or '').strip() if id_col else ''
                                if n_val.lower() in ('none', 'nan', 'null', '0', 'unknown'):
                                    n_val = ''
                                if i_val.lower() in ('none', 'nan', 'null', '0', 'unknown', 'n/a'):
                                    i_val = ''
                                if not is_valid_counterparty(n_val) and not is_valid_counterparty(i_val):
                                    continue
                                cnt_rows.append({
                                    'Contact_Name': n_val if is_valid_counterparty(n_val) else (i_val.split('@')[0] if '@' in i_val else 'Saved Payee'),
                                    'Identifier': i_val if is_valid_counterparty(i_val) else n_val,
                                })
                            if cnt_rows:
                                collected_contacts.append(pd.DataFrame(cnt_rows).drop_duplicates())
                except Exception:
                    pass

            # ---------------- 3. Notifications & Alerts ----------------
            notif_title = _match_column(col_map, NOTIF_TITLE_PATTERNS)
            notif_body = _match_column(col_map, NOTIF_BODY_PATTERNS)
            if (notif_title or notif_body) and date_col and not amt_col:
                if any(k in t_low for k in ['notif', 'push', 'alert', 'inbox', 'event', 'history']):
                    try:
                        raw_nt = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 5000', conn)
                        if not raw_nt.empty:
                            nt = pd.DataFrame()
                            nt['Timestamp'] = raw_nt[date_col].map(lambda v: normalize_timestamp_value(v, epoch=epoch))
                            nt['Title'] = raw_nt[notif_title].astype(str) if notif_title else 'Notification'
                            nt['Body'] = raw_nt[notif_body].astype(str) if notif_body else ''
                            if not nt.empty:
                                collected_notifs.append(nt)
                                notif_txs = []
                                for _, n_row in nt.iterrows():
                                    p_notif = parse_indian_financial_text(
                                        f"{n_row['Title']} {n_row['Body']}",
                                        default_date=n_row['Timestamp'],
                                        sender=str(n_row['Title']),
                                    )
                                    if p_notif:
                                        notif_txs.append(p_notif)
                                if notif_txs:
                                    collected_txs.append(pd.DataFrame(notif_txs))
                    except Exception:
                        pass

            # ---------------- 4. Financial Transactions ----------------
            has_split_dr_cr = (debit_col is not None and credit_col is not None)
            if amt_col or has_split_dr_cr or blob_col:
                try:
                    raw_tx = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 25000', conn)
                    if raw_tx.empty:
                        continue

                    if not (date_col and cparty_col and txid_col):
                        blind_fill = _classify_columns_by_content(raw_tx)
                        date_col = date_col or blind_fill.get('date_col')
                        cparty_col = cparty_col or blind_fill.get('cparty_col')
                        txid_col = txid_col or blind_fill.get('txid_col')
                        status_col = status_col or blind_fill.get('status_col')
                        type_col = type_col or blind_fill.get('type_col')

                    if amt_col and not has_split_dr_cr and not _column_looks_like_currency(raw_tx[amt_col], amt_col) and not blob_col:
                        continue

                    if payer_col and payee_col and payer_col != payee_col and len(raw_tx) >= 5:
                        combined_parties = (
                            list(raw_tx[payer_col].dropna().astype(str))
                            + list(raw_tx[payee_col].dropna().astype(str))
                        )
                        vpa_counts = Counter(
                            p.strip().lower() for p in combined_parties if '@' in p
                        )
                        if vpa_counts:
                            top_vpa, top_cnt = vpa_counts.most_common(1)[0]
                            if top_cnt >= len(raw_tx) * 0.55:
                                local_owners.add(top_vpa)

                    tx_df = pd.DataFrame(index=raw_tx.index)
                    tx_df['Date'] = (
                        raw_tx[date_col].map(lambda v: normalize_timestamp_value(v, epoch=epoch))
                        if date_col
                        else None
                    )
                    tx_df['Transaction_ID'] = (
                        raw_tx[txid_col].map(lambda v: str(v).strip() if is_valid_txid(v) else 'N/A')
                        if txid_col
                        else 'N/A'
                    )

                    if has_split_dr_cr and not amt_col:
                        dr_s = clean_amount_series(raw_tx[debit_col]).fillna(0.0)
                        cr_s = clean_amount_series(raw_tx[credit_col]).fillna(0.0)
                        tx_df['Amount'] = np.where(dr_s > 0, dr_s, np.where(cr_s > 0, cr_s, np.nan))
                        signed_amounts = pd.Series(np.where(dr_s > 0, -dr_s, cr_s), index=raw_tx.index)
                    else:
                        tx_df['Amount'] = (
                            clean_amount_series(raw_tx[amt_col]) if amt_col else pd.Series(np.nan, index=raw_tx.index)
                        )
                        signed_amounts = tx_df['Amount'].copy()

                    raw_type_series = (
                        raw_tx[type_col].fillna('').astype(str)
                        if type_col
                        else pd.Series('', index=raw_tx.index, dtype='object')
                    )

                    if payer_col and payee_col and payer_col != payee_col:
                        cpty_list = []
                        dir_list = []
                        for idx in raw_tx.index:
                            c_res, d_res = resolve_payer_payee_counterparty(
                                raw_tx.at[idx, payer_col],
                                raw_tx.at[idx, payee_col],
                                owner_identifiers=local_owners,
                                explicit_direction=raw_type_series.at[idx],
                            )
                            if not is_valid_counterparty(c_res) and cparty_col:
                                fb_val = raw_tx.at[idx, cparty_col]
                                if is_valid_counterparty(fb_val):
                                    c_res = str(fb_val).strip()
                            cpty_list.append(c_res if is_valid_counterparty(c_res) else 'Unknown')
                            dir_list.append(d_res or raw_type_series.at[idx])
                        tx_df['Counterparty'] = cpty_list
                        raw_type_series = pd.Series(dir_list, index=raw_tx.index, dtype='object')
                    else:
                        tx_df['Counterparty'] = (
                            raw_tx[cparty_col].map(
                                lambda v: str(v).strip() if is_valid_counterparty(v) else 'Unknown'
                            )
                            if cparty_col
                            else 'Unknown'
                        )

                    tx_df['Status'] = (
                        raw_tx[status_col].fillna('SUCCESS').astype(str).replace({'None': 'SUCCESS', 'nan': 'SUCCESS'})
                        if status_col
                        else 'SUCCESS'
                    )

                    if amt_col and tx_df['Amount'].notna().any():
                        amt_lower = amt_col.lower()
                        if 'micros' in amt_lower:
                            tx_df['Amount'] = tx_df['Amount'] / 1_000_000.0
                        elif '1000' in amt_lower:
                            tx_df['Amount'] = tx_df['Amount'] / 1000.0
                        elif any(k in amt_lower for k in ['paise', 'paisa', 'minor', 'cent']):
                            tx_df['Amount'] = tx_df['Amount'] / 100.0
                        elif col_divisor and col_divisor != 1.0:
                            tx_df['Amount'] = tx_df['Amount'] / col_divisor

                    candidate_blob_cols = list(dict.fromkeys(([blob_col] if blob_col else []) + blob_typed_cols))
                    for b_col in candidate_blob_cols[:3]:
                        if b_col not in raw_tx.columns:
                            continue
                        pb_observed = 0
                        for idx, val in raw_tx[b_col].items():
                            if isinstance(val, (bytes, bytearray, str)) and val:
                                row_complete = (
                                    pd.notna(tx_df.at[idx, 'Amount'])
                                    and tx_df.at[idx, 'Amount'] > 0
                                    and pd.notna(tx_df.at[idx, 'Date'])
                                    and tx_df.at[idx, 'Counterparty'] != 'Unknown'
                                    and tx_df.at[idx, 'Transaction_ID'] != 'N/A'
                                    and str(raw_type_series.at[idx]).strip().lower() not in ('', 'none', 'nan', 'null')
                                )
                                if row_complete:
                                    continue

                                if isinstance(val, (bytes, bytearray)) and pb_observed < 30:
                                    pb_stream = decode_protobuf_stream(val)
                                    if pb_stream:
                                        synthesizer.observe(pb_stream)
                                        pb_observed += 1
                                extracted = extract_from_blob(
                                    val,
                                    app_label=app_label,
                                    json_paths=json_paths,
                                    owner_identifiers=local_owners,
                                )
                                if extracted['Amount'] is not None and (
                                    pd.isna(tx_df.at[idx, 'Amount']) or tx_df.at[idx, 'Amount'] == 0
                                ):
                                    try:
                                        ext_amt = float(extracted['Amount'])
                                        if ext_amt > 10_000_000 and 'google' in app_label.lower():
                                            ext_amt = ext_amt / 1_000_000.0
                                        elif json_divisor and json_divisor != 1.0 and ext_amt > 100 and float(ext_amt).is_integer():
                                            ext_amt = ext_amt / json_divisor
                                        tx_df.at[idx, 'Amount'] = ext_amt
                                    except Exception:
                                        pass
                                if extracted['Date'] and pd.isna(tx_df.at[idx, 'Date']):
                                    tx_df.at[idx, 'Date'] = normalize_timestamp_value(extracted['Date'], epoch=epoch)
                                if extracted['Counterparty'] and tx_df.at[idx, 'Counterparty'] == 'Unknown':
                                    tx_df.at[idx, 'Counterparty'] = str(extracted['Counterparty'])
                                if extracted['Transaction_ID'] and tx_df.at[idx, 'Transaction_ID'] == 'N/A':
                                    tx_df.at[idx, 'Transaction_ID'] = str(extracted['Transaction_ID'])
                                if extracted['Status'] and tx_df.at[idx, 'Status'] in ['SUCCESS', 'UNKNOWN', 'nan', 'None']:
                                    tx_df.at[idx, 'Status'] = str(extracted['Status'])
                                if extracted.get('Type') and str(raw_type_series.at[idx]).strip().lower() in ('', 'none', 'nan', 'null'):
                                    raw_type_series.at[idx] = str(extracted['Type'])

                    tx_df['Type'] = _infer_transaction_type(
                        status_series=tx_df['Status'],
                        type_series=raw_type_series,
                        signed_amt_series=signed_amounts,
                        counterparty_series=tx_df['Counterparty'],
                    )

                    tx_df['Amount'] = pd.to_numeric(tx_df['Amount'], errors='coerce').abs()
                    tx_df.loc[tx_df['Amount'] == 0, 'Amount'] = np.nan

                    for idx, c_val in tx_df['Counterparty'].items():
                        if isinstance(c_val, str) and '@' in c_val and not c_val.startswith('Self / Own Account'):
                            vpa_match = re.search(r'[a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+', c_val)
                            v_clean = clean_and_validate_vpa(vpa_match.group(0)) if vpa_match else None
                            if v_clean:
                                m_paren = re.match(r'^(.*?)\s*\(([^()]+)\)$', c_val)
                                if m_paren and is_valid_counterparty(m_paren.group(1)):
                                    tx_df.at[idx, 'Counterparty'] = f"{m_paren.group(1).strip()} ({v_clean})"
                                else:
                                    tx_df.at[idx, 'Counterparty'] = format_counterparty_display(v_clean)
                            else:
                                name_prefix = re.sub(r'\(.*?\)', '', c_val).strip()
                                if is_valid_counterparty(name_prefix) and '@' not in name_prefix:
                                    tx_df.at[idx, 'Counterparty'] = name_prefix
                                else:
                                    tx_df.at[idx, 'Counterparty'] = 'Unknown'

                    valid_mask = tx_df['Amount'].notna() & (tx_df['Amount'] > 0) & (tx_df['Amount'] <= _AMOUNT_MAX_ABS)
                    tx_df = tx_df[valid_mask]
                    if not tx_df.empty:
                        collected_txs.append(tx_df[[
                            'Date', 'Transaction_ID', 'Amount', 'Counterparty', 'Status', 'Type'
                        ]])
                except Exception:
                    continue
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    all_tx_fragments: List[pd.DataFrame] = list(collected_txs)

    db_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    if not (is_whatsapp and db_size > 40 * 1024 * 1024):
        try:
            freelist_df = carve_sqlite_freelists(db_path)
            if not freelist_df.empty:
                all_tx_fragments.append(freelist_df)
        except Exception:
            pass

        try:
            wal_path = f"{db_path}-wal"
            if os.path.exists(wal_path):
                wal_rollback_df = analyze_wal_revisions(wal_path)
                if not wal_rollback_df.empty:
                    all_tx_fragments.append(wal_rollback_df)
        except Exception:
            pass

    try:
        from parsers.deep_sqlite import deep_parse, route_sqlite_file
        from parsers.custodial_wallet_parser import is_custodial_wallet_app
        routed_tag = route_sqlite_file(os.path.basename(db_path), app_label)
        is_custodial = is_custodial_wallet_app(app_label)
        if (not collected_txs and not is_whatsapp) or routed_tag is not None or is_custodial:
            deep = deep_parse(db_path, app_label, owner_identifiers=local_owners, **kwargs)
            if 'custodial_wallet_records' in deep and not deep['custodial_wallet_records'].empty:
                artifacts['custodial_wallet_records'] = deep['custodial_wallet_records']
            if 'transactions' in deep and not deep['transactions'].empty:
                all_tx_fragments.append(deep['transactions'])
            for k in ['chats', 'contacts', 'notifications']:
                if k in deep and not deep[k].empty:
                    if k == 'chats':
                        d_ch = deep[k]
                        d_col_map = {re.sub(r'[^a-zA-Z0-9]', '', c.lower()): c for c in d_ch.columns}
                        norm_d_ch = _normalize_chat_dataframe(
                            raw_c=d_ch,
                            col_map=d_col_map,
                            date_col='Timestamp' if 'Timestamp' in d_ch.columns else None,
                            msg_col='Message' if 'Message' in d_ch.columns else d_ch.columns[-1],
                            cparty_col='Sender' if 'Sender' in d_ch.columns else None,
                            epoch='auto',
                            local_owners=local_owners,
                        )
                        if not norm_d_ch.empty:
                            collected_chats.append(norm_d_ch)
                    elif k == 'contacts':
                        valid_d_cnt = [
                            r for _, r in deep[k].iterrows()
                            if _is_valid_human_contact(r.get('Contact_Name'), r.get('Identifier'))
                        ]
                        if valid_d_cnt:
                            collected_contacts.append(pd.DataFrame(valid_d_cnt))
                    elif k == 'notifications':
                        collected_notifs.append(deep[k])
            deep_raw = {k: v for k, v in deep.items() if k.startswith('raw__') and not v.empty}
            if 'extracted' in deep and not deep['extracted'].empty:
                deep_raw['extracted_kv'] = deep['extracted']
            if deep_raw:
                artifacts['_deep_raw'] = deep_raw
    except Exception:
        pass

    if all_tx_fragments:
        artifacts['transactions'] = synthesize_and_deduplicate_records(
            pd.concat(all_tx_fragments, ignore_index=True),
            owner_identifiers=local_owners,
        )
    # Mine `_deep_raw` tables if primary extraction found no structured payments/contacts (fixes BHIM UPI & custom stores)
    if artifacts.get('_deep_raw'):
        for raw_tname, raw_tdf in artifacts['_deep_raw'].items():
            if not isinstance(raw_tdf, pd.DataFrame) or raw_tdf.empty:
                continue
            # Check Key-Value extracted tables (`Key`, `Decoded_Value`)
            if 'Key' in raw_tdf.columns and 'Decoded_Value' in raw_tdf.columns:
                kv_txs = _carve_rkstorage_kv(
                    raw_tdf.rename(columns={'Key': 'key', 'Decoded_Value': 'value'}),
                    owner_identifiers=local_owners,
                )
                if kv_txs:
                    artifacts['transactions'] = synthesize_and_deduplicate_records(
                        pd.concat([artifacts['transactions'], pd.DataFrame(kv_txs)], ignore_index=True),
                        owner_identifiers=local_owners,
                    )

    # Auto-populate Saved Contacts / Transacted Payees from verified Counterparties if contacts table was empty
    if not artifacts['transactions'].empty:
        payee_contacts = []
        for _, tr in artifacts['transactions'].iterrows():
            cp = str(tr.get('Counterparty', 'Unknown')).strip()
            if cp != 'Unknown' and not _is_generic_cpty_label(cp):
                m_both = re.match(r'^([^()]+?)\s*\(([^()]+)\)$', cp)
                if m_both:
                    payee_contacts.append({'Contact_Name': m_both.group(1).strip(), 'Identifier': m_both.group(2).strip()})
                elif '@' in cp:
                    payee_contacts.append({'Contact_Name': cp.split('@')[0], 'Identifier': cp})
                else:
                    payee_contacts.append({'Contact_Name': cp, 'Identifier': 'Transacted Counterparty'})
        if payee_contacts:
            payee_df = pd.DataFrame(payee_contacts).drop_duplicates(subset=['Identifier'])
            artifacts['contacts'] = (
                pd.concat([artifacts['contacts'], payee_df], ignore_index=True).drop_duplicates(subset=['Identifier']).reset_index(drop=True)
                if not artifacts['contacts'].empty
                else payee_df.reset_index(drop=True)
            )
    if collected_chats:
        artifacts['chats'] = pd.concat(collected_chats, ignore_index=True).drop_duplicates()
    else:
        artifacts['chats'] = pd.DataFrame(columns=CATEGORIZED_FORENSIC_COLUMNS)
    if collected_contacts:
        c_all = pd.concat(collected_contacts, ignore_index=True).drop_duplicates()
        artifacts['contacts'] = (
            pd.concat([artifacts['contacts'], c_all], ignore_index=True).drop_duplicates(subset=['Identifier']).reset_index(drop=True)
            if not artifacts['contacts'].empty
            else c_all.reset_index(drop=True)
        )
    if collected_notifs:
        artifacts['notifications'] = pd.concat(collected_notifs, ignore_index=True).drop_duplicates()

    return artifacts