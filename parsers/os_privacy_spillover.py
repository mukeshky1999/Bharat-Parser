"""
OS-Level Privacy & Ephemeral Spillover Evidence Recovery Engine.
Extracts disappearing messages, typed tokens, clipboard entries, app switcher
task screenshots, and foreground execution timelines when suspects use
ephemeral privacy apps (Zangi, Signal, Session, Snapchat, Telegram Secret Chats).
"""

from __future__ import annotations
from src.core.sqlite_uri import ro_uri

import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

IST = timezone(timedelta(hours=5, minutes=30))

# Target Privacy & Financial Package Identifiers
TARGET_PRIVACY_PKGS = {
    'com.beint.zangi': 'Zangi Messenger',
    'org.thoughtcrime.securesms': 'Signal Private Messenger',
    'network.loki.messenger': 'Session Messenger',
    'com.snapchat.android': 'Snapchat',
    'com.instagram.android': 'Instagram',
    'com.tinder': 'Tinder',
    'com.bumble.app': 'Bumble',
    'org.telegram.messenger': 'Telegram',
    'org.telegram.plus': 'Telegram Plus',
    'ch.threema.app': 'Threema',
    'chat.simplex.app': 'SimpleX',
    'com.phonepe.app': 'PhonePe',
    'com.google.android.apps.nbu.paisa.user': 'Google Pay',
    'net.one97.paytm': 'Paytm',
    'com.binance.dev': 'Binance',
    'com.wallet.crypto.trustapp': 'Trust Wallet'
}

REGEX_PATTERNS = {
    'ZANGI_ID': re.compile(r'\b(?:\d{2}-\d{4}-\d{4}|10\d{8})\b'),
    'SESSION_ID': re.compile(r'\b05[a-fA-F0-9]{64}\b'),
    'INDIAN_MOBILE': re.compile(r'\b(?:\+?91[\-\s]?)?[6-9]\d{9}\b'),
    'UPI_VPA': re.compile(r'\b[a-zA-Z0-9.\-_]{2,64}@(okaxis|okhdfcbank|okicici|oksbi|ybl|axl|ibl|paytm|apl|upi)\b', re.IGNORECASE),
    'TRON_USDT': re.compile(r'\bT[A-Za-z1-9]{33}\b'),
    'ETH_EVM': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    'OTP_CODE': re.compile(r'\b(?:OTP|code|pin|verification)\s*[:\-]?\s*([0-9]{4,8})\b', re.IGNORECASE)
}


def normalize_ts(val: Any) -> Tuple[str, str, int]:
    if not val:
        return '', '', 0
    try:
        n = float(val)
        if n > 1000000000000000:
            ms = int(n / 1000)
        elif n > 100000000000:
            ms = int(n)
        elif n > 0:
            ms = int(n * 1000)
        else:
            ms = 0
    except Exception:
        return str(val), str(val), 0

    if ms <= 0:
        return '', '', 0

    dt_utc = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    dt_ist = dt_utc.astimezone(IST)
    return dt_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z', dt_ist.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' IST (+05:30)', ms


class OsPrivacySpilloverRecovery:
    """
    Recovers critical ephemeral artifacts from OS-level caches.
    """

    @staticmethod
    def parse_notification_spillover(db_path: str, source_file_label: str = "notification_log.db") -> List[Dict[str, Any]]:
        """
        1. Recovers incoming push notifications from disappearing chat apps.
        """
        results: List[Dict[str, Any]] = []
        if not os.path.exists(db_path):
            return results

        try:
            conn = sqlite3.connect(ro_uri(db_path), uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0].lower() for r in cur.fetchall()}

            target_tbl = next((t for t in ('notifications', 'posted_notifications', 'log', 'notification_records') if t in tables), None)
            if target_tbl:
                cur.execute(f"PRAGMA table_info({target_tbl})")
                cols = {c['name'].lower(): c['name'] for c in cur.fetchall()}

                pkg_c = cols.get('package_name') or cols.get('pkg') or cols.get('package') or 'package'
                title_c = cols.get('title') or cols.get('tag') or 'title'
                text_c = cols.get('text') or cols.get('content') or cols.get('message') or 'text'
                ts_c = cols.get('post_time') or cols.get('timestamp') or cols.get('time') or 'timestamp'

                cur.execute(f"SELECT rowid, * FROM {target_tbl} ORDER BY rowid DESC")
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r['rowid']
                    pkg = str(r[pkg_c] if pkg_c in r else '')
                    title = str(r[title_c] if title_c in r else '')
                    body = str(r[text_c] if text_c in r else '')
                    ts_val = r[ts_c] if ts_c in r else 0

                    # Check if matching target privacy or cybercrime packages
                    matched_app = None
                    for p_id, p_name in TARGET_PRIVACY_PKGS.items():
                        if p_id in pkg.lower():
                            matched_app = p_name
                            break

                    if matched_app or any(kw in body.lower() for kw in ('otp', 'disappearing', 'zangi', 'signal', 'session', 'secret chat')):
                        app_name = matched_app or f"OS Notification ({pkg[:20]})"
                        utc_iso, ist_fmt, epoch_ms = normalize_ts(ts_val)

                        results.append({
                            'Artifact_ID': f"OS_NOTIF_{row_id}",
                            'Source_App': app_name,
                            'Platform': 'Android OS Spillover',
                            'Timestamp_UTC': utc_iso,
                            'Timestamp_IST': ist_fmt,
                            'Epoch_MS': epoch_ms,
                            'Direction': 'INCOMING',
                            'Status': 'POPUP_DISPLAYED',
                            'Chat_Type': 'EPHEMERAL_NOTIFICATION_SPILLOVER',
                            'Thread_ID': pkg,
                            'Thread_Title': title or app_name,
                            'Sender_ID': title or app_name,
                            'Sender_Name': title or app_name,
                            'Recipient_ID': 'This Device (Owner)',
                            'Recipient_Name': 'This Device (Owner)',
                            'Message_Text': body or f"Notification from {title}",
                            'Message_Type': 'NOTIFICATION_POPUP',
                            'Source_File': source_file_label,
                            'Source_Table': target_tbl,
                            'Row_ID': row_id,
                            'Page_Number': 0,
                            'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                            'Recovery_Method': 'OS Notification Spillover'
                        })

            conn.close()
        except Exception:
            pass

        return results

    @staticmethod
    def parse_keyboard_clipboard_caches(file_path: str, source_file_label: str = "keyboard_cache.db") -> List[Dict[str, Any]]:
        """
        2. Recovers typed tokens, Zangi IDs, Session IDs, VPAs, and OTPs from keyboard dictionaries and clipboard.
        """
        results: List[Dict[str, Any]] = []
        if not os.path.exists(file_path):
            return results

        # If SQLite database (user_dict.db)
        if file_path.endswith('.db') or file_path.endswith('.sqlite'):
            try:
                conn = sqlite3.connect(ro_uri(file_path), uri=True)
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cur.fetchall()]

                for tbl in tables:
                    try:
                        cur.execute(f"SELECT rowid, * FROM {tbl}")
                        for r in cur.fetchall():
                            r = dict(r)
                            row_id = r[0]
                            row_str = ' '.join(str(v) for v in r[1:] if v)

                            # Scan for high-value cybercrime tokens
                            for pattern_name, regex in REGEX_PATTERNS.items():
                                matches = regex.findall(row_str)
                                for match_val in matches:
                                    val_str = match_val if isinstance(match_val, str) else match_val[0]
                                    results.append({
                                        'Artifact_ID': f"KB_CACHE_{row_id}_{pattern_name}",
                                        'Source_App': 'Keyboard/Clipboard Cache',
                                        'Platform': 'OS Spillover',
                                        'Token_Type': pattern_name,
                                        'Extracted_Value': val_str,
                                        'Surrounding_Context': row_str[:120],
                                        'Source_File': source_file_label,
                                        'Source_Table': tbl,
                                        'Row_ID': row_id,
                                        'Byte_Offset': '',  # no B-tree walk: offset unknown (C-09)
                                        'Recovery_Method': 'Keyboard Cache Spillover'
                                    })
                    except Exception:
                        pass
                conn.close()
            except Exception:
                pass
        else:
            # Plain binary or text cache (clipboard, token files)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read().decode('latin1', errors='ignore')

                for pattern_name, regex in REGEX_PATTERNS.items():
                    for match in regex.finditer(content):
                        match_str = match.group(0)
                        offset = match.start()
                        results.append({
                            'Artifact_ID': f"CLIPBOARD_{pattern_name}_{offset}",
                            'Source_App': 'OS Clipboard',
                            'Platform': 'OS Spillover',
                            'Token_Type': pattern_name,
                            'Extracted_Value': match_str,
                            'Surrounding_Context': content[max(0, offset - 40):min(len(content), offset + 80)].strip(),
                            'Source_File': source_file_label,
                            'Source_Table': 'clipboard_dump',
                            'Row_ID': offset,
                            'Byte_Offset': f"0x{offset:08X}",
                            'Recovery_Method': 'Clipboard Cache Spillover'
                        })
            except Exception:
                pass

        return results

    @staticmethod
    def index_app_switcher_snapshots(snapshots_dir: str) -> List[Dict[str, Any]]:
        """
        3. Indexes recent task snapshots captured by Android/iOS when minimizing privacy apps.
        """
        results: List[Dict[str, Any]] = []
        if not os.path.exists(snapshots_dir):
            return results

        try:
            for root, _, files in os.walk(snapshots_dir):
                for f in files:
                    if f.endswith(('.jpg', '.jpeg', '.png')):
                        full_p = os.path.join(root, f)
                        st = os.stat(full_p)
                        utc_iso, ist_fmt, epoch_ms = normalize_ts(st.st_mtime)

                        # Check if snapshot filename contains package or taskId
                        matched_app = "Task Snapshot"
                        for p_id, p_name in TARGET_PRIVACY_PKGS.items():
                            if p_id in f.lower():
                                matched_app = f"{p_name} Snapshot"
                                break

                        results.append({
                            'Artifact_ID': f"SNAP_TASK_{f}",
                            'Source_App': matched_app,
                            'Platform': 'App Switcher Snapshot',
                            'File_Path': full_p,
                            'File_Name': f,
                            'File_Size_Bytes': st.st_size,
                            'Timestamp_UTC': utc_iso,
                            'Timestamp_IST': ist_fmt,
                            'Epoch_MS': epoch_ms,
                            'OCR_Queued': True,
                            'Recovery_Method': 'App Switcher Recent Task Snapshot'
                        })
        except Exception:
            pass

        return results

    @staticmethod
    def parse_usagestats_timeline(usagestats_path: str) -> List[Dict[str, Any]]:
        """
        4. Builds a precise foreground execution timeline showing exact seconds
        target privacy apps were opened around a crime timestamp.
        """
        results: List[Dict[str, Any]] = []
        if not os.path.exists(usagestats_path):
            return results

        # Parse iOS knowledgeC.db
        if usagestats_path.endswith('.db') or 'knowledgec' in usagestats_path.lower():
            try:
                conn = sqlite3.connect(ro_uri(usagestats_path), uri=True)
                conn.row_factory = sqlite3.Row
                conn.row_factory = sqlite3.Row  # dict(row) below needs named columns
                cur = conn.cursor()
                cur.execute("""
                SELECT Z_PK, ZSTARTDATE, ZENDDATE, ZSTREAMNAME, ZVALUESTRING
                FROM ZOBJECT
                WHERE ZSTREAMNAME LIKE '%/app/inFocus%' OR ZSTREAMNAME LIKE '%app.inFocus%'
                ORDER BY ZSTARTDATE DESC
                """)
                for r in cur.fetchall():
                    r = dict(r)
                    row_id = r.get('Z_PK')
                    s_date = r.get('ZSTARTDATE') or 0
                    e_date = r.get('ZENDDATE', 0)
                    stream = r.get('ZSTREAMNAME', '')
                    app_id = r.get('ZVALUESTRING', '')
                    utc_iso, ist_fmt, epoch_ms = normalize_ts(s_date + 978307200.0)

                    app_str = str(app_id or '')
                    matched_label = TARGET_PRIVACY_PKGS.get(app_str, app_str)

                    results.append({
                        'Artifact_ID': f"KNOWLEDGEC_{row_id}",
                        'Source_App': matched_label,
                        'Platform': 'iOS knowledgeC',
                        'App_Identifier': app_str,
                        'Activity': 'App inFocus (Foreground Execution)',
                        'Timestamp_UTC': utc_iso,
                        'Timestamp_IST': ist_fmt,
                        'Epoch_MS': epoch_ms,
                        'Recovery_Method': 'UsageStats Foreground Timeline'
                    })
                conn.close()
            except Exception:
                pass

        return results


# =============================================================================
# TOP-LEVEL OS PRIVACY SPILLOVER API & DATAFRAME GENERATORS
# =============================================================================

import pandas as pd


def extract_chat_notifications(db_path: str) -> pd.DataFrame:
    """
    Recovers incoming push notifications from disappearing chat apps.
    """
    records = OsPrivacySpilloverRecovery.parse_notification_spillover(db_path)
    return pd.DataFrame(records)


def extract_keyboard_clipboard_tokens(file_path: str) -> pd.DataFrame:
    """
    Recovers typed tokens, Zangi IDs, Session IDs, VPAs, and OTPs from keyboard dictionaries and clipboard.
    """
    records = OsPrivacySpilloverRecovery.parse_keyboard_clipboard_caches(file_path)
    return pd.DataFrame(records)


def extract_app_switcher_snapshots(dir_or_paths: Union[str, List[str]]) -> pd.DataFrame:
    """
    Indexes OS task-switcher screenshots captured when the user minimized a privacy app.
    """
    records = OsPrivacySpilloverRecovery.index_app_switcher_snapshots(dir_or_paths)
    return pd.DataFrame(records)


def extract_usage_timeline(file_or_dir: str) -> pd.DataFrame:
    """
    Builds a precise foreground execution timeline proving the exact second the suspect opened privacy/banking apps.
    """
    records = OsPrivacySpilloverRecovery.parse_usagestats_timeline(file_or_dir)
    return pd.DataFrame(records)


def recover_all_privacy_spillovers(extraction_root: str) -> Dict[str, pd.DataFrame]:
    """
    Scans an extraction folder or VFS root for all 4 OS spillover artifacts
    and returns a categorized dictionary of DataFrames.
    """
    results = {
        'notifications': pd.DataFrame(),
        'keyboard_tokens': pd.DataFrame(),
        'snapshots': pd.DataFrame(),
        'timeline': pd.DataFrame(),
    }

    if not os.path.exists(extraction_root):
        return results

    # Scan for notification databases
    notif_candidates = ['notification_log.db', 'notifs.db', 'fcm_queued_messages.db']
    kb_candidates = ['user_dict.db', 'trainingcache.db', 'clips.xml', 'clipboard_dump.txt']
    snap_candidates = ['snapshots', 'Snapshots']
    usage_candidates = ['usagestats', 'knowledgeC.db']

    for root, dirs, files in os.walk(extraction_root):
        for f in files:
            f_low = f.lower()
            full_path = os.path.join(root, f)
            if any(nc in f_low for nc in notif_candidates):
                df = extract_chat_notifications(full_path)
                if not df.empty:
                    results['notifications'] = pd.concat([results['notifications'], df], ignore_index=True)
            elif any(kc in f_low for kc in kb_candidates):
                df = extract_keyboard_clipboard_tokens(full_path)
                if not df.empty:
                    results['keyboard_tokens'] = pd.concat([results['keyboard_tokens'], df], ignore_index=True)
            elif any(uc in f_low for uc in usage_candidates):
                df = extract_usage_timeline(full_path)
                if not df.empty:
                    results['timeline'] = pd.concat([results['timeline'], df], ignore_index=True)

        for d in dirs:
            if any(sc in d for sc in snap_candidates):
                full_dir = os.path.join(root, d)
                df = extract_app_switcher_snapshots(full_dir)
                if not df.empty:
                    results['snapshots'] = pd.concat([results['snapshots'], df], ignore_index=True)

    return results
