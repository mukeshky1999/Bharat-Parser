"""
Unsupervised Zero-Knowledge Financial Data Mining Engine.
Inspects uncataloged SQLite databases to detect genuine unknown Indian banking/UPI ledgers
while strictly excluding social media, browser, media, and OS system databases (e.g. Facebook,
Instagram, Google Play Services, WebView, Contacts, Settings).
"""

from __future__ import annotations
from src.core.sqlite_uri import ro_uri

import os
import re
import sqlite3
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from parsers.app_overrides import is_valid_counterparty, is_valid_txid, normalize_timestamp_value
from parsers.vpa_harvester import clean_and_validate_vpa

UTR_REGEX = re.compile(r'^[0-9]{12}$')

# Non-financial app/system path tokens that must NEVER be mined as financial apps
NON_FINANCIAL_PATH_BLOCKLIST = (
    'facebook', 'fbmessaging', 'orca', 'katana', 'instagram', 'burbn',
    'snapchat', 'zhiliaoapp', 'musically', 'tiktok', 'twitter', 'linkedin',
    'spotify', 'netflix', 'youtube', 'vending', 'google.android.gms',
    'google.android.gsf', 'googlequicksearchbox', 'chrome', 'webview',
    'com.android.providers', 'contacts2', 'calendar', 'downloads', 'media',
    'gallery', 'photos', 'camera', 'settings', 'systemui', 'launcher',
    'keyboard', 'inputmethod', 'LatinIME', 'gboard', 'truecaller',
    'analytics', 'crashlytics', 'firebase', 'workmanager', 'androidx.work',
    'room_master', 'exoplayer', 'glide', 'fresco', 'picasso', 'coil',
    'OneSignal', 'clevertap', 'moengage', 'branch.io', 'appsflyer',
)

BLACKLIST_TABLES = {
    'android_metadata', 'sqlite_sequence', 'sqlite_stat1', 'room_master_table',
    'workspec', 'worktag', 'workname', 'systemidinfo', 'preference', 'session',
    'http_auth', 'properties', 'geofence', 'sync_state', 'metadata', 'events',
    'cookies', 'cache', 'favicons', 'history', 'downloads', 'autofill',
}


def _score_table(df: pd.DataFrame) -> Tuple[float, Dict[str, str]]:
    """
    Scores a candidate SQLite table.
    Requires genuine financial column names AND actual verified UPI VPAs (`@handle`)
    or 12-digit UTRs in the rows before qualifying as a financial ledger.
    """
    if df.empty or len(df.columns) < 3:
        return 0.0, {}

    score = 0.0
    mapping: Dict[str, str] = {}
    col_map = {re.sub(r'[^a-zA-Z0-9]', '', c.lower()): c for c in df.columns}

    # 1. Explicit Financial Amount Column (excludes generic 'val' or 'total')
    for norm_c, orig_c in col_map.items():
        if any(k in norm_c for k in ['txnamount', 'transactionamount', 'paidamount', 'amount', 'amt', 'debitamount', 'creditamount']):
            if any(norm_c.endswith(sfx) for sfx in ('id', 'no', 'num', 'code', 'time', 'date', 'count')):
                continue
            try:
                numeric = pd.to_numeric(df[orig_c], errors='coerce').dropna().abs()
                if not numeric.empty and (numeric > 0).any():
                    if (numeric <= 5_000_000).mean() >= 0.75:
                        mapping['amount'] = orig_c
                        score += 30.0
                        break
            except Exception:
                continue

    if 'amount' not in mapping:
        return 0.0, {}

    # 2. Counterparty / VPA Column
    for norm_c, orig_c in col_map.items():
        if any(k in norm_c for k in ['vpa', 'payeevpa', 'payervpa', 'payee', 'beneficiary', 'counterparty', 'merchantname', 'narration']):
            mapping['counterparty'] = orig_c
            score += 20.0
            break

    # 3. Verify Actual Indian UPI VPA or 12-Digit UTR Presence in Sample Values
    has_real_vpa = False
    sample_strs = df.head(100).astype(str).values.flatten()
    for s in sample_strs[:600]:
        if '@' in s:
            for tok in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', s):
                if clean_and_validate_vpa(tok):
                    has_real_vpa = True
                    break
        if has_real_vpa:
            break

    if has_real_vpa:
        score += 35.0

    # 4. Transaction ID / UTR Column
    for norm_c, orig_c in col_map.items():
        if any(k in norm_c for k in ['txid', 'txnid', 'transactionid', 'utr', 'bankref', 'upi_txn_id']):
            mapping['txid'] = orig_c
            score += 15.0
            break

    # 5. Date / Timestamp Column
    for norm_c, orig_c in col_map.items():
        if any(k in norm_c for k in ['txndate', 'txntime', 'transactiontime', 'createdat', 'timestamp', 'date', 'time']):
            mapping['date'] = orig_c
            score += 10.0
            break

    # 6. Status / Type Column
    for norm_c, orig_c in col_map.items():
        if any(k in norm_c for k in ['txnstatus', 'paymentstatus', 'status', 'state', 'txntype']):
            mapping['status'] = orig_c
            score += 5.0
            break

    # Must have a real VPA OR both an explicit counterparty column and an explicit txid column
    if not has_real_vpa and not ('counterparty' in mapping and 'txid' in mapping):
        return 0.0, {}

    return score, mapping


def inspect_unindexed_database(db_path: str, clean_path: str) -> Optional[Tuple[str, Dict[str, pd.DataFrame]]]:
    """
    Zero-Knowledge Scanner: inspects unknown SQLite databases while skipping
    non-financial social/system apps (`FBMessaging...`, `gms`, `webview`, etc.).
    """
    if not os.path.exists(db_path):
        return None

    path_low = clean_path.replace('\\', '/').lower()
    if any(blocked in path_low for blocked in NON_FINANCIAL_PATH_BLOCKLIST):
        return None

    # Quick SQLite header check before opening connection
    try:
        with open(db_path, 'rb') as f:
            if f.read(16) != b'SQLite format 3\x00':
                return None
    except Exception:
        return None

    conn = None
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = [r[0] for r in cursor.fetchall() if not r[0].startswith('sqlite_')]
    except Exception:
        if conn:
            conn.close()
        return None

    tables = [t for t in tables if t.lower() not in BLACKLIST_TABLES]
    if not tables:
        if conn:
            conn.close()
        return None

    mined_transactions: List[pd.DataFrame] = []
    try:
        for t in tables:
            if any(skip in t.lower() for skip in ('message', 'chat', 'thread', 'contact', 'analytics', 'config', 'log', 'cache', 'media')):
                continue
            try:
                sample_df = pd.read_sql_query(f'SELECT * FROM "{t}" LIMIT 2000', conn)
                if sample_df.empty:
                    continue

                conf_score, col_map = _score_table(sample_df)
                if conf_score >= 70.0 and ('amount' in col_map and 'counterparty' in col_map):
                    tx = pd.DataFrame(index=sample_df.index)
                    tx['Date'] = (
                        sample_df[col_map['date']].map(lambda v: normalize_timestamp_value(v, 'auto'))
                        if 'date' in col_map else None
                    )
                    tx['Transaction_ID'] = (
                        sample_df[col_map['txid']].map(lambda v: str(v).strip() if is_valid_txid(v) else 'N/A')
                        if 'txid' in col_map else 'N/A'
                    )
                    tx['Amount'] = pd.to_numeric(sample_df[col_map['amount']], errors='coerce').abs()
                    tx['Counterparty'] = sample_df[col_map['counterparty']].map(
                        lambda v: str(v).strip() if is_valid_counterparty(v) else 'Unknown'
                    )
                    tx['Status'] = (
                        sample_df[col_map['status']].astype(str)
                        if 'status' in col_map else 'SUCCESS'
                    )

                    amt_col_low = col_map['amount'].lower()
                    if any(u in amt_col_low for u in ('paise', 'paisa', 'minor', 'cent')):
                        tx['Amount'] = tx['Amount'] / 100.0

                    st_str = tx['Status'].astype(str).str.upper()
                    tx['Type'] = np.where(
                        st_str.str.contains('DEBIT|SENT|PAID|WITHDRAW', na=False),
                        'DEBIT',
                        np.where(st_str.str.contains('CREDIT|RECEIVED|REFUND', na=False), 'CREDIT', 'TRANSFER')
                    )

                    tx = tx[tx['Amount'].notna() & (tx['Amount'] > 0) & (tx['Counterparty'] != 'Unknown')]
                    if not tx.empty:
                        mined_transactions.append(tx)
            except Exception:
                continue
    finally:
        if conn:
            conn.close()

    if mined_transactions:
        consolidated = pd.concat(mined_transactions, ignore_index=True).drop_duplicates()
        parts = clean_path.replace('\\', '/').split('/')
        app_name = f"Discovered Financial DB ({parts[-3] if len(parts) >= 3 else parts[0]})"
        return app_name, {'transactions': consolidated}

    return None