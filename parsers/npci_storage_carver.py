"""
Next-Gen Non-SQLite Storage & Universal NPCI Protocol Grammar Carver.
Supports:
- Tencent MMKV (/files/mmkv/*) & Android Jetpack DataStore (*.preferences_pb / *.pb)
- Realm (*.realm) & Flutter Hive/Isar (*.hive, *.isar) binary stores
- Universal NPCI `upi://pay?...` and `upi://mandate?...` URI & QR Intent parsing
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse
import pandas as pd

from parsers.app_overrides import (
    extract_from_blob,
    normalize_timestamp_value,
)
from parsers.protobuf_decoder import (
    decode_protobuf_stream,
    extract_financials_from_protobuf,
)

# Universal NPCI UPI Deep-Link / QR / Mandate / Circle URI Pattern
UPI_URI_REGEX = re.compile(
    rb'upi://(?:pay|mandate|collect|global|circle)\?[a-zA-Z0-9%\-._~&=+@:/$,;]+',
    re.IGNORECASE,
)

# Base64-encoded `upi://pay?` prefix (`dXBpOi8vcGF5P` or `dXBpOi8vbWFuZGF0ZT`)
B64_UPI_REGEX = re.compile(rb'(?:dXBpOi8vcGF5P|dXBpOi8vbWFuZGF0ZT)[A-Za-z0-9+/=]{16,512}')

# 35-character NPCI Canonical Transaction ID
NPCI_TXID_REGEX = re.compile(
    r'\b(?:YBL|IBL|AXL|OKH|OKI|OKA|OKS|PTM|PYT|UPI|SBI|ICI|HDF|AXIS|KKB|BARB|PUNB|CNRB|UBIN|IDFC|INDB|FDRL)[a-zA-Z0-9]{20,32}\b'
)

INLINE_JSON_REGEX = re.compile(rb'\{[^{}]{18,2000}\}')


def parse_npci_upi_uri(uri_str: str) -> Optional[Dict[str, Any]]:
    """
    Parses an NPCI standard `upi://pay?...` or `upi://mandate?...` URI into a structured record.
    Works across all past, present, and future Indian payment apps.
    """
    try:
        clean_uri = unquote(uri_str.strip())
        parsed = urlparse(clean_uri)
        params = parse_qs(parsed.query)

        is_mandate = 'mandate' in parsed.netloc.lower() or 'mandate' in clean_uri.lower()
        is_circle = 'circle' in parsed.netloc.lower() or 'circle' in clean_uri.lower() or params.get('mandateType', [''])[0].upper() == 'DELEGATED'
        delegate_vpa = params.get('delegateVpa', [None])[0]
        primary_vpa = params.get('primaryVpa', [None])[0]
        circle_status = params.get('circleStatus', [None])[0]
        pa = params.get('pa', [None])[0] or delegate_vpa
        pn = params.get('pn', [None])[0]
        am = params.get('am', [None])[0] or params.get('mam', [None])[0]
        tr = params.get('tr', [None])[0] or params.get('tid', [None])[0] or params.get('umn', [None])[0]
        purpose = params.get('purpose', [''])[0]

        if not pa and not am and not is_circle:
            return None

        amt_val = None
        if am:
            try:
                amt_val = float(re.sub(r'[^\d.]', '', str(am)))
            except ValueError:
                amt_val = None

        cparty = pa if pa else (pn if pn else ('UPI Circle Delegated' if is_circle else 'UPI QR Merchant'))
        if pa and pn and pn.lower() not in pa.lower():
            cparty = f"{pa} ({pn[:30]})"

        if is_circle:
            status = f"UPI_CIRCLE_DELEGATED ({circle_status or 'Active'})"
        elif is_mandate:
            status = 'UPI_AUTOPAY_MANDATE'
        elif purpose == '41':
            status = 'UPI_LITE_ON_DEVICE'
        else:
            status = 'UPI_INTENT / QR_SCANNED'

        return {
            'Date': None,
            'Transaction_ID': str(tr) if tr else ('UPI_CIRCLE' if is_circle else ('UPI_MANDATE' if is_mandate else 'UPI_QR_INTENT')),
            'Amount': amt_val,
            'Counterparty': cparty,
            'Status': status,
            'Type': 'DEBIT',
            'Delegation_Flag': is_circle,
        }
    except Exception:
        return None


def carve_non_sqlite_store(file_path: str, app_label: str = '') -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Carves transactions and user profile attributes from non-SQLite storage engines:
    MMKV, Android Jetpack DataStore (.preferences_pb), Realm (.realm), and Flutter Hive (.hive).
    """
    std_cols = ['Date', 'Transaction_ID', 'Amount', 'Counterparty', 'Status', 'Type']
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return pd.DataFrame(columns=std_cols), {}

    tx_records: List[Dict[str, Any]] = []
    profile_hints: Dict[str, Any] = {}

    try:
        with open(file_path, 'rb') as f:
            raw_bytes = f.read(32 * 1024 * 1024)
    except Exception:
        return pd.DataFrame(columns=std_cols), {}

    # 1. Extract Universal NPCI `upi://pay?...` and `upi://mandate?...` URIs
    for m in UPI_URI_REGEX.finditer(raw_bytes):
        uri_s = m.group(0).decode('utf-8', errors='ignore')
        parsed_uri = parse_npci_upi_uri(uri_s)
        if parsed_uri and parsed_uri.get('Amount'):
            tx_records.append(parsed_uri)

    # 1b. Extract Base64-encoded UPI QR payloads
    for bm in B64_UPI_REGEX.finditer(raw_bytes):
        try:
            decoded_uri = base64.b64decode(bm.group(0) + b'==').decode('utf-8', errors='ignore')
            parsed_b64 = parse_npci_upi_uri(decoded_uri)
            if parsed_b64 and parsed_b64.get('Amount'):
                tx_records.append(parsed_b64)
        except Exception:
            continue

    # 2. Extract Inline JSON Payloads (MMKV, Realm, Hive, React Native caches)
    for m in INLINE_JSON_REGEX.finditer(raw_bytes):
        chunk_bytes = m.group(0)
        try:
            text = chunk_bytes.decode('utf-8', errors='ignore')
            if any(k in text.lower() for k in ['amount', 'vpa', 'txnid', 'transactionid', 'utr', 'payee', 'delegatevpa', 'circlemandate']):
                is_delegated = any(k in text.lower() for k in ['delegatevpa', 'primaryvpa', 'circlestatus'])
                ext = extract_from_blob(chunk_bytes, app_label=app_label)
                if ext.get('Amount') is not None or is_delegated:
                    try:
                        amt = float(ext.get('Amount') or 0.0)
                    except (ValueError, TypeError):
                        amt = 0.0
                    if amt > 0 or is_delegated:
                        tx_records.append({
                            'Date': normalize_timestamp_value(ext.get('Date'), 'auto'),
                            'Transaction_ID': str(ext.get('Transaction_ID') or ('UPI_CIRCLE_JSON' if is_delegated else 'MMKV_JSON_REC')),
                            'Amount': amt,
                            'Counterparty': str(ext.get('Counterparty') or ('UPI Circle User' if is_delegated else 'Unknown')),
                            'Status': str(ext.get('Status') or ('UPI_CIRCLE_DELEGATED' if is_delegated else 'SUCCESS')),
                            'Type': 'TRANSFER',
                            'Delegation_Flag': is_delegated,
                        })
        except Exception:
            continue

    # 3. Decode Protobuf Streams (Jetpack DataStore .preferences_pb & MMKV varint streams)
    if file_path.lower().endswith(('.preferences_pb', '.pb')) or 'mmkv' in file_path.lower():
        pb_decoded = decode_protobuf_stream(raw_bytes[:262144], max_depth=3)
        if pb_decoded:
            fin = extract_financials_from_protobuf(pb_decoded)
            pb_amt = None
            if fin.get('Amount') is not None:
                try:
                    pb_amt = float(fin['Amount'])
                except (ValueError, TypeError):
                    pb_amt = None
            if pb_amt is not None and pb_amt > 0:
                tx_records.append({
                    'Date': normalize_timestamp_value(fin.get('Date'), 'auto'),
                    'Transaction_ID': str(fin.get('Transaction_ID') or 'PB_STORE_REC'),
                    'Amount': pb_amt,
                    'Counterparty': str(fin.get('Counterparty') or 'Unknown'),
                    'Status': 'SUCCESS',
                    'Type': 'TRANSFER',
                    'Delegation_Flag': False,
                })

    # 4. Extract Owner Profile Hints (VPA & Registered Mobile) from MMKV / DataStore
    text_latin = raw_bytes[:524288].decode('latin-1', errors='ignore')
    vpa_m = re.search(r'\b([a-zA-Z0-9.\-_]{3,40}@[a-zA-Z0-9]{2,20})\b', text_latin)
    if vpa_m and not vpa_m.group(1).lower().endswith(('.com', '.in', '.org', '.png', '.jpg')):
        profile_hints['Primary_VPA'] = vpa_m.group(1)
    phone_m = re.search(r'(?:\+?91)?([6-9]\d{9})\b', text_latin)
    if phone_m:
        profile_hints['Registered_Phone'] = phone_m.group(1)

    if tx_records:
        df_out = pd.DataFrame(tx_records).drop_duplicates(subset=['Transaction_ID', 'Amount', 'Counterparty'])
        cols_to_use = [c for c in std_cols if c in df_out.columns]
        if 'Delegation_Flag' in df_out.columns:
            cols_to_use.append('Delegation_Flag')
        return df_out[cols_to_use], profile_hints

    return pd.DataFrame(columns=std_cols), profile_hints