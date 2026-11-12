"""
Deep SQLite Inspector & Per-App Forensic Decoders.
Fixes the >100 Rupee division bug and uses owner_identifiers to pick the external
counterparty and accurate DEBIT/CREDIT direction in PhonePe and WhatsApp stores.
"""

from __future__ import annotations
from src.core.sqlite_uri import ro_uri

import json
import logging
import os
import re
import sqlite3
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from parsers import is_safe_sqlite_table_name, quote_sqlite_identifier
from parsers.app_overrides import (
    is_valid_counterparty,
    is_valid_txid,
    matches_owner_identity,
    normalize_timestamp_value,
    resolve_payer_payee_counterparty,
)
from parsers.protobuf_decoder import decode_protobuf_stream

logger = logging.getLogger(__name__)


def _name_tokens(name: Any) -> Set[str]:
    """Lower-case word tokens of a column name: 'sentTime' -> {'sent','time'}, 'recipient_id' -> {'recipient','id'}."""
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', str(name))
    return {t for t in re.split(r'[^a-z0-9]+', spaced.lower()) if t}


def _decode_blob(raw: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 2:
        return None, 'raw'
    data = bytes(raw)

    for wbits, tag in (
        (zlib.MAX_WBITS, 'zlib+json'),
        (16 + zlib.MAX_WBITS, 'gzip+json'),
        (-zlib.MAX_WBITS, 'deflate+json'),
    ):
        try:
            decompressed = zlib.decompress(data, wbits)
        except zlib.error:
            continue
        try:
            payload = json.loads(decompressed.decode('utf-8', errors='replace'))
            return {'_json': payload}, tag
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    try:
        payload = json.loads(data.decode('utf-8', errors='replace'))
        return {'_json': payload}, 'json'
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    for wbits, tag in (
        (zlib.MAX_WBITS, 'zlib+protobuf'),
        (16 + zlib.MAX_WBITS, 'gzip+protobuf'),
        (-zlib.MAX_WBITS, 'deflate+protobuf'),
    ):
        try:
            decompressed = zlib.decompress(data, wbits)
        except zlib.error:
            continue
        pb = decode_protobuf_stream(decompressed, max_depth=4)
        if pb:
            return {'_pb': pb}, tag

    pb = decode_protobuf_stream(data, max_depth=4)
    if pb:
        return {'_pb': pb}, 'protobuf'

    try:
        text = data.decode('utf-8')
        if text.strip() and any(c.isalnum() for c in text):
            return {'_text': text}, 'utf8'
    except UnicodeDecodeError:
        pass

    return None, 'raw'


def _flatten_json(obj: Any, prefix: str = '', max_depth: int = 3) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if max_depth <= 0:
        return {prefix: str(obj)[:200]}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, key, max_depth - 1))
            else:
                out[key] = v
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:5]):
            key = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                out.update(_flatten_json(item, key, max_depth - 1))
            else:
                out[key] = item
    else:
        out[prefix] = obj
    return out


def dump_sqlite_tables(
    db_path: str,
    max_rows_per_table: int = 5000,
    max_blob_bytes: int = 65536,
) -> Dict[str, pd.DataFrame]:
    out: Dict[str, pd.DataFrame] = {}
    if not os.path.exists(db_path):
        return out
    conn = None
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = [r[0] for r in cur.fetchall() if not r[0].startswith('sqlite_')]
        for table in tables:
            if not is_safe_sqlite_table_name(table):
                continue
            q_table = quote_sqlite_identifier(table)
            try:
                df = pd.read_sql_query(
                    f'SELECT * FROM {q_table} LIMIT {max_rows_per_table}',
                    conn,
                )
                if df.empty:
                    continue
                if len(df) >= max_rows_per_table:
                    logger.warning('TRUNCATED: table %s in %s has at least %d rows; only the first %d were read',
                                   table, os.path.basename(db_path), max_rows_per_table, max_rows_per_table)
                for col in df.columns:
                    sample = df[col].dropna()
                    if len(sample) == 0:
                        continue
                    if any(isinstance(val, (bytes, bytearray)) for val in sample.iloc[:10]):
                        decoded: List[Optional[str]] = []
                        method: List[str] = []
                        for raw in df[col]:
                            if not isinstance(raw, (bytes, bytearray)):
                                decoded.append(str(raw) if pd.notna(raw) else None)
                                method.append('n/a')
                                continue
                            parsed, m = _decode_blob(raw[:max_blob_bytes])
                            method.append(m)
                            if parsed is None:
                                decoded.append(None)
                            elif '_json' in parsed:
                                decoded.append(json.dumps(_flatten_json(parsed['_json']), default=str)[:4000])
                            elif '_pb' in parsed:
                                decoded.append(str(parsed['_pb'])[:4000])
                            elif '_text' in parsed:
                                decoded.append(parsed['_text'][:4000])
                            else:
                                decoded.append(None)
                        df[f'{col}__decoded'] = decoded
                        df[f'{col}__method'] = method
                out[table] = df
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return out


_KV_KEY_NAMES = {'key', 'name', 'k', 'preference', 'config_key', 'column_key'}
_KV_VAL_NAMES = {'value', 'val', 'v', 'data', 'config_value', 'column_value'}


def _looks_like_kv_table(df: pd.DataFrame) -> bool:
    if df is None or df.empty or len(df.columns) < 2:
        return False
    lower = [str(c).lower() for c in df.columns]
    has_key = any(c in _KV_KEY_NAMES for c in lower)
    has_val = any(c in _KV_VAL_NAMES for c in lower)
    return has_key and has_val


def extract_kv_pairs(df: pd.DataFrame) -> pd.DataFrame:
    lower = {str(c).lower(): c for c in df.columns}
    key_col = next((lower[k] for k in lower if k in _KV_KEY_NAMES), None)
    val_col = next((lower[k] for k in lower if k in _KV_VAL_NAMES), None)
    if key_col is None or val_col is None:
        return pd.DataFrame(columns=['Key', 'Value', 'Decoded_Value', 'Encoding'])

    rows = []
    for _, r in df.iterrows():
        key = str(r.get(key_col, ''))
        raw_val = r.get(val_col)
        decoded_val: Optional[str] = None
        encoding = 'raw'
        if isinstance(raw_val, (bytes, bytearray)):
            parsed, method = _decode_blob(raw_val)
            encoding = method
            if parsed is not None:
                if '_json' in parsed:
                    decoded_val = json.dumps(_flatten_json(parsed['_json']), default=str)[:4000]
                elif '_pb' in parsed:
                    decoded_val = str(parsed['_pb'])[:4000]
                elif '_text' in parsed:
                    decoded_val = parsed['_text'][:4000]
        else:
            decoded_val = str(raw_val)[:4000] if raw_val is not None else None
        rows.append({
            'Key': key,
            'Value': (
                str(raw_val)[:500]
                if not isinstance(raw_val, (bytes, bytearray))
                else f'<{len(raw_val)} bytes>'
            ),
            'Decoded_Value': decoded_val,
            'Encoding': encoding,
        })
    return pd.DataFrame(rows)


_PHONEPE_KNOWN = {
    'chatplatform.sqlite': 'phonepe_chats',
    'p2p.sqlite': 'phonepe_txn',
    'transactionsstore.sqlite': 'phonepe_txn',
    'authdatamodel.sqlite': 'phonepe_auth',
    'chronicle.sqlite': 'phonepe_activity',
}
_WHATSAPP_KNOWN = {
    'payments.sqlite': 'whatsapp_pay',
    'callhistory.sqlite': 'whatsapp_calls',
}
_JIOFINANCE_KNOWN = {
    'cache.db': 'jiofinance_http',
    'httpstorages.sqlite': 'jiofinance_http',
}


def route_sqlite_file(basename: str, app_label: str) -> Optional[str]:
    b = basename.lower()
    if app_label == 'PhonePe':
        return _PHONEPE_KNOWN.get(b)
    if app_label == 'WhatsApp':
        return _WHATSAPP_KNOWN.get(b)
    if app_label == 'JioFinance':
        return _JIOFINANCE_KNOWN.get(b)
    return None


def _parse_phonepe_chats(db_path: str) -> pd.DataFrame:
    out_cols = ['Timestamp', 'Sender', 'Recipient', 'Message']
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=20000).items():
        lower = {str(c).lower(): c for c in df.columns}
        ts_col = next((lower[k] for k in lower if _name_tokens(k) & {'time', 'timestamp', 'date', 'created', 'sent', 'ts'}), None)
        msg_col = next((lower[k] for k in lower if _name_tokens(k) & {'message', 'msg', 'body', 'text', 'payload', 'note', 'content'}), None)
        sender_col = next((lower[k] for k in lower if _name_tokens(k) & {'sender', 'from', 'origin'}), None)
        recipient_col = next((lower[k] for k in lower if _name_tokens(k) & {'recipient', 'receiver', 'to', 'destination'}), None)
        if not msg_col:
            continue
        for _, r in df.iterrows():
            msg_val = r.get(msg_col)
            if isinstance(msg_val, (bytes, bytearray)):
                parsed, _ = _decode_blob(msg_val)
                if parsed and '_text' in parsed:
                    msg_val = parsed['_text']
                elif parsed and '_json' in parsed:
                    msg_val = json.dumps(parsed['_json'], default=str)
                else:
                    continue
            msg_str = str(msg_val).strip() if msg_val is not None else ''
            if len(msg_str) < 2:
                continue
            rows.append({
                'Timestamp': normalize_timestamp_value(r.get(ts_col), 'auto') if ts_col else '',
                'Sender': str(r.get(sender_col)) if sender_col and r.get(sender_col) is not None else 'Unknown',
                'Recipient': str(r.get(recipient_col)) if recipient_col and r.get(recipient_col) is not None else 'Unknown',
                'Message': msg_str[:8000],
            })
    if rows:
        return pd.DataFrame(rows)[out_cols]
    return pd.DataFrame(columns=out_cols)


def _parse_phonepe_transactions(db_path: str, owner_identifiers: Optional[Set[str]] = None) -> pd.DataFrame:
    out_cols = ['Date', 'Transaction_ID', 'Amount', 'Counterparty', 'Status', 'Type', 'Amount_Basis']
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=30000).items():
        for _, r in df.iterrows():
            try:
                amount: Optional[float] = None
                amount_basis: str = ''
                vpa_candidates: List[str] = []
                payer_vpa: Optional[str] = None
                payee_vpa: Optional[str] = None
                ts: Optional[str] = None
                txid: Optional[str] = None
                status: Optional[str] = None
                tx_type: str = 'TRANSFER'

                for col in df.columns:
                    val = r.get(col)
                    if val is None or pd.isna(val):
                        continue
                    col_low = str(col).lower()
                    s = str(val)
                    if '@' in s:
                        for m in re.finditer(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', s):
                            v_cand = m.group(0)
                            if not v_cand.lower().endswith(('.png', '.jpg', '.com')):
                                vpa_candidates.append(v_cand)
                    if amount is None and col_low in ('amount', 'zamount', 'txnamount', 'amount_in_paise', 'amountinpaise'):
                        try:
                            amount = float(val) / 100.0
                            amount_basis = ('paise, as the column name says' if 'paise' in col_low else
                                            f"ASSUMED paise (column '{col}' states no unit); not checked against a real sample")
                        except (TypeError, ValueError):
                            pass
                    if '__decoded' in col_low and ('amount' in s.lower() or 'vpa' in s.lower()):
                        try:
                            obj = json.loads(s)
                            for k, v in obj.items():
                                k_low = k.lower()
                                if amount is None and 'amount' in k_low:
                                    try:
                                        # PhonePe JSON stores amountInPaise or minor units; divide by 100
                                        amount = float(v) / 100.0
                                        amount_basis = ('paise, as the key name says' if 'paise' in k_low else
                                                        f"ASSUMED paise (key '{k}' states no unit); not checked against a real sample")
                                    except (TypeError, ValueError):
                                        pass
                                if 'payer' in k_low or 'sender' in k_low:
                                    if isinstance(v, str) and '@' in v:
                                        payer_vpa = v
                                elif 'payee' in k_low or 'receiver' in k_low or 'recipient' in k_low:
                                    if isinstance(v, str) and '@' in v:
                                        payee_vpa = v
                                if 'type' in k_low or 'direction' in k_low:
                                    if 'debit' in str(v).lower() or 'sent' in str(v).lower():
                                        tx_type = 'DEBIT'
                                    elif 'credit' in str(v).lower() or 'received' in str(v).lower():
                                        tx_type = 'CREDIT'
                        except Exception:
                            pass
                    if ts is None and any(k in str(col).lower() for k in ['time', 'date', 'ts', 'created']):
                        ts = normalize_timestamp_value(val, 'auto')
                    if txid is None and any(k in str(col).lower() for k in ['txid', 'txn', 'ref', 'utr', 'id']):
                        if is_valid_txid(s) and len(s) >= 10:
                            txid = s[:64]
                    if status is None and ('status' in str(col).lower() or 'state' in str(col).lower()):
                        if s.upper() in ('SUCCESS', 'COMPLETED', 'FAILED', 'PENDING'):
                            status = s.upper()

                if amount is None or amount <= 0 or amount > 5_000_000:
                    continue

                resolved_cpty, resolved_dir = resolve_payer_payee_counterparty(
                    payer_vpa, payee_vpa, owner_identifiers=owner_identifiers, explicit_direction=tx_type
                )
                if resolved_dir:
                    tx_type = resolved_dir

                if not resolved_cpty and vpa_candidates:
                    non_owner_vpas = [v for v in vpa_candidates if not matches_owner_identity(v, owner_identifiers)]
                    resolved_cpty = non_owner_vpas[0] if non_owner_vpas else vpa_candidates[0]

                if not is_valid_counterparty(resolved_cpty) and not is_valid_txid(txid):
                    continue

                rows.append({
                    'Date': ts,
                    'Transaction_ID': txid or 'N/A',
                    'Amount': amount,
                    'Counterparty': resolved_cpty or 'Unknown',
                    'Status': status or 'UNKNOWN',
                    'Type': tx_type,
                    'Amount_Basis': amount_basis,
                })
            except Exception:
                continue
    if rows:
        df_out = pd.DataFrame(rows)[out_cols]
        return df_out.dropna(subset=['Amount'], how='all')
    return pd.DataFrame(columns=out_cols)


def _parse_phonepe_auth(db_path: str) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=5000).items():
        for _, r in df.iterrows():
            name = None
            vpa = None
            phone = None
            for col in df.columns:
                s = str(r.get(col, ''))
                if not name and len(s) > 2 and s.replace(' ', '').isalpha():
                    name = s
                if not vpa and '@' in s:
                    m = re.search(r'[\w.\-]+@[\w.\-]+', s)
                    if m:
                        vpa = m.group(0)
                if not phone:
                    m = re.search(r'[6-9]\d{9}', s)
                    if m:
                        phone = m.group(0)
            if name or vpa or phone:
                rows.append({
                    'Contact_Name': name or '',
                    'Identifier': vpa or phone or '',
                })
    if rows:
        return pd.DataFrame(rows).drop_duplicates()
    return pd.DataFrame(columns=['Contact_Name', 'Identifier'])


def _parse_phonepe_chronicle(db_path: str) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=10000).items():
        for _, r in df.iterrows():
            title = None
            body = None
            ts = None
            for col in df.columns:
                s = str(r.get(col, ''))
                if 'time' in str(col).lower() or 'date' in str(col).lower():
                    ts = normalize_timestamp_value(r.get(col), 'auto')
                if not title and 2 < len(s) < 200:
                    title = s
                if not body and len(s) > 2:
                    body = s[:1000]
            if title or body:
                rows.append({
                    'Timestamp': ts or '',
                    'Title': title or '',
                    'Body': body or '',
                })
    if rows:
        return pd.DataFrame(rows)
    return pd.DataFrame()


def _parse_whatsapp_payments(db_path: str) -> pd.DataFrame:
    out_cols = ['Date', 'Transaction_ID', 'Amount', 'Counterparty', 'Status', 'Type']
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=10000).items():
        for _, r in df.iterrows():
            amount = None
            for col in df.columns:
                if 'amount' in str(col).lower() or 'value' in str(col).lower():
                    try:
                        val = float(str(r.get(col, '')).replace(',', ''))
                        amount = val / 1000.0 if '1000' in str(col).lower() else val
                        break
                    except (TypeError, ValueError):
                        continue
            if amount is None or amount <= 0:
                continue
            cparty = str(r.get('remote_jid', r.get('sender_jid', 'Unknown')))
            txid = str(r.get('id', r.get('_id', 'N/A')))
            if not is_valid_counterparty(cparty) and not is_valid_txid(txid):
                continue
            rows.append({
                'Date': normalize_timestamp_value(r.get('timestamp', r.get('init_timestamp')), 'auto'),
                'Transaction_ID': txid,
                'Amount': amount,
                'Counterparty': cparty,
                'Status': str(r.get('status') or 'UNKNOWN'),
                'Type': 'TRANSFER',
            })
    if rows:
        return pd.DataFrame(rows)[out_cols]
    return pd.DataFrame(columns=out_cols)


def _parse_whatsapp_calls(db_path: str) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=10000).items():
        for _, r in df.iterrows():
            rows.append({
                'Timestamp': normalize_timestamp_value(r.get('timestamp', r.get('start_time')), 'auto') or '',
                'Title': "WhatsApp Call",
                'Body': f"JID: {r.get('jid', 'Unknown')} | Duration: {r.get('duration', '?')}s",
            })
    if rows:
        return pd.DataFrame(rows)
    return pd.DataFrame()


def _parse_jiofinance_http(db_path: str) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, df in dump_sqlite_tables(db_path, max_rows_per_table=20000).items():
        url_col = next((c for c in df.columns if 'url' in str(c).lower()), None)
        if url_col is None:
            continue
        for _, r in df.iterrows():
            u = str(r.get(url_col, ''))
            if not u:
                continue
            rows.append({
                'Timestamp': '',
                'Title': 'JioFinance HTTP Cache',
                'Body': u[:1000],
            })
    if rows:
        return pd.DataFrame(rows)
    return pd.DataFrame()


def deep_parse(
    db_path: str,
    app_label: str = '',
    owner_identifiers: Optional[Any] = None,
    **kwargs,
) -> Dict[str, Any]:
    # ── Wallet dispatch (15 custodial + hybrid wallets) ────────────────
    try:
        from parsers.custodial_wallet_parser import (
            is_custodial_wallet_app,
            dispatch_custodial_wallet,
            get_wallet_signature,
        )
        from parsers.wallet_deleted_recovery import recover_deleted_wallet_records
        from parsers.wallet_provenance import WalletProvenance

        if is_custodial_wallet_app(app_label):
            live = dispatch_custodial_wallet(db_path, app_label, owner_identifiers)
            deleted = recover_deleted_wallet_records(db_path, app_label)

            combined = (
                pd.concat([live, deleted], ignore_index=True)
                if not deleted.empty
                else live
            )

            # Attach court-defensible provenance
            if isinstance(owner_identifiers, dict):
                case_id = owner_identifiers.get("case_id", "UNSPECIFIED")
            elif isinstance(owner_identifiers, (set, list, tuple)):
                case_id = "UNSPECIFIED"
            else:
                case_id = "UNSPECIFIED"
            case_id = kwargs.get('case_id') or case_id

            prov = WalletProvenance(case_id=case_id)
            combined = prov.annotate(combined, db_path)

            if not combined.empty:
                return {
                    "custodial_wallet_records": combined,
                    "wallet_signature": get_wallet_signature(app_label),
                }
    except Exception as e:
        try:
            from fs_handler import _log_forensic_error
            _log_forensic_error(f"wallet.dispatch.{app_label}", e)
        except Exception:
            pass
    # ── End wallet dispatch ───────────────────────────────────────

    result: Dict[str, pd.DataFrame] = {}
    tag = route_sqlite_file(os.path.basename(db_path), app_label)

    try:
        if tag == 'phonepe_chats':
            result['chats'] = _parse_phonepe_chats(db_path)
        elif tag == 'phonepe_txn':
            result['transactions'] = _parse_phonepe_transactions(db_path, owner_identifiers=owner_identifiers)
        elif tag == 'phonepe_auth':
            result['contacts'] = _parse_phonepe_auth(db_path)
        elif tag == 'phonepe_activity':
            result['notifications'] = _parse_phonepe_chronicle(db_path)
        elif tag == 'whatsapp_pay':
            result['transactions'] = _parse_whatsapp_payments(db_path)
        elif tag == 'whatsapp_calls':
            result['notifications'] = _parse_whatsapp_calls(db_path)
        elif tag == 'jiofinance_http':
            result['notifications'] = _parse_jiofinance_http(db_path)
    except Exception as exc:  # a failed app-specific parse must not look like an empty database
        logger.warning('app-specific parse failed for %s (%s): %s', db_path, tag, exc)

    dumps = dump_sqlite_tables(db_path)
    extracted_frames: List[pd.DataFrame] = []
    for table_name, df in dumps.items():
        if _looks_like_kv_table(df):
            kv = extract_kv_pairs(df)
            if not kv.empty:
                kv.insert(0, 'Source_Table', table_name)
                extracted_frames.append(kv)
        result[f'raw__{table_name}'] = df
    if extracted_frames:
        result['extracted'] = pd.concat(extracted_frames, ignore_index=True)

    return result