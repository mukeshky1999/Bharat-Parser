"""
Phase 3: Multi-Source Evidence Fusion & Bank Reconciliation Engine.
Ingests external Bank Statement CSVs/Excel files and Telecom Call Detail Records (CDRs),
reconciling reference numbers against mobile app databases to detect deleted or spoofed records.
"""

from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, List, Optional, Union
import pandas as pd

from parsers.app_overrides import normalize_timestamp_value
from parsers.freelist_carver import KNOWN_UPI_SUFFIXES

UTR_REGEX = re.compile(r'\b[0-9]{12}\b')
VPA_REGEX = re.compile(
    r'\b[a-zA-Z0-9.\-_]{3,64}@(' + '|'.join(KNOWN_UPI_SUFFIXES) + r')\b',
    re.IGNORECASE,
)
PHONE_REGEX = re.compile(r'(?:\+?91|0)?([6-9]\d{9})\b')


def parse_bank_statement(
    file_source: Union[str, bytes, io.BytesIO], filename: str = ''
) -> pd.DataFrame:
    """
    Parses and standardizes external bank statements (CSV or Excel) from major Indian banks.
    Extracts Date, Narration, Ref_UTR, Debit, Credit, Balance, and Extracted_VPA.
    """
    standard_cols = [
        'Date', 'Narration', 'Ref_UTR', 'Debit', 'Credit', 'Balance', 'Extracted_VPA'
    ]
    df: Optional[pd.DataFrame] = None
    try:
        if isinstance(file_source, (bytes, io.BytesIO)):
            buffer = io.BytesIO(file_source) if isinstance(file_source, bytes) else file_source
            if filename.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(buffer)
            else:
                try:
                    df = pd.read_csv(buffer, encoding='utf-8', errors='replace')
                except Exception:
                    buffer.seek(0)
                    df = pd.read_csv(buffer)
        elif os.path.exists(str(file_source)):
            p = str(file_source).lower()
            if p.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_source)
            else:
                try:
                    df = pd.read_csv(file_source, encoding='utf-8', errors='replace')
                except Exception:
                    df = pd.read_csv(file_source)
    except Exception:
        return pd.DataFrame(columns=standard_cols)

    if df is None or df.empty:
        return pd.DataFrame(columns=standard_cols)

    col_tokens = {
        c: [tok for tok in re.split(r'[^a-z0-9]+', str(c).lower()) if tok]
        for c in df.columns
    }
    def _find_col(exact_or_tokens: set, substrings: tuple = ()) -> Optional[str]:
        for orig_c, toks in col_tokens.items():
            if any(t in exact_or_tokens for t in toks):
                return orig_c
        for orig_c in df.columns:
            low = re.sub(r'[^a-z0-9]', '', str(orig_c).lower())
            if any(s in low for s in substrings):
                return orig_c
        return None

    date_col   = _find_col({'date', 'txndate', 'valuedate', 'trandate'}, ('txndate', 'valuedate'))
    narr_col   = _find_col({'narration', 'description', 'particulars', 'remarks', 'details'})
    ref_col    = _find_col({'chq', 'ref', 'utr', 'chequeno', 'refno', 'rrn'}, ('utr', 'refno', 'chqno'))
    debit_col  = _find_col({'debit', 'withdrawal', 'dr', 'dramt', 'debitamt'}, ('withdrawal', 'debit'))
    credit_col = _find_col({'credit', 'deposit', 'cr', 'cramt', 'creditamt'}, ('deposit', 'credit'))
    bal_col    = _find_col({'balance', 'bal', 'closingbalance'}, ('balance',))

    records: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        narr = str(row[narr_col]).strip() if narr_col and pd.notna(row[narr_col]) else ''
        if not narr and not date_col:
            continue

        d_val = re.sub(r'[^\d.]', '', str(row[debit_col])) if debit_col and pd.notna(row[debit_col]) else None
        c_val = re.sub(r'[^\d.]', '', str(row[credit_col])) if credit_col and pd.notna(row[credit_col]) else None
        b_val = re.sub(r'[^\d.]', '', str(row[bal_col])) if bal_col and pd.notna(row[bal_col]) else None

        try:
            debit = float(d_val) if d_val and d_val != '.' else 0.0
        except (ValueError, TypeError):
            debit = 0.0
        try:
            credit = float(c_val) if c_val and c_val != '.' else 0.0
        except (ValueError, TypeError):
            credit = 0.0
        try:
            balance = float(b_val) if b_val and b_val != '.' else None
        except (ValueError, TypeError):
            balance = None

        if debit == 0.0 and credit == 0.0:
            continue

        raw_ref = str(row[ref_col]).strip() if ref_col and pd.notna(row[ref_col]) else ''
        utr_match = UTR_REGEX.search(raw_ref) or UTR_REGEX.search(narr)
        ref_utr = utr_match.group(0) if utr_match else (raw_ref if raw_ref else 'N/A')

        vpa_match = VPA_REGEX.search(narr)
        extracted_vpa = vpa_match.group(0) if vpa_match else None

        date_str = normalize_timestamp_value(row[date_col], epoch='auto') if date_col and pd.notna(row[date_col]) else None

        records.append({
            'Date': date_str,
            'Narration': narr,
            'Ref_UTR': ref_utr,
            'Debit': debit,
            'Credit': credit,
            'Balance': balance,
            'Extracted_VPA': extracted_vpa,
        })

    if records:
        return pd.DataFrame(records)
    return pd.DataFrame(columns=standard_cols)


def reconcile_bank_statement_with_device(
    bank_df: pd.DataFrame,
    master_timeline: pd.DataFrame,
) -> pd.DataFrame:
    """
    Cross-verifies an official Bank Statement against extracted phone transactions.
    Identifies:
    - Verified matches (present on both phone & bank statement)
    - Missing from Phone (present on bank statement, wiped from phone or made via another device)
    """
    out_cols = [
        'Reconciliation_Status',
        'Date',
        'Bank_Ref_ID',
        'Amount_INR',
        'Direction',
        'Counterparty_or_Narration',
        'Matched_Phone_App',
    ]
    if bank_df is None or bank_df.empty:
        return pd.DataFrame(columns=out_cols)

    phone_refs = set()
    phone_amts_by_app: List[Dict[str, Any]] = []
    if master_timeline is not None and not master_timeline.empty:
        for _, r in master_timeline.iterrows():
            tid = str(r.get('Transaction_ID', '')).strip()
            if tid and tid not in ('N/A', 'None', 'nan'):
                phone_refs.add(tid)
            try:
                raw_amt = pd.to_numeric(r.get('Amount'), errors='coerce')
                amt_f = float(raw_amt) if pd.notna(raw_amt) else 0.0
            except Exception:
                amt_f = 0.0
            phone_amts_by_app.append({
                'amt': amt_f,
                'app': str(r.get('Application', 'Phone App')),
                'txid': tid,
                'type': str(r.get('Type', '')).upper(),
            })

    rows: List[Dict[str, Any]] = []
    for _, brow in bank_df.iterrows():
        ref = str(brow.get('Ref_UTR', 'N/A')).strip()
        try:
            raw_deb = pd.to_numeric(brow.get('Debit', 0.0), errors='coerce')
            debit = float(raw_deb) if pd.notna(raw_deb) else 0.0
        except Exception:
            debit = 0.0
        try:
            raw_crd = pd.to_numeric(brow.get('Credit', 0.0), errors='coerce')
            credit = float(raw_crd) if pd.notna(raw_crd) else 0.0
        except Exception:
            credit = 0.0
        amt = debit if debit > 0 else credit
        direction = '💸 Debit' if debit > 0 else '💰 Credit'
        cparty = brow.get('Extracted_VPA') or str(brow.get('Narration', ''))[:60]

        matched_app = None
        if ref != 'N/A' and ref in phone_refs:
            for item in phone_amts_by_app:
                if item['txid'] == ref:
                    matched_app = item['app']
                    break
        else:
            expected_type = 'DEBIT' if debit > 0 else 'CREDIT'
            for item in phone_amts_by_app:
                if abs(item['amt'] - amt) < 0.05:
                    item_type = item.get('type', '')
                    if not item_type or item_type == expected_type or item_type == 'TRANSFER':
                        matched_app = item['app']
                        break

        if matched_app:
            status = '✅ Verified on Both Phone & Bank Statement'
        else:
            status = '⚠️ In Bank Statement ONLY (Wiped from Phone / Other Device)'

        rows.append({
            'Reconciliation_Status': status,
            'Date': str(brow.get('Date', '')),
            'Bank_Ref_ID': ref,
            'Amount_INR': amt,
            'Direction': direction,
            'Counterparty_or_Narration': cparty,
            'Matched_Phone_App': matched_app or 'Not Found on Phone',
        })

    return pd.DataFrame(rows)[out_cols]


def parse_cdr_record(
    file_source: Union[str, bytes, io.BytesIO], filename: str = ''
) -> pd.DataFrame:
    """
    Parses and standardizes Call Detail Records (CDRs) and IPDR logs.
    Normalizes Calling Number (A-Party), Called Number (B-Party), Call Time, Type, and Duration.
    """
    standard_cols = [
        'Call_Time', 'Caller_A', 'Receiver_B', 'Call_Type', 'Duration_Sec'
    ]
    df: Optional[pd.DataFrame] = None
    try:
        if isinstance(file_source, (bytes, io.BytesIO)):
            buffer = io.BytesIO(file_source) if isinstance(file_source, bytes) else file_source
            if filename.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(buffer)
            else:
                try:
                    df = pd.read_csv(buffer, encoding='utf-8', errors='replace')
                except Exception:
                    buffer.seek(0)
                    df = pd.read_csv(buffer)
        elif os.path.exists(str(file_source)):
            p = str(file_source).lower()
            if p.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_source)
            else:
                try:
                    df = pd.read_csv(file_source, encoding='utf-8', errors='replace')
                except Exception:
                    df = pd.read_csv(file_source)
    except Exception:
        return pd.DataFrame(columns=standard_cols)

    if df is None or df.empty:
        return pd.DataFrame(columns=standard_cols)

    col_tokens = {
        c: [tok for tok in re.split(r'[^a-z0-9]+', str(c).lower()) if tok]
        for c in df.columns
    }
    def _find_cdr_col(exact_or_tokens: set, substrings: tuple = ()) -> Optional[str]:
        for orig_c, toks in col_tokens.items():
            if any(t in exact_or_tokens for t in toks):
                return orig_c
        for orig_c in df.columns:
            low = re.sub(r'[^a-z0-9]', '', str(orig_c).lower())
            if any(s in low for s in substrings):
                return orig_c
        return None

    time_col     = _find_cdr_col({'time', 'date', 'datetime', 'calltime', 'start', 'timestamp'}, ('datetime', 'calltime'))
    caller_col   = _find_cdr_col({'calling', 'caller', 'anumber', 'source', 'from', 'callera'}, ('calling', 'anumber'))
    receiver_col = _find_cdr_col({'called', 'receiver', 'bnumber', 'destination', 'to', 'receiverb'}, ('called', 'bnumber'))
    type_col     = _find_cdr_col({'type', 'calltype', 'servicetype', 'direction'}, ('calltype', 'servicetype'))
    dur_col      = _find_cdr_col({'duration', 'dur', 'sec', 'seconds', 'durationsec'}, ('duration',))

    records: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        raw_a = str(row[caller_col]) if caller_col and pd.notna(row[caller_col]) else ''
        raw_b = str(row[receiver_col]) if receiver_col and pd.notna(row[receiver_col]) else ''

        match_a = PHONE_REGEX.search(raw_a)
        match_b = PHONE_REGEX.search(raw_b)

        caller_a = match_a.group(1) if match_a else raw_a[-10:]
        receiver_b = match_b.group(1) if match_b else raw_b[-10:]

        if not caller_a or not receiver_b:
            continue

        call_time = normalize_timestamp_value(row[time_col], epoch='auto') if time_col and pd.notna(row[time_col]) else None
        call_type = str(row[type_col]).strip().upper() if type_col and pd.notna(row[type_col]) else 'VOICE'
        dur_val = re.sub(r'[^\d]', '', str(row[dur_col])) if dur_col and pd.notna(row[dur_col]) else '0'
        duration_sec = int(dur_val) if dur_val else 0

        records.append({
            'Call_Time': call_time,
            'Caller_A': caller_a,
            'Receiver_B': receiver_b,
            'Call_Type': call_type,
            'Duration_Sec': duration_sec,
        })

    if records:
        return pd.DataFrame(records)
    return pd.DataFrame(columns=standard_cols)


def correlate_cdr_with_transactions(
    cdr_df: pd.DataFrame,
    master_timeline: pd.DataFrame,
    window_minutes: int = 15,
) -> pd.DataFrame:
    """
    Temporal Telecom Correlation Engine:
    Identifies phone calls or SMS deliveries occurring within +/- window_minutes
    of a financial transaction.
    """
    output_cols = [
        'Correlation_Type',
        'Transaction_Time',
        'Transaction_Amount',
        'Transaction_Counterparty',
        'Call_Time',
        'Phone_Party_A',
        'Phone_Party_B',
        'Call_Type',
        'Time_Delta_Minutes',
        'Investigative_Insight',
    ]

    if cdr_df.empty or master_timeline.empty:
        return pd.DataFrame(columns=output_cols)

    tx_valid = master_timeline.dropna(subset=['Date', 'Amount']).copy()
    tx_valid['Parsed_Tx_Time'] = pd.to_datetime(tx_valid['Date'], errors='coerce')
    tx_valid = tx_valid.dropna(subset=['Parsed_Tx_Time'])

    cdr_valid = cdr_df.dropna(subset=['Call_Time']).copy()
    cdr_valid['Parsed_Call_Time'] = pd.to_datetime(cdr_valid['Call_Time'], errors='coerce')
    cdr_valid = cdr_valid.dropna(subset=['Parsed_Call_Time'])

    correlations: List[Dict[str, Any]] = []
    for _, tx_row in tx_valid.iterrows():
        t_time = tx_row['Parsed_Tx_Time']
        t_amt = tx_row['Amount']
        t_cparty = tx_row['Counterparty']

        window_start = t_time - pd.Timedelta(minutes=window_minutes)
        window_end = t_time + pd.Timedelta(minutes=window_minutes)

        matched_calls = cdr_valid[
            (cdr_valid['Parsed_Call_Time'] >= window_start) &
            (cdr_valid['Parsed_Call_Time'] <= window_end)
        ]

        for _, call_row in matched_calls.iterrows():
            c_time = call_row['Parsed_Call_Time']
            delta_mins = round((c_time - t_time).total_seconds() / 60.0, 1)

            if delta_mins < 0:
                corr_type = 'Pre-Transaction Call / Possible Social Engineering'
                insight = f"Phone call occurred {abs(delta_mins)} mins BEFORE payment of ₹{t_amt:,.2f}."
            else:
                corr_type = 'Post-Transaction Confirmation Call'
                insight = f"Phone call occurred {delta_mins} mins AFTER payment of ₹{t_amt:,.2f}."

            correlations.append({
                'Correlation_Type': corr_type,
                'Transaction_Time': str(tx_row['Date']),
                'Transaction_Amount': t_amt,
                'Transaction_Counterparty': t_cparty,
                'Call_Time': str(call_row['Call_Time']),
                'Phone_Party_A': call_row['Caller_A'],
                'Phone_Party_B': call_row['Receiver_B'],
                'Call_Type': call_row['Call_Type'],
                'Time_Delta_Minutes': abs(delta_mins),
                'Investigative_Insight': insight,
            })

    if correlations:
        return pd.DataFrame(correlations).sort_values(by='Time_Delta_Minutes', ascending=True)
    return pd.DataFrame(columns=output_cols)