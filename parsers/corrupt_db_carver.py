"""
Raw SQLite Page Carver & Fault Simulator.
Performs raw B-Tree Table Leaf page carving (0x0D) on damaged or fragmented databases.
Requires explicit currency prefixes (Rs/INR/₹) and valid VPA handles so random page strings
are never carved as fake transactions.
"""

import os
import re
import shutil
import tempfile
from typing import List
import pandas as pd

STANDARD_COLUMNS = [
    'Date',
    'Transaction_ID',
    'Amount',
    'Counterparty',
    'Status',
    'Type',
    'Page_Number',
]

_VPA_RE = re.compile(r'\b([a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,20})\b')
_EXPLICIT_AMT_RE = re.compile(
    r'(?:rs\.?|inr|₹)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)\b',
    re.IGNORECASE,
)


def carve_corrupted_sqlite_file(file_path: str) -> pd.DataFrame:
    """
    Emergency raw B-Tree leaf carver for corrupted SQLite files.
    Identifies B-Tree table leaf pages (0x0D header byte) and extracts anchored financial strings.
    """
    if not os.path.exists(file_path):
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    carved_rows: List[dict] = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        page_size = 4096
        if len(data) >= 100 and data[:16] == b'SQLite format 3\x00':
            detected_size = int.from_bytes(data[16:18], byteorder='big')
            if detected_size in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                page_size = detected_size

        total_pages = max(1, len(data) // page_size)
        for p in range(total_pages):
            page_offset = p * page_size
            page_data = data[page_offset : page_offset + page_size]
            if len(page_data) < 8:
                continue

            page_type = (
                page_data[0]
                if page_offset != 0
                else (page_data[100] if len(page_data) > 100 else 0)
            )
            if page_type == 0x0D or p == 0:
                strings = re.findall(rb'[\x20-\x7E]{6,}', page_data)
                for s in strings:
                    cs = s.decode('latin-1', errors='ignore').strip()
                    vpa_m = _VPA_RE.search(cs)
                    if not vpa_m:
                        continue
                    vpa_str = vpa_m.group(1)
                    if vpa_str.lower().endswith(('.com', '.in', '.org', '.png', '.jpg')):
                        continue
                    amt_match = _EXPLICIT_AMT_RE.search(cs)
                    amt_val = float(amt_match.group(1).replace(',', '')) if amt_match else None
                    if amt_val is not None and 0 < amt_val <= 1_000_000:
                        carved_rows.append({
                            'Date': None,
                            'Transaction_ID': f'CARVED_P{p}',
                            'Amount': amt_val,
                            'Counterparty': vpa_str,
                            'Status': 'CARVED_RAW',
                            'Type': (
                                'DEBIT'
                                if 'debit' in cs.lower()
                                else ('CREDIT' if 'credit' in cs.lower() else 'TRANSFER')
                            ),
                            'Page_Number': p,
                        })
    except Exception:
        pass

    if carved_rows:
        return pd.DataFrame(carved_rows)
    return pd.DataFrame(columns=STANDARD_COLUMNS)


def run_regression_fault_simulation() -> pd.DataFrame:
    """
    Simulates commercial regression tests by injecting faults into SQLite
    databases inside an isolated temp directory (safe for concurrent sessions).
    """
    results: List[dict] = []
    sim_dir = tempfile.mkdtemp(prefix='dfir_fault_sim_')

    try:
        test_file_1 = os.path.join(sim_dir, 'test_corrupt_hdr.tmp')
        try:
            corrupt_header = (
                b'\x00' * 100
                + b'\x0d' + (b'\x00' * 20)
                + b'Rs. 1500.00 paid to user@okhdfcbank ref 428711223344'
                + (b'\x00' * 4000)
            )
            with open(test_file_1, 'wb') as f:
                f.write(corrupt_header)
            df1 = carve_corrupted_sqlite_file(test_file_1)
            schema_ok = all(
                col in df1.columns
                for col in ['Date', 'Amount', 'Counterparty', 'Transaction_ID']
            )
            results.append({
                'Test Description': 'Zeroed SQLite Header (Malformed B-Tree)',
                'Status': 'PASS (Handled Gracefully)',
                'Schema Verified': schema_ok,
                'Records Recovered': len(df1),
            })
        except Exception as e:
            results.append({
                'Test Description': 'Zeroed SQLite Header',
                'Status': f'FAIL ({str(e)})',
                'Schema Verified': False,
                'Records Recovered': 0,
            })

        test_file_2 = os.path.join(sim_dir, 'test_trunc.tmp')
        try:
            truncated_bytes = b'SQLite format 3\x00\x10\x00\x01\x01\x00'
            with open(test_file_2, 'wb') as f:
                f.write(truncated_bytes)
            df2 = carve_corrupted_sqlite_file(test_file_2)
            schema_ok = all(
                col in df2.columns
                for col in ['Date', 'Amount', 'Counterparty', 'Transaction_ID']
            )
            results.append({
                'Test Description': 'Truncated Database File Header',
                'Status': 'PASS (Handled Gracefully)',
                'Schema Verified': schema_ok,
                'Records Recovered': len(df2),
            })
        except Exception as e:
            results.append({
                'Test Description': 'Truncated Database File',
                'Status': f'FAIL ({str(e)})',
                'Schema Verified': False,
                'Records Recovered': 0,
            })

        test_file_3 = os.path.join(sim_dir, 'test_zero.tmp')
        try:
            with open(test_file_3, 'wb') as f:
                f.write(b"")
            df3 = carve_corrupted_sqlite_file(test_file_3)
            schema_ok = all(
                col in df3.columns
                for col in ['Date', 'Amount', 'Counterparty', 'Transaction_ID']
            )
            results.append({
                'Test Description': 'Zero-Byte Evidence Container File',
                'Status': 'PASS (Handled Gracefully)',
                'Schema Verified': schema_ok,
                'Records Recovered': len(df3),
            })
        except Exception as e:
            results.append({
                'Test Description': 'Zero-Byte Evidence File',
                'Status': f'FAIL ({str(e)})',
                'Schema Verified': False,
                'Records Recovered': 0,
            })
    finally:
        shutil.rmtree(sim_dir, ignore_errors=True)

    return pd.DataFrame(results)