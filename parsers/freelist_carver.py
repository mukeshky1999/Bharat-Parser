"""
Phase 2: Structured SQLite B-Tree Cell Parser & Freelist Carving Engine.
Requires both a valid VPA and a valid Transaction ID or Timestamp when carving raw B-Tree cells,
preventing random table integers from becoming phantom deleted transactions.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

STANDARD_TX_COLUMNS = [
    'Date',
    'Transaction_ID',
    'Amount',
    'Counterparty',
    'Status',
    'Type',
]

_UPI_SUFFIXES_RAW = {
    'ybl', 'ibl', 'axl', 'okaxis', 'okhdfcbank', 'okicici', 'oksbi',
    'paytm', 'pty', 'ptys', 'ptybl', 'ptsbi', 'ptaxis', 'ptyes',
    'apl', 'yapl', 'rapl', 'upi', 'icici', 'hdfcbank', 'axisbank',
    'sbi', 'sbipay', 'kotak', 'kkbk', 'kbl', 'cnrb', 'pnb', 'barb',
    'indus', 'idfcbank', 'federal', 'rbl', 'yesbank', 'yespay',
    'airtel', 'mairtel', 'jio', 'jiopay', 'freecharge', 'fino',
    'superyes', 'naviaxis', 'jupiteraxis', 'fbl', 'sliceaxis', 'ikwik', 'fam',
}
KNOWN_UPI_SUFFIXES = tuple(sorted(_UPI_SUFFIXES_RAW, key=len, reverse=True))

VPA_VALID_RE = re.compile(
    r'\b[a-zA-Z0-9.\-_]{3,64}@(' + '|'.join(KNOWN_UPI_SUFFIXES) + r')\b',
    re.IGNORECASE,
)
# Mandatory currency symbol (Rs / INR / ₹) so random numbers are never matched
AMOUNT_VALID_RE = re.compile(
    r'(?:rs\.?\s*|inr\s*|₹\s*)([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)\b',
    re.IGNORECASE,
)


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes a variable-length integer (varint) according to the SQLite specification."""
    res = 0
    for _ in range(8):
        if offset >= len(data):
            return res, offset
        b = data[offset]
        offset += 1
        res = (res << 7) | (b & 0x7F)
        if not (b & 0x80):
            return res, offset
    if offset < len(data):
        b = data[offset]
        offset += 1
        res = (res << 8) | b
    return res, offset


def decode_record_payload(payload: bytes) -> List[Any]:
    """Decodes an SQLite Record Format payload into Python values."""
    if len(payload) < 2:
        return []
    try:
        header_len, offset = read_varint(payload, 0)
        if header_len > len(payload) or header_len < 1:
            return []

        serial_types: List[int] = []
        while offset < header_len:
            stype, offset = read_varint(payload, offset)
            serial_types.append(stype)

        body_offset = header_len
        values: List[Any] = []

        for st in serial_types:
            if st == 0:
                values.append(None)
            elif st == 1:
                if body_offset + 1 <= len(payload):
                    val = struct.unpack('>b', payload[body_offset:body_offset + 1])[0]
                    values.append(val)
                    body_offset += 1
            elif st == 2:
                if body_offset + 2 <= len(payload):
                    val = struct.unpack('>h', payload[body_offset:body_offset + 2])[0]
                    values.append(val)
                    body_offset += 2
            elif st == 3:
                if body_offset + 3 <= len(payload):
                    b = payload[body_offset:body_offset + 3]
                    val = int.from_bytes(b, byteorder='big', signed=True)
                    values.append(val)
                    body_offset += 3
            elif st == 4:
                if body_offset + 4 <= len(payload):
                    val = struct.unpack('>i', payload[body_offset:body_offset + 4])[0]
                    values.append(val)
                    body_offset += 4
            elif st == 5:
                if body_offset + 6 <= len(payload):
                    b = payload[body_offset:body_offset + 6]
                    val = int.from_bytes(b, byteorder='big', signed=True)
                    values.append(val)
                    body_offset += 6
            elif st == 6:
                if body_offset + 8 <= len(payload):
                    val = struct.unpack('>q', payload[body_offset:body_offset + 8])[0]
                    values.append(val)
                    body_offset += 8
            elif st == 7:
                if body_offset + 8 <= len(payload):
                    val = struct.unpack('>d', payload[body_offset:body_offset + 8])[0]
                    values.append(val)
                    body_offset += 8
            elif st == 8:
                values.append(0)
            elif st == 9:
                values.append(1)
            elif st >= 12 and (st % 2 == 0):
                blob_len = (st - 12) // 2
                if body_offset + blob_len <= len(payload):
                    values.append(payload[body_offset:body_offset + blob_len])
                    body_offset += blob_len
            elif st >= 13 and (st % 2 != 0):
                text_len = (st - 13) // 2
                if body_offset + text_len <= len(payload):
                    text_bytes = payload[body_offset:body_offset + text_len]
                    values.append(text_bytes.decode('utf-8', errors='replace'))
                    body_offset += text_len
            else:
                values.append(None)

        return values
    except Exception:
        return []


def _record_to_transaction(
    values: List[Any],
    origin_tag: str,
    allow_crypto_addresses: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Analyzes a decoded B-Tree record row to determine if it represents a deleted transaction.
    Requires:
    1. A valid Indian VPA (`user@bank`) OR valid crypto address (if allow_crypto_addresses=True)
    2. A valid Transaction ID OR a valid Timestamp
    3. A plausible Amount
    """
    if not values or len(values) < 3:
        return None

    amount = None
    counterparty = None
    txid = None
    date_val = None
    status = 'DELETED (Cell Carved)'

    for item in values:
        if isinstance(item, float):
            if 1.0 <= item <= 500_000.0 and amount is None:
                amount = round(item, 2)
        elif isinstance(item, int) and not isinstance(item, bool):
            if 1500000000000 <= item <= 2100000000000 and date_val is None:
                try:
                    date_val = pd.to_datetime(item, unit='ms').strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
            elif 1500000000 <= item <= 2100000000 and date_val is None:
                try:
                    date_val = pd.to_datetime(item, unit='s').strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
            elif 100 <= item <= 50_000_000 and amount is None and item % 100 == 0:
                amount = float(item) / 100.0
        elif isinstance(item, str):
            s_clean = item.strip()
            if '@' in s_clean and counterparty is None:
                from parsers.vpa_harvester import clean_and_validate_vpa
                for tok in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', s_clean):
                    cand_v = clean_and_validate_vpa(tok)
                    if cand_v:
                        counterparty = cand_v
                        break
            elif allow_crypto_addresses and counterparty is None:
                from parsers.custodial_wallet_parser import detect_chain_from_address
                if detect_chain_from_address(s_clean):
                    counterparty = s_clean
            if amount is None:
                for m in AMOUNT_VALID_RE.finditer(s_clean):
                    try:
                        cand = float(m.group(1).replace(',', ''))
                        if 1.0 <= cand <= 1_000_000.0:
                            amount = round(cand, 2)
                            break
                    except ValueError:
                        continue
            if (
                re.match(r'^(?:[0-9]{12}|T\d{18,24}|(?:YBL|IBL|AXL|OKH|OKI|OKA|OKS|PTM|UPI)[a-zA-Z0-9]{18,32})$', s_clean)
                and txid is None
            ):
                txid = s_clean
            elif allow_crypto_addresses and txid is None and (
                re.match(r'^(?:0x)?[a-fA-F0-9]{64}$', s_clean) or re.match(r'^[1-9A-HJ-NP-Za-km-z]{86,90}$', s_clean)
            ):
                txid = s_clean
            elif re.match(r'^\d{4}-\d{2}-\d{2}', s_clean) and date_val is None:
                date_val = s_clean[:19]

    # Must have VPA/crypto address + Amount + at least one of (txid or date_val)
    if amount is not None and counterparty is not None and (txid is not None or date_val is not None):
        return {
            'Date': date_val,
            'Transaction_ID': txid or origin_tag,
            'Amount': amount,
            'Counterparty': counterparty,
            'Status': status,
            'Type': 'TRANSFER',
        }
    return None


def parse_page_unallocated_cells(
    page_bytes: bytes,
    page_num: int,
    include_active_cells: bool = True,
    allow_crypto_addresses: bool = False,
) -> List[Dict[str, Any]]:
    transactions: List[Dict[str, Any]] = []
    # Fast C-level memory check: valid carved UPI cells must contain an '@' VPA handle byte (unless allow_crypto_addresses=True)
    if len(page_bytes) < 8 or (not allow_crypto_addresses and b'@' not in page_bytes):
        return transactions

    is_leaf = (page_bytes[0] == 0x0D)
    header_offset = 0 if is_leaf else (100 if len(page_bytes) >= 108 and page_bytes[100] == 0x0D else None)
    active_offsets: set = set()
    slack_start = 8
    slack_end = len(page_bytes) - 16

    if header_offset is not None and len(page_bytes) >= header_offset + 8:
        try:
            num_cells = int.from_bytes(page_bytes[header_offset + 3:header_offset + 5], 'big')
            cell_content_offset = int.from_bytes(page_bytes[header_offset + 5:header_offset + 7], 'big')
            if cell_content_offset == 0:
                cell_content_offset = 65536

            ptr_offset = header_offset + 8
            for _ in range(min(num_cells, 1000)):
                if ptr_offset + 2 > len(page_bytes):
                    break
                cell_offset = int.from_bytes(page_bytes[ptr_offset:ptr_offset + 2], 'big')
                ptr_offset += 2
                active_offsets.add(cell_offset)
                if include_active_cells and cell_offset < len(page_bytes):
                    p_size, v_off = read_varint(page_bytes, cell_offset)
                    rowid, v_off = read_varint(page_bytes, v_off)
                    if v_off + p_size <= len(page_bytes):
                        payload = page_bytes[v_off:v_off + p_size]
                        rec_vals = decode_record_payload(payload)
                        tx = _record_to_transaction(rec_vals, f'PG{page_num}_R{rowid}', allow_crypto_addresses=allow_crypto_addresses)
                        if tx:
                            transactions.append(tx)

            slack_start = ptr_offset
            slack_end = min(cell_content_offset, len(page_bytes) - 16)

            # Traverse SQLite Freeblock chain inside cell content area
            fb_offset = int.from_bytes(page_bytes[header_offset + 1:header_offset + 3], 'big')
            visited_fb = set()
            while fb_offset != 0 and fb_offset + 4 <= len(page_bytes) and fb_offset not in visited_fb:
                visited_fb.add(fb_offset)
                next_fb = int.from_bytes(page_bytes[fb_offset:fb_offset + 2], 'big')
                fb_size = int.from_bytes(page_bytes[fb_offset + 2:fb_offset + 4], 'big')
                if fb_size >= 12 and fb_offset + fb_size <= len(page_bytes):
                    try:
                        p_size, v_off = read_varint(page_bytes, fb_offset + 4)
                        if 8 <= p_size <= fb_size and v_off < len(page_bytes):
                            rowid, v_off2 = read_varint(page_bytes, v_off)
                            if v_off2 + p_size <= len(page_bytes):
                                rec_vals = decode_record_payload(page_bytes[v_off2:v_off2 + p_size])
                                tx = _record_to_transaction(rec_vals, f'FB_P{page_num}_O{fb_offset}', allow_crypto_addresses=allow_crypto_addresses)
                                if tx:
                                    transactions.append(tx)
                    except Exception:
                        pass
                fb_offset = next_fb
        except Exception:
            pass

    s_start = max(8, slack_start)
    s_end = max(8, slack_end)
    if not allow_crypto_addresses and b'@' not in page_bytes:
        return transactions

    for offset in range(s_start, s_end, 4):
        if offset in active_offsets:
            continue
        try:
            p_size, v_off = read_varint(page_bytes, offset)
            if 12 <= p_size <= 2048 and v_off < len(page_bytes):
                rowid, v_off2 = read_varint(page_bytes, v_off)
                if v_off2 + p_size <= len(page_bytes):
                    payload = page_bytes[v_off2:v_off2 + p_size]
                    rec_vals = decode_record_payload(payload)
                    if rec_vals and len(rec_vals) >= 3:
                        tx = _record_to_transaction(rec_vals, f'SLACK_P{page_num}_O{offset}', allow_crypto_addresses=allow_crypto_addresses)
                        if tx:
                            transactions.append(tx)
        except Exception:
            continue

    return transactions


def carve_sqlite_freelists(
    db_path: str,
    origin_tag: str = 'FREELIST',
    allow_crypto_addresses: bool = False,
) -> pd.DataFrame:
    if not os.path.exists(db_path):
        return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

    carved_records: List[Dict[str, Any]] = []
    page_size = 4096
    import mmap
    try:
        file_size = os.path.getsize(db_path)
        if file_size < 100:
            return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

        with open(db_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as raw:
                if raw[:16] != b'SQLite format 3\x00':
                    return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

                page_size = int.from_bytes(raw[16:18], byteorder='big')
                if page_size == 1:
                    page_size = 65536
                elif page_size not in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                    page_size = 4096

                first_freelist_trunk = int.from_bytes(raw[32:36], byteorder='big')
                total_freelist_pages = int.from_bytes(raw[36:40], byteorder='big')

                freelist_page_nums: List[int] = []
                seen_trunks: set = set()
                current_trunk = first_freelist_trunk
                while current_trunk != 0 and len(freelist_page_nums) < min(total_freelist_pages, 100000):
                    if current_trunk in seen_trunks:
                        break  # Break cyclic trunk loop corruption
                    seen_trunks.add(current_trunk)
                    freelist_page_nums.append(current_trunk)
                    trunk_offset = (current_trunk - 1) * page_size
                    if trunk_offset + 8 > len(raw):
                        break
                    next_trunk = int.from_bytes(raw[trunk_offset:trunk_offset + 4], byteorder='big')
                    leaf_count = int.from_bytes(raw[trunk_offset + 4:trunk_offset + 8], byteorder='big')
                    for i in range(min(leaf_count, page_size // 4)):
                        ptr_offset = trunk_offset + 8 + (i * 4)
                        if ptr_offset + 4 <= len(raw):
                            leaf_pg = int.from_bytes(raw[ptr_offset:ptr_offset + 4], byteorder='big')
                            if leaf_pg != 0:
                                freelist_page_nums.append(leaf_pg)
                    current_trunk = next_trunk

                for pg_num in set(freelist_page_nums):
                    pg_offset = (pg_num - 1) * page_size
                    pg_bytes = raw[pg_offset:pg_offset + page_size]
                    if not pg_bytes:
                        continue
                    struct_txs = parse_page_unallocated_cells(pg_bytes, pg_num, include_active_cells=True, allow_crypto_addresses=allow_crypto_addresses)
                    carved_records.extend(struct_txs)

                    strings = re.findall(rb'[\x20-\x7E]{12,}', pg_bytes)
                    for s in strings:
                        cs = s.decode('latin-1', errors='ignore').strip()
                        from parsers.vpa_harvester import clean_and_validate_vpa
                        vpa_clean = None
                        for tok in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', cs):
                            vpa_clean = clean_and_validate_vpa(tok)
                            if vpa_clean:
                                break
                        if vpa_clean:
                            amt_val = None
                            for m in AMOUNT_VALID_RE.finditer(cs):
                                try:
                                    cand = float(m.group(1).replace(',', ''))
                                    if 1.0 <= cand <= 1_000_000.0:
                                        amt_val = cand
                                        break
                                except ValueError:
                                    continue
                            if amt_val is not None:
                                carved_records.append({
                                    'Date': None,
                                    'Transaction_ID': f'RAW_FREELIST_P{pg_num}',
                                    'Amount': amt_val,
                                    'Counterparty': vpa_clean,
                                    'Status': 'DELETED (Raw Freelist Carved)',
                                    'Type': 'DEBIT' if 'debit' in cs.lower() else ('CREDIT' if 'credit' in cs.lower() else 'TRANSFER'),
                                })

                total_pages = len(raw) // page_size
                for p in range(1, total_pages + 1):
                    if p in freelist_page_nums:
                        continue
                    pg_offset = (p - 1) * page_size
                    pg_bytes = raw[pg_offset:pg_offset + page_size]
                    if len(pg_bytes) >= 8 and (pg_bytes[0] == 0x0D or (p == 1 and len(pg_bytes) >= 108 and pg_bytes[100] == 0x0D)):
                        slack_txs = parse_page_unallocated_cells(pg_bytes, p, include_active_cells=False, allow_crypto_addresses=allow_crypto_addresses)
                        carved_records.extend(slack_txs)

    except Exception:
        pass

    wal_path = f"{db_path}-wal"
    if os.path.exists(wal_path):
        from parsers.wal_rollback_analyzer import analyze_wal_revisions
        wal_df = analyze_wal_revisions(wal_path, page_size=page_size, allow_crypto_addresses=allow_crypto_addresses)
        if not wal_df.empty:
            carved_records.extend(wal_df.to_dict('records'))

    if carved_records:
        df = pd.DataFrame(carved_records)
        for col in STANDARD_TX_COLUMNS:
            if col not in df.columns:
                df[col] = None
        return df.drop_duplicates(subset=['Counterparty', 'Transaction_ID', 'Amount'])[STANDARD_TX_COLUMNS]
    return pd.DataFrame(columns=STANDARD_TX_COLUMNS)