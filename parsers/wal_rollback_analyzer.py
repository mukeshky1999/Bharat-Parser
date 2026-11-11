"""
Phase 2: WAL Frame Multi-Revision Rollback Analysis Engine.
Inspects SQLite Write-Ahead Log (WAL) files. Analyzes 32-byte headers and
24-byte frame headers to discover older uncheckpointed page revisions,
recovering historical transaction states that existed prior to modification.
Conforms strictly to the official SQLite WAL format specifications:
- 32-byte WAL header with big-endian page size, salts, and checksums.
- 24-byte frame headers with big-endian pgno, commit size, salts, and rolling checksums.
- Supports both WAL_MAGIC_LE (0x377F0682) and WAL_MAGIC_BE (0x377F0683).
"""

from __future__ import annotations
import os
import struct
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple
import pandas as pd
from parsers.freelist_carver import parse_page_unallocated_cells

STANDARD_TX_COLUMNS = [
    'Date',
    'Transaction_ID',
    'Amount',
    'Counterparty',
    'Status',
    'Type',
]

# SQLite WAL magic numbers:
# 0x377F0682: Checksums calculated by interpreting data as 32-bit little-endian words
# 0x377F0683: Checksums calculated by interpreting data as 32-bit big-endian words
# Note: In both formats, all multi-byte integers in WAL header and frame headers are stored in big-endian format.
WAL_MAGIC_LE = 0x377F0682
WAL_MAGIC_BE = 0x377F0683


def compute_wal_checksum(
    data: bytes,
    endian_code: str,
    s0: int = 0,
    s1: int = 0,
) -> Tuple[int, int]:
    """
    Computes or updates SQLite rolling checksum (cumulative Fibonacci weights).
    SQLite specification:
      for i from 0 to N-1 step 2:
          s0 += x[i] + s1
          s1 += x[i+1] + s0
    where x is an array of unsigned 32-bit integers, accumulated modulo 2^32.
    """
    num_words = len(data) // 4
    words = struct.unpack(f'{endian_code}{num_words}I', data[:num_words * 4])
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


class WalFrame:
    def __init__(
        self,
        frame_idx: int,
        pgno: int,
        commit_count: int,
        salt1: int,
        salt2: int,
        data: bytes,
        checksum1: int = 0,
        checksum2: int = 0,
        is_valid_checksum: bool = True,
        is_valid_salt: bool = True,
    ):
        self.frame_idx = frame_idx
        self.pgno = pgno
        self.commit_count = commit_count
        self.salt1 = salt1
        self.salt2 = salt2
        self.data = data
        self.checksum1 = checksum1
        self.checksum2 = checksum2
        self.is_valid_checksum = is_valid_checksum
        self.is_valid_salt = is_valid_salt


def parse_wal_file(wal_path: str, page_size: int = 4096) -> Tuple[Dict[int, List[WalFrame]], int]:
    """
    Parses an SQLite WAL file into organized frame revisions grouped by page number (pgno).
    Conforms to official SQLite WAL specifications:
    - 32-byte WAL Header: Magic (0x377F0682 or 0x377F0683), big-endian integers for page size, salts, and checksums.
    - 24-byte Frame Headers: big-endian pgno, commit_count, salts, and rolling checksums.
    """
    revisions: Dict[int, List[WalFrame]] = defaultdict(list)
    if not os.path.exists(wal_path) or os.path.getsize(wal_path) < 32:
        return revisions, page_size

    try:
        with open(wal_path, 'rb') as f:
            header = f.read(32)
            if len(header) < 32:
                return revisions, page_size

            # Magic number: 32-bit big-endian unsigned integer
            magic = struct.unpack('>I', header[:4])[0]
            if magic not in (WAL_MAGIC_LE, WAL_MAGIC_BE):
                return revisions, page_size

            # LSB determines checksum byte order (little-endian for 0x377F0682, big-endian for 0x377F0683)
            cksum_endian = '>' if magic == WAL_MAGIC_BE else '<'

            # Header fields are all big-endian unsigned integers
            file_format = struct.unpack('>I', header[4:8])[0]
            detected_page_size = struct.unpack('>I', header[8:12])[0]
            if detected_page_size in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                page_size = detected_page_size

            checkpoint_seq = struct.unpack('>I', header[12:16])[0]
            wal_salt1, wal_salt2 = struct.unpack('>II', header[16:24])
            wal_ck1, wal_ck2 = struct.unpack('>II', header[24:32])

            # Header checksum (over first 24 bytes)
            exp_s0, exp_s1 = compute_wal_checksum(header[:24], cksum_endian, 0, 0)
            header_cksum_valid = (exp_s0 == wal_ck1 and exp_s1 == wal_ck2) or (wal_ck1 == 0 and wal_ck2 == 0)

            # Rolling checksum state begins with header checksum if valid
            prev_s0 = exp_s0 if header_cksum_valid and (wal_ck1 != 0 or wal_ck2 != 0) else 0
            prev_s1 = exp_s1 if header_cksum_valid and (wal_ck1 != 0 or wal_ck2 != 0) else 0

            frame_size = 24 + page_size
            frame_idx = 1

            while True:
                frame_bytes = f.read(frame_size)
                if len(frame_bytes) < frame_size:
                    break

                f_hdr = frame_bytes[:24]
                f_data = frame_bytes[24:]

                # Frame header: 6 big-endian 32-bit unsigned integers
                pgno, commit_count, s1, s2, f_ck1, f_ck2 = struct.unpack('>IIIIII', f_hdr)

                # Salt validation: matches WAL header salts for current write cycle
                is_valid_salt = (s1 == wal_salt1 and s2 == wal_salt2)

                # Rolling checksum validation:
                # 1. First 8 bytes of frame header
                c_s0, c_s1 = compute_wal_checksum(f_hdr[:8], cksum_endian, prev_s0, prev_s1)
                # 2. Entire page data (page_size bytes)
                c_s0, c_s1 = compute_wal_checksum(f_data, cksum_endian, c_s0, c_s1)
                is_valid_checksum = (c_s0 == f_ck1 and c_s1 == f_ck2) or (f_ck1 == 0 and f_ck2 == 0)

                if is_valid_checksum and (f_ck1 != 0 or f_ck2 != 0):
                    prev_s0, prev_s1 = c_s0, c_s1

                wf = WalFrame(
                    frame_idx=frame_idx,
                    pgno=pgno,
                    commit_count=commit_count,
                    salt1=s1,
                    salt2=s2,
                    data=f_data,
                    checksum1=f_ck1,
                    checksum2=f_ck2,
                    is_valid_checksum=is_valid_checksum,
                    is_valid_salt=is_valid_salt,
                )
                revisions[pgno].append(wf)
                frame_idx += 1

    except Exception:
        pass

    return revisions, page_size


def analyze_wal_revisions(
    wal_path: str,
    page_size: int = 4096,
    allow_crypto_addresses: bool = False,
) -> pd.DataFrame:
    """
    Time-travel analysis: examines pages with multiple commit versions and uncheckpointed
    WAL frames. Recovers transactions from older frame revisions that were overwritten
    or deleted by newer commits in the same WAL file, as well as uncheckpointed freelist/slack frames.
    """
    if not os.path.exists(wal_path):
        return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

    revisions, detected_pg_size = parse_wal_file(wal_path, page_size)
    recovered_historical_txs: List[Dict[str, Any]] = []

    # 1. Discover uncheckpointed freelist pages from latest Page 1 frame (or base db file)
    freelist_pages: Set[int] = set()
    latest_p1 = revisions.get(1, [])
    p1_data = None
    if latest_p1:
        p1_data = latest_p1[-1].data
    else:
        db_path = wal_path[:-4] if wal_path.endswith('-wal') else None
        if db_path and os.path.exists(db_path):
            try:
                with open(db_path, 'rb') as f_db:
                    p1_data = f_db.read(100)
            except Exception:
                pass

    if p1_data and len(p1_data) >= 40:
        first_trunk = int.from_bytes(p1_data[32:36], 'big')
        total_freelist = int.from_bytes(p1_data[36:40], 'big')
        curr_trunk = first_trunk
        seen_trunks: Set[int] = set()
        db_path = wal_path[:-4] if wal_path.endswith('-wal') else None
        while curr_trunk != 0 and curr_trunk not in seen_trunks and len(freelist_pages) < min(total_freelist + 50, 10000):
            seen_trunks.add(curr_trunk)
            freelist_pages.add(curr_trunk)
            trunk_data = None
            if curr_trunk in revisions and revisions[curr_trunk]:
                trunk_data = revisions[curr_trunk][-1].data
            elif db_path and os.path.exists(db_path):
                try:
                    with open(db_path, 'rb') as f_db:
                        f_db.seek((curr_trunk - 1) * detected_pg_size)
                        trunk_data = f_db.read(detected_pg_size)
                except Exception:
                    pass
            if not trunk_data or len(trunk_data) < 8:
                break
            next_trunk = int.from_bytes(trunk_data[0:4], 'big')
            leaf_count = int.from_bytes(trunk_data[4:8], 'big')
            for i in range(min(leaf_count, detected_pg_size // 4)):
                ptr_off = 8 + i * 4
                if ptr_off + 4 <= len(trunk_data):
                    l_pg = int.from_bytes(trunk_data[ptr_off:ptr_off + 4], 'big')
                    if l_pg != 0:
                        freelist_pages.add(l_pg)
            curr_trunk = next_trunk

    # 2. Extract active transactions from the latest revision of each non-freelist page
    latest_active_keys: Set[Tuple[Any, ...]] = set()
    for pgno, frames in revisions.items():
        if pgno in freelist_pages or not frames:
            continue
        latest_frame = frames[-1]
        p_bytes = latest_frame.data
        is_leaf = (len(p_bytes) >= 8 and p_bytes[0] == 0x0D)
        hdr_off = 0 if is_leaf else (100 if pgno == 1 and len(p_bytes) >= 108 and p_bytes[100] == 0x0D else None)
        if hdr_off is not None:
            num_cells = int.from_bytes(p_bytes[hdr_off + 3:hdr_off + 5], 'big')
            ptr = hdr_off + 8
            for _ in range(min(num_cells, 1000)):
                if ptr + 2 > len(p_bytes):
                    break
                c_off = int.from_bytes(p_bytes[ptr:ptr + 2], 'big')
                ptr += 2
                if c_off < len(p_bytes):
                    from parsers.freelist_carver import read_varint, decode_record_payload, _record_to_transaction
                    p_sz, v_off = read_varint(p_bytes, c_off)
                    rowid, v_off2 = read_varint(p_bytes, v_off)
                    if v_off2 + p_sz <= len(p_bytes):
                        rec = decode_record_payload(p_bytes[v_off2:v_off2 + p_sz])
                        tx = _record_to_transaction(rec, f'PG{pgno}_R{rowid}', allow_crypto_addresses=allow_crypto_addresses)
                        if tx:
                            latest_active_keys.add((tx.get('Counterparty'), tx.get('Amount')))

    # 3. Recover historical pre-commit frames and uncheckpointed freelist/slack pages
    seen_recovered_keys: Set[Tuple[Any, ...]] = set()

    for pgno, frames in revisions.items():
        if not frames:
            continue
        is_freelist_page = (pgno in freelist_pages)

        # Older frame revisions represent historical pre-commit versions of this page
        if len(frames) > 1:
            for old_frame in frames[:-1]:
                historical_txs = parse_page_unallocated_cells(
                    old_frame.data,
                    pgno,
                    include_active_cells=True,
                    allow_crypto_addresses=allow_crypto_addresses,
                )
                for h_tx in historical_txs:
                    h_key = (h_tx.get('Counterparty'), h_tx.get('Amount'))
                    if h_key not in latest_active_keys and h_key not in seen_recovered_keys:
                        seen_recovered_keys.add(h_key)
                        h_tx_copy = dict(h_tx)
                        h_tx_copy['Status'] = f"MODIFIED / WIPED (Pre-Commit Frame #{old_frame.frame_idx})"
                        h_tx_copy['Transaction_ID'] = f"WAL_REV_P{pgno}_F{old_frame.frame_idx}"
                        recovered_historical_txs.append(h_tx_copy)

        # Latest frame: if it is on the freelist, or contains deleted slack / freeblocks
        latest_frame = frames[-1]
        latest_txs = parse_page_unallocated_cells(
            latest_frame.data,
            pgno,
            include_active_cells=is_freelist_page,
            allow_crypto_addresses=allow_crypto_addresses,
        )
        for s_tx in latest_txs:
            tid = str(s_tx.get('Transaction_ID', ''))
            is_slack_or_fb = ('SLACK' in tid or 'FB' in tid)
            s_key = (s_tx.get('Counterparty'), s_tx.get('Amount'))
            if (is_freelist_page or is_slack_or_fb) and s_key not in latest_active_keys and s_key not in seen_recovered_keys:
                seen_recovered_keys.add(s_key)
                s_tx_copy = dict(s_tx)
                if is_freelist_page:
                    s_tx_copy['Status'] = f"DELETED (WAL Freelist Frame #{latest_frame.frame_idx})"
                else:
                    s_tx_copy['Status'] = f"DELETED (WAL Slack Frame #{latest_frame.frame_idx})"
                recovered_historical_txs.append(s_tx_copy)

    if recovered_historical_txs:
        df = pd.DataFrame(recovered_historical_txs)
        return df.drop_duplicates(subset=['Counterparty', 'Transaction_ID', 'Amount'])

    return pd.DataFrame(columns=STANDARD_TX_COLUMNS)
