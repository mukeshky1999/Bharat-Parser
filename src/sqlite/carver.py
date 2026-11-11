"""
4-Zone B-Tree Residual and Deleted Cell Carver.
Adheres strictly to Specification Section 8 (Pipeline C).
"""

import logging
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from src.core.enums import ResidualConfidence
from src.sqlite.models import RecoveredRecord, TableSchema
from src.sqlite.record import decode_serial_type, decode_record, extract_serial_types
from src.sqlite.varint import decode_varint

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
AMOUNT_VALID_RE = re.compile(
    r'(?:rs\.?\s*|inr\s*|₹\s*)([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)\b',
    re.IGNORECASE,
)
UTR_VALID_RE = re.compile(
    r'^(?:[0-9]{12}|T\d{18,24}|(?:YBL|IBL|AXL|OKH|OKI|OKA|OKS|PTM|UPI)[a-zA-Z0-9]{18,32})$'
)


def is_valid_upi_vpa(text: str) -> bool:
    """Validates if string contains a legitimate Indian UPI Virtual Payment Address (VPA)."""
    return bool(VPA_VALID_RE.search(text)) if text else False


def is_valid_utr(text: str) -> bool:
    """Validates 12-digit Indian UTR or banking transaction reference number."""
    return bool(UTR_VALID_RE.match(text)) if text else False


def extract_indian_currency_amount(text: str) -> Optional[float]:
    """Extracts genuine currency amount formatted with Rs / INR / ₹."""
    if not text:
        return None
    m = AMOUNT_VALID_RE.search(text)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None
    return None


def is_printable_text(text: str) -> bool:
    """Checks if decoded string consists predominantly of printable characters."""
    if not text:
        return True
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return (printable / len(text)) >= 0.85


def serial_type_data_len(serial_type: int) -> int:
    """Returns byte length of data associated with SQLite serial_type."""
    if serial_type in (0, 8, 9, 10, 11):
        return 0
    elif serial_type == 1:
        return 1
    elif serial_type == 2:
        return 2
    elif serial_type == 3:
        return 3
    elif serial_type == 4:
        return 4
    elif serial_type == 5:
        return 6
    elif serial_type in (6, 7):
        return 8
    elif serial_type >= 12 and (serial_type % 2 == 0):
        return (serial_type - 12) // 2
    elif serial_type >= 13 and (serial_type % 2 == 1):
        return (serial_type - 13) // 2
    return 0


class ResidualCarver:
    """Carves deleted records from Freeblocks, Unallocated Gaps, Freelist, and Post-EOF pages."""

    def __init__(self, table_schemas: Dict[str, TableSchema], page_size: int, text_encoding: str = "UTF-8"):
        self.table_schemas = table_schemas
        self.page_size = page_size
        self.text_encoding = text_encoding

    def carve_freeblocks(
        self,
        page_bytes: bytes,
        page_num: int,
        first_freeblock_offset: int,
        owning_table: Optional[str] = None
    ) -> List[RecoveredRecord]:
        """
        Carves deleted records from Zone 1 (In-Page Freeblocks).
        Uses Reverse Serial-Type Alignment to bypass overwritten 4-byte headers.
        """
        recovered: List[RecoveredRecord] = []
        fb_offset = first_freeblock_offset
        visited_offsets = set()

        candidate_tables = (
            [self.table_schemas[owning_table]]
            if owning_table and owning_table in self.table_schemas
            else list(self.table_schemas.values())
        )

        while 0 < fb_offset < len(page_bytes) - 4:
            if fb_offset in visited_offsets:
                break
            visited_offsets.add(fb_offset)

            next_fb_offset = struct.unpack(">H", page_bytes[fb_offset:fb_offset + 2])[0]
            fb_size = struct.unpack(">H", page_bytes[fb_offset + 2:fb_offset + 4])[0]

            if fb_size < 4 or fb_offset + fb_size > len(page_bytes):
                break

            fb_bytes = page_bytes[fb_offset:fb_offset + fb_size]

            # First, check if there is an intact cell inside fb_bytes (Case A: merged freeblocks)
            found_intact = self._carve_intact_cells_in_slice(
                fb_bytes,
                page_num=page_num,
                base_byte_offset=fb_offset,
                zone="IN_PAGE_FREEBLOCK",
                candidate_tables=candidate_tables
            )
            if found_intact:
                recovered.extend(found_intact)
            else:
                # Case B: Clobbered first cell recovery via reverse serial-type alignment
                clobbered_rec = self._carve_clobbered_freeblock(
                    fb_bytes,
                    page_num=page_num,
                    base_byte_offset=fb_offset,
                    candidate_tables=candidate_tables
                )
                if clobbered_rec:
                    recovered.append(clobbered_rec)

            fb_offset = next_fb_offset

        return recovered

    def _carve_clobbered_freeblock(
        self,
        fb_bytes: bytes,
        page_num: int,
        base_byte_offset: int,
        candidate_tables: List[TableSchema]
    ) -> Optional[RecoveredRecord]:
        """
        Attempts reverse serial-type alignment starting at bytes 4..12 of fb_bytes.
        """
        fb_len = len(fb_bytes)
        for tbl in candidate_tables:
            expected_cols = tbl.columns
            num_cols = len(expected_cols)
            if num_cols == 0:
                continue

            # Candidate starting positions past the 4-byte overwritten header
            for s in range(4, min(14, fb_len)):
                # Strategy 1: s is start of record (header_size varint)
                try:
                    hdr_size, serial_types = extract_serial_types(fb_bytes, s)
                    if 0 < hdr_size <= fb_len - s and len(serial_types) in (num_cols, num_cols - 1):
                        rec = self._match_and_build_record(
                            fb_bytes=fb_bytes,
                            types_start=s + (hdr_size - sum(serial_type_data_len(st) for st in serial_types)),
                            data_start=s + hdr_size,
                            serial_types=serial_types,
                            tbl=tbl,
                            page_num=page_num,
                            base_byte_offset=base_byte_offset + s
                        )
                        if rec:
                            return rec
                except Exception as exc:
                    logger.debug("Freeblock speculative strategy 1 parse exception: %s", exc)

                # Strategy 2: s is start of raw serial types list (header_size was clobbered in bytes 0..3)
                # Try all columns or suffix of columns (if first column/IPK was clobbered)
                for col_slice in (expected_cols, expected_cols[1:]):
                    candidate_types = []
                    cursor = s
                    valid_types = True

                    for _ in col_slice:
                        if cursor >= fb_len:
                            valid_types = False
                            break
                        st, st_len = decode_varint(fb_bytes, cursor)
                        if st_len <= 0:
                            valid_types = False
                            break
                        candidate_types.append(st)
                        cursor += st_len

                    if not valid_types or not candidate_types:
                        continue

                    # Sum data lengths
                    total_data_len = sum(serial_type_data_len(st) for st in candidate_types)
                    if cursor + total_data_len > fb_len:
                        continue

                    # Attempt to decode and validate values
                    data_cursor = cursor
                    cols_dict: Dict[str, Any] = {}
                    matched = True

                    for col_def, st in zip(col_slice, candidate_types):
                        val, consumed = decode_serial_type(st, fb_bytes, data_cursor, self.text_encoding)
                        data_cursor += consumed

                        # Validate type consistency
                        if "TEXT" in col_def.affinity or "CHAR" in col_def.data_type.upper():
                            if not isinstance(val, str) or not is_printable_text(val):
                                matched = False
                                break
                        elif "INT" in col_def.affinity:
                            if not (val is None or isinstance(val, int)):
                                matched = False
                                break
                        elif "REAL" in col_def.affinity or "NUM" in col_def.affinity:
                            if not (val is None or isinstance(val, (int, float))):
                                matched = False
                                break

                        cols_dict[col_def.name] = val

                    if matched and len(cols_dict) >= len(col_slice) and any(v is not None for v in cols_dict.values()):
                        classification = (
                            ResidualConfidence.RESIDUAL_RECORD
                            if len(cols_dict) == num_cols
                            else ResidualConfidence.PARTIAL_RECORD
                        )
                        return RecoveredRecord(
                            table_name=tbl.name,
                            sqlite_rowid=None,
                            recovery_classification=classification,
                            source_origin_zone="IN_PAGE_FREEBLOCK",
                            source_page_number=page_num,
                            source_byte_offset=base_byte_offset + s,
                            columns_dict=cols_dict,
                        )

        return None

    def _match_and_build_record(
        self,
        fb_bytes: bytes,
        types_start: int,
        data_start: int,
        serial_types: List[int],
        tbl: TableSchema,
        page_num: int,
        base_byte_offset: int
    ) -> Optional[RecoveredRecord]:
        """Matches extracted serial types against table schema and constructs RecoveredRecord."""
        expected_cols = tbl.columns
        cols_to_use = expected_cols if len(serial_types) == len(expected_cols) else expected_cols[1:]

        data_cursor = data_start
        cols_dict: Dict[str, Any] = {}

        for col_def, st in zip(cols_to_use, serial_types):
            val, consumed = decode_serial_type(st, fb_bytes, data_cursor, self.text_encoding)
            data_cursor += consumed

            if "TEXT" in col_def.affinity and isinstance(val, str):
                if not is_printable_text(val):
                    return None
            cols_dict[col_def.name] = val

        classification = (
            ResidualConfidence.RESIDUAL_RECORD
            if len(cols_dict) == len(expected_cols)
            else ResidualConfidence.PARTIAL_RECORD
        )

        return RecoveredRecord(
            table_name=tbl.name,
            sqlite_rowid=None,
            recovery_classification=classification,
            source_origin_zone="IN_PAGE_FREEBLOCK",
            source_page_number=page_num,
            source_byte_offset=base_byte_offset,
            columns_dict=cols_dict,
        )

    def _carve_intact_cells_in_slice(
        self,
        slice_bytes: bytes,
        page_num: int,
        base_byte_offset: int,
        zone: str,
        candidate_tables: List[TableSchema]
    ) -> List[RecoveredRecord]:
        """
        Slides cursor across slice_bytes and uses the Fast Sanity Filter:
        4 <= P <= max_payload, 0 < row_id < 10^16, 2 <= header_size <= 512, header_size + D == P.
        """
        recovered: List[RecoveredRecord] = []
        slice_len = len(slice_bytes)
        p = 0

        while p < slice_len - 6:
            try:
                # Varint 1: Payload size P
                P, p_len = decode_varint(slice_bytes, p)
                if P < 4 or P > self.page_size or p_len <= 0 or p + p_len >= slice_len:
                    p += 1
                    continue

                # Varint 2: Row ID
                row_id, rowid_len = decode_varint(slice_bytes, p + p_len)
                if row_id <= 0 or row_id > 10**16 or rowid_len <= 0 or p + p_len + rowid_len >= slice_len:
                    p += 1
                    continue

                # Varint 3: Record header size
                payload_start = p + p_len + rowid_len
                hdr_size, hdr_varint_len = decode_varint(slice_bytes, payload_start)
                if hdr_size < 2 or hdr_size > 512 or hdr_size > P or payload_start + hdr_size > slice_len:
                    p += 1
                    continue

                # Decode serial types inside record header
                st_cursor = payload_start + hdr_varint_len
                hdr_end = payload_start + hdr_size
                serial_types = []
                while st_cursor < hdr_end:
                    st, st_len = decode_varint(slice_bytes, st_cursor)
                    if st_len <= 0:
                        break
                    serial_types.append(st)
                    st_cursor += st_len

                # Exact cell match condition: header_size + D == P
                D = sum(serial_type_data_len(st) for st in serial_types)
                if hdr_size + D != P:
                    p += 1
                    continue

                # Successfully found genuine cell! Match against table schemas
                for tbl in candidate_tables:
                    if len(tbl.columns) == len(serial_types) or len(tbl.columns) == len(serial_types) + 1:
                        cols_dict = {}
                        data_cursor = payload_start + hdr_size
                        cols_to_use = tbl.columns if len(tbl.columns) == len(serial_types) else tbl.columns[1:]
                        matched = True

                        for col_def, st in zip(cols_to_use, serial_types):
                            val, consumed = decode_serial_type(st, slice_bytes, data_cursor, self.text_encoding)
                            data_cursor += consumed

                            if "TEXT" in col_def.affinity and isinstance(val, str):
                                if not is_printable_text(val):
                                    matched = False
                                    break
                            cols_dict[col_def.name] = val

                        if matched:
                            if tbl.ipk_column_name and tbl.ipk_column_name not in cols_dict:
                                cols_dict[tbl.ipk_column_name] = row_id

                            recovered.append(
                                RecoveredRecord(
                                    table_name=tbl.name,
                                    sqlite_rowid=row_id,
                                    recovery_classification=ResidualConfidence.RESIDUAL_RECORD,
                                    source_origin_zone=zone,
                                    source_page_number=page_num,
                                    source_byte_offset=base_byte_offset + p,
                                    columns_dict=cols_dict,
                                )
                            )
                            # Advance past this cell
                            p = payload_start + P
                            break
            except Exception as exc:
                logger.debug("Fast sanity filter speculative parse failed: %s", exc)

            p += 1

        return recovered

    def carve_unallocated_gaps(
        self,
        page_bytes: bytes,
        page_num: int,
        gap_start: int,
        gap_end: int,
        owning_table: Optional[str] = None
    ) -> List[RecoveredRecord]:
        """Carves Zone 2 (Unallocated Page Gap)."""
        if gap_start >= gap_end or gap_end > len(page_bytes):
            return []

        gap_bytes = page_bytes[gap_start:gap_end]
        candidate_tables = (
            [self.table_schemas[owning_table]]
            if owning_table and owning_table in self.table_schemas
            else list(self.table_schemas.values())
        )

        return self._carve_intact_cells_in_slice(
            slice_bytes=gap_bytes,
            page_num=page_num,
            base_byte_offset=gap_start,
            zone="UNALLOCATED_GAP",
            candidate_tables=candidate_tables,
        )

    def carve_freelist_page(
        self,
        page_bytes: bytes,
        page_num: int
    ) -> List[RecoveredRecord]:
        """Carves Zone 3 (Freelist Pages)."""
        return self._carve_intact_cells_in_slice(
            slice_bytes=page_bytes,
            page_num=page_num,
            base_byte_offset=0,
            zone="FREELIST_LEAF_PAGE",
            candidate_tables=list(self.table_schemas.values()),
        )

    def carve_post_eof_page(
        self,
        page_bytes: bytes,
        page_num: int
    ) -> List[RecoveredRecord]:
        """Carves Zone 4 (Post-EOF Residual Pages)."""
        return self._carve_intact_cells_in_slice(
            slice_bytes=page_bytes,
            page_num=page_num,
            base_byte_offset=0,
            zone="POST_EOF_PAGE",
            candidate_tables=list(self.table_schemas.values()),
        )
