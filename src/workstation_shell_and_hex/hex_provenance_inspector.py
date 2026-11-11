"""
Synchronized 3-Pane Provenance & Byte-Level Hex Inspector (Sub-Engine 9.1D).
Computes exact physical SQLite/WAL offsets, 4-layer highlight spans, and 12-format Data Interpreter values.
"""

from datetime import datetime, timezone
import struct
from typing import Optional

from src.workstation_shell_and_hex.models import (
    ByteHighlightSpan,
    DataInterpreterResult,
    HexLayerType,
    HexSliceInspectionResult,
    HexSliceWindow,
)


class HexProvenanceInspector:
    """Calculates physical byte offsets across SQLite, WAL, and binary stores with 4-layer highlighting."""

    @staticmethod
    def compute_sqlite_btree_offset(
        page_size: int, page_number: int, cell_offset_in_page: int
    ) -> int:
        """Physical_File_Offset = (Page_No - 1) * Page_Size + Cell_Offset_In_Page."""
        page_no = max(1, page_number)
        return (page_no - 1) * page_size + cell_offset_in_page

    @staticmethod
    def compute_sqlite_wal_offset(
        page_size: int, frame_number: int, cell_offset_in_page: int
    ) -> int:
        """Physical_WAL_Offset = 32 + (Frame_No - 1) * (Page_Size + 24) + 24 + Cell_Offset_In_Page."""
        frame_no = max(1, frame_number)
        return 32 + (frame_no - 1) * (page_size + 24) + 24 + cell_offset_in_page

    def generate_4layer_highlight_spans(
        self,
        frame_start_offset: int,
        cell_physical_offset: int,
        cell_header_length: int,
        column_payload_length: int,
        slack_range: Optional[tuple[int, int]] = None,
    ) -> list[ByteHighlightSpan]:
        """Builds the 4 structural highlight layers for the synchronized hex viewer."""
        spans: list[ByteHighlightSpan] = []

        # Layer 1: Frame or Page Header (24 bytes for WAL frame header)
        spans.append(
            ByteHighlightSpan(
                layer_type=HexLayerType.LAYER_1_PAGE_OR_WAL_HEADER,
                start_offset=frame_start_offset,
                end_offset=frame_start_offset + 24,
                css_color_class="hex-layer-slate-blue",
                label="WAL Frame Header (Page No + Salts)",
            )
        )

        # Layer 2: Record Cell Header (Varints)
        spans.append(
            ByteHighlightSpan(
                layer_type=HexLayerType.LAYER_2_CELL_HEADER,
                start_offset=cell_physical_offset,
                end_offset=cell_physical_offset + cell_header_length,
                css_color_class="hex-layer-amber",
                label="Record Cell Varint Header",
            )
        )

        # Layer 3: Column Payload (Selected field)
        payload_start = cell_physical_offset + cell_header_length
        spans.append(
            ByteHighlightSpan(
                layer_type=HexLayerType.LAYER_3_COLUMN_PAYLOAD,
                start_offset=payload_start,
                end_offset=payload_start + column_payload_length,
                css_color_class="hex-layer-bright-cyan",
                label="Selected Field Column Payload",
            )
        )

        # Layer 4: Slack / Freeblock Bytes
        if slack_range:
            spans.append(
                ByteHighlightSpan(
                    layer_type=HexLayerType.LAYER_4_SLACK_OR_FREEBLOCK,
                    start_offset=slack_range[0],
                    end_offset=slack_range[1],
                    css_color_class="hex-layer-crimson",
                    label="Unallocated Page Freeblock Slack",
                )
            )

        return spans

    def compute_aligned_hex_slice_window(
        self, center_offset: int, total_file_size: int, window_size: int = 16384
    ) -> HexSliceWindow:
        """Calculates 4 KB page-aligned binary window slice [floor(offset/4096)*4096 - 4096, +16KB]."""
        raw_base = (center_offset // 4096) * 4096 - 4096
        base = max(0, raw_base)
        max_possible = max(0, total_file_size - base)
        length = min(window_size, max_possible)

        return HexSliceWindow(
            base_offset=base,
            length=length,
            data=b"",
        )

    def inspect_byte_slice(
        self,
        raw_bytes: bytes,
        cursor_byte_offset: int = 0,
        slice_length: int = 16,
    ) -> HexSliceInspectionResult:
        """Inspects byte slice and formats hex tokens, ascii tokens, and decoded integer values."""
        start = max(0, cursor_byte_offset)
        end = min(len(raw_bytes), start + max(1, slice_length))
        slice_data = raw_bytes[start:end]

        hex_tokens = [f"{b:02X}" for b in slice_data]
        ascii_tokens = [chr(b) if 32 <= b <= 126 else "." for b in slice_data]

        decoder = DataInterpreterDecoder()
        interp = decoder.decode_all_formats(slice_data)

        return HexSliceInspectionResult(
            cursor_byte_offset=start,
            slice_length=len(slice_data),
            hex_tokens=hex_tokens,
            ascii_tokens=ascii_tokens,
            int32_le=interp.int32_le,
            uint32_le=interp.uint32_le,
            data_interpreter=interp,
        )


class DataInterpreterDecoder:
    """Decodes raw binary selections across 12 forensic representations off the UI thread."""

    COCOA_EPOCH_OFFSET = 978307200  # 2001-01-01 in Unix seconds

    @staticmethod
    def _format_dt(dt: datetime) -> str:
        utc_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # Compute IST (+05:30)
        ts = dt.timestamp() + 19800
        ist_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        ist_str = ist_dt.strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")
        return f"{ist_str} [{utc_str}]"

    def decode_all_formats(self, data: bytes) -> DataInterpreterResult:
        """Translates 1 to 16 bytes into numbers, timestamps, varints, and strings."""
        res = DataInterpreterResult()
        n = len(data)
        if n == 0:
            return res

        res.hex_string = data.hex().upper()

        # 1-byte integers
        res.uint8 = data[0]
        res.int8 = struct.unpack("<b", data[0:1])[0]

        # 2-byte integers
        if n >= 2:
            res.uint16_le = struct.unpack("<H", data[0:2])[0]
            res.uint16_be = struct.unpack(">H", data[0:2])[0]
            res.int16_le = struct.unpack("<h", data[0:2])[0]
            res.int16_be = struct.unpack(">h", data[0:2])[0]

        # 4-byte integers & floats
        if n >= 4:
            res.uint32_le = struct.unpack("<I", data[0:4])[0]
            res.uint32_be = struct.unpack(">I", data[0:4])[0]
            res.int32_le = struct.unpack("<i", data[0:4])[0]
            res.int32_be = struct.unpack(">i", data[0:4])[0]
            try:
                res.float32_le = round(struct.unpack("<f", data[0:4])[0], 4)
                res.float32_be = round(struct.unpack(">f", data[0:4])[0], 4)
            except Exception:
                res.float32_le = 0.0
                res.float32_be = 0.0

        # 8-byte integers & floats
        if n >= 8:
            res.uint64_le = struct.unpack("<Q", data[0:8])[0]
            res.uint64_be = struct.unpack(">Q", data[0:8])[0]
            res.int64_le = struct.unpack("<q", data[0:8])[0]
            res.int64_be = struct.unpack(">q", data[0:8])[0]
            try:
                res.float64_le = round(struct.unpack("<d", data[0:8])[0], 4)
                res.float64_be = round(struct.unpack(">d", data[0:8])[0], 4)
            except Exception:
                res.float64_le = 0.0
                res.float64_be = 0.0

        # SQLite 9-byte Huffman Varint
        varint_val = 0
        for i in range(min(9, n)):
            b = data[i]
            if i < 8:
                varint_val = (varint_val << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
            else:
                varint_val = (varint_val << 8) | b
        res.sqlite_varint = varint_val

        # Protobuf / LevelDB LEB128 Varint
        leb_val = 0
        shift = 0
        for i in range(min(10, n)):
            b = data[i]
            leb_val |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        res.leb128_varint = leb_val

        # Timestamps evaluation
        candidate_num = res.uint64_be or res.uint32_be
        # 10-digit Unix Seconds (1.42e9 to 1.90e9)
        if 1.42e9 <= candidate_num <= 1.90e9:
            try:
                dt = datetime.fromtimestamp(candidate_num, tz=timezone.utc)
                res.unix_s_ist_utc = self._format_dt(dt)
            except Exception:
                res.unix_s_ist_utc = ""

        # 13-digit Unix Milliseconds (1.42e12 to 1.90e12)
        if 1.42e12 <= candidate_num <= 1.90e12:
            try:
                dt = datetime.fromtimestamp(candidate_num / 1000.0, tz=timezone.utc)
                res.unix_ms_ist_utc = self._format_dt(dt)
            except Exception:
                res.unix_ms_ist_utc = ""

        # 16-digit Unix Microseconds (1.42e15 to 1.90e15)
        if 1.42e15 <= candidate_num <= 1.90e15:
            try:
                dt = datetime.fromtimestamp(candidate_num / 1_000_000.0, tz=timezone.utc)
                res.unix_us_ist_utc = self._format_dt(dt)
            except Exception:
                res.unix_us_ist_utc = ""

        # Apple Cocoa CoreData Seconds (4.41e8 to 9.20e8)
        if 4.41e8 <= candidate_num <= 9.20e8:
            try:
                dt = datetime.fromtimestamp(candidate_num + self.COCOA_EPOCH_OFFSET, tz=timezone.utc)
                res.cocoa_s_ist_utc = self._format_dt(dt)
            except Exception:
                res.cocoa_s_ist_utc = ""

        # Strings
        res.utf8_string = data.decode("utf-8", errors="replace")
        res.utf16_le_string = data.decode("utf-16le", errors="replace")

        return res
