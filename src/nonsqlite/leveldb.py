"""
Google LevelDB & Chromium IndexedDB Raw Block, Log & Tombstone Parser.
Adheres strictly to Specification Section 4 (Sub-Engine 2.3B).
"""

import logging
import os
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.core.enums import ResidualConfidence
from src.nonsqlite.models import (
    InferredDataType,
    KVRecoveredRecord,
    ValueOperationType,
)
from src.nonsqlite.snappy import snappy_decompress
from src.nonsqlite.varint import decode_le_varint

logger = logging.getLogger(__name__)

LEVELDB_MAGIC = 0xDB4775248B80FB57


def clean_user_key(user_key_bytes: bytes) -> str:
    """Decodes user key bytes to a clean string, handling binary/UTF-8 keys."""
    try:
        return user_key_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return user_key_bytes.decode("latin-1", errors="replace")


def infer_leveldb_value_type(val_bytes: bytes) -> Tuple[str, str]:
    """Infers data type of LevelDB value payload."""
    if not val_bytes:
        return InferredDataType.TOMBSTONE_NULL.value, ""

    # Check UTF-8 string or JSON
    try:
        text = val_bytes.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            stripped = text.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                return InferredDataType.JSON_OBJECT.value, stripped
            return InferredDataType.UTF8_STRING.value, text
    except UnicodeDecodeError:
        return InferredDataType.RAW_BYTES_HEX.value, val_bytes.hex()

    return InferredDataType.RAW_BYTES_HEX.value, val_bytes.hex()


class LevelDBDecoder:
    """Parses LevelDB .log Write-Ahead Logs and .ldb/.sst tables without triggering compaction."""

    def decode_leveldb_directory(
        self,
        leveldb_dir: Union[str, Path],
        kv_store_id: int = 1
    ) -> List[KVRecoveredRecord]:
        """
        Scans all .log and .ldb/.sst files in the LevelDB folder, reconstructing
        the full key version history and recovering deleted keys behind tombstones.
        """
        dir_p = Path(leveldb_dir)
        if not dir_p.exists() or not dir_p.is_dir():
            return []

        # Raw extracted items: list of dicts
        raw_items: List[Dict[str, Any]] = []

        # 1. Parse all .log files
        for log_p in sorted(dir_p.glob("*.log")):
            log_entries = self._parse_log_file(log_p)
            raw_items.extend(log_entries)

        # 2. Parse all .ldb and .sst files
        for ldb_p in sorted(list(dir_p.glob("*.ldb")) + list(dir_p.glob("*.sst"))):
            ldb_entries = self._parse_ldb_file(ldb_p)
            raw_items.extend(ldb_entries)

        recovered: List[KVRecoveredRecord] = []

        if not raw_items:
            try:
                from parsers.leveldb_parser import carve_leveldb_directory
                df_fallback = carve_leveldb_directory(str(dir_p))
                for idx, row in df_fallback.iterrows():
                    recovered.append(
                        KVRecoveredRecord(
                            kv_store_id=kv_store_id,
                            key_name_text=str(row.get("Title", f"heuristic_key_{idx}")),
                            sequence_or_append_order=idx + 1,
                            value_operation_type=ValueOperationType.LIVE_PUT_ENTRY.value,
                            recovery_classification=ResidualConfidence.UNVERIFIED_FRAGMENT.value,
                            inferred_data_type=InferredDataType.JSON_OBJECT.value if "JSON" in str(row.get("Type", "")) else InferredDataType.UTF8_STRING.value,
                            decoded_value_text_or_json=str(row.get("Body", "")),
                            source_file_name=str(row.get("Source_File", "fallback")),
                            source_byte_offset=0,
                        )
                    )
                if recovered:
                    return recovered
            except Exception as exc:
                logger.debug("Fallback LevelDB carving failed for directory %s: %s", dir_p, exc)

        # 3. Group by user_key and sort by sequence_number descending
        grouped_keys: Dict[bytes, List[Dict[str, Any]]] = {}
        for item in raw_items:
            k = item["user_key"]
            if k not in grouped_keys:
                grouped_keys[k] = []
            grouped_keys[k].append(item)

        recovered: List[KVRecoveredRecord] = []

        for user_k_bytes, versions in grouped_keys.items():
            # Sort descending by sequence_number
            versions.sort(key=lambda x: x["sequence_number"], reverse=True)
            top_version = versions[0]
            k_name = clean_user_key(user_k_bytes)

            is_tombstone_active = (top_version["value_type"] == 0x00)

            for idx, ver in enumerate(versions):
                seq = ver["sequence_number"]
                vtype = ver["value_type"]
                vbytes = ver["val_bytes"]
                src_file = ver["source_file"]
                src_offset = ver["source_byte_offset"]

                if vtype == 0x00:
                    # Deletion Tombstone
                    op_type = ValueOperationType.EXPLICIT_DELETION_TOMBSTONE.value
                    classification = (
                        ResidualConfidence.RESIDUAL_RECORD
                        if is_tombstone_active
                        else ResidualConfidence.HISTORICAL_COMMITTED_RECORD
                    )
                    inf_t, dec_t = InferredDataType.TOMBSTONE_NULL.value, None
                else:
                    inf_t, dec_t = infer_leveldb_value_type(vbytes)
                    if idx == 0 and not is_tombstone_active:
                        op_type = ValueOperationType.LIVE_VALUE.value
                        classification = ResidualConfidence.ORIGINAL_RECORD
                    else:
                        op_type = ValueOperationType.SUPERSEDED_OVERWRITTEN_VALUE.value
                        classification = (
                            ResidualConfidence.RESIDUAL_RECORD
                            if is_tombstone_active
                            else ResidualConfidence.HISTORICAL_COMMITTED_RECORD
                        )

                recovered.append(
                    KVRecoveredRecord(
                        kv_store_id=kv_store_id,
                        key_name_text=k_name,
                        sequence_or_append_order=seq,
                        value_operation_type=op_type,
                        recovery_classification=classification,
                        inferred_data_type=inf_t,
                        decoded_value_text_or_json=dec_t,
                        source_file_name=src_file,
                        source_byte_offset=src_offset,
                    )
                )

        return recovered

    def _parse_log_file(self, log_path: Path) -> List[Dict[str, Any]]:
        """Parses a LevelDB 32 KB block formatted .log file."""
        entries: List[Dict[str, Any]] = []
        data = log_path.read_bytes()
        file_len = len(data)
        block_size = 32768

        batch_fragments = bytearray()
        cursor = 0

        while cursor < file_len:
            block_rem = block_size - (cursor % block_size)
            if block_rem < 7:
                cursor += block_rem
                continue

            chunk_start = cursor
            crc = struct.unpack("<I", data[cursor:cursor + 4])[0]
            payload_len = struct.unpack("<H", data[cursor + 4:cursor + 6])[0]
            chunk_type = data[cursor + 6]
            cursor += 7

            if cursor + payload_len > file_len:
                break

            chunk_payload = data[cursor:cursor + payload_len]
            cursor += payload_len

            if chunk_type == 1:  # FULL
                batch_fragments = bytearray(chunk_payload)
                self._decode_write_batch(bytes(batch_fragments), log_path.name, chunk_start, entries)
                batch_fragments.clear()
            elif chunk_type == 2:  # FIRST
                batch_fragments = bytearray(chunk_payload)
            elif chunk_type == 3:  # MIDDLE
                batch_fragments.extend(chunk_payload)
            elif chunk_type == 4:  # LAST
                batch_fragments.extend(chunk_payload)
                self._decode_write_batch(bytes(batch_fragments), log_path.name, chunk_start, entries)
                batch_fragments.clear()

        return entries

    def _decode_write_batch(
        self,
        batch_buf: bytes,
        source_name: str,
        base_offset: int,
        out_list: List[Dict[str, Any]]
    ) -> None:
        """Decodes records from a reassembled LevelDB WriteBatch."""
        if len(batch_buf) < 12:
            return

        base_seq = struct.unpack("<Q", batch_buf[:8])[0]
        record_count = struct.unpack("<I", batch_buf[8:12])[0]
        pos = 12
        buf_len = len(batch_buf)

        for idx in range(record_count):
            if pos >= buf_len:
                break
            entry_offset = base_offset + pos
            vtype = batch_buf[pos]
            pos += 1
            entry_seq = base_seq + idx

            if vtype == 0x01:  # Live Put
                k_len, k_var_len = decode_le_varint(batch_buf, pos)
                pos += k_var_len
                user_key = batch_buf[pos:pos + k_len]
                pos += k_len

                v_len, v_var_len = decode_le_varint(batch_buf, pos)
                pos += v_var_len
                val_bytes = batch_buf[pos:pos + v_len]
                pos += v_len

                out_list.append({
                    "user_key": user_key,
                    "sequence_number": entry_seq,
                    "value_type": 0x01,
                    "val_bytes": val_bytes,
                    "source_file": source_name,
                    "source_byte_offset": entry_offset,
                })
            elif vtype == 0x00:  # Delete Tombstone
                k_len, k_var_len = decode_le_varint(batch_buf, pos)
                pos += k_var_len
                user_key = batch_buf[pos:pos + k_len]
                pos += k_len

                out_list.append({
                    "user_key": user_key,
                    "sequence_number": entry_seq,
                    "value_type": 0x00,
                    "val_bytes": b"",
                    "source_file": source_name,
                    "source_byte_offset": entry_offset,
                })

    def _parse_ldb_file(self, ldb_path: Path) -> List[Dict[str, Any]]:
        """Parses a LevelDB .ldb or .sst file."""
        entries: List[Dict[str, Any]] = []
        data = ldb_path.read_bytes()
        file_len = len(data)
        if file_len < 48:
            return entries

        # 1. Read 48-byte Footer
        footer = data[-48:]
        magic = struct.unpack("<Q", footer[40:48])[0]
        if magic != LEVELDB_MAGIC:
            return entries

        # Parse index block handle from footer
        pos = 0
        _, v1 = decode_le_varint(footer, pos)
        pos += v1
        _, v2 = decode_le_varint(footer, pos)
        pos += v2

        index_off, v3 = decode_le_varint(footer, pos)
        pos += v3
        index_size, _ = decode_le_varint(footer, pos)

        # 2. Decompress Index Block
        idx_block = self._read_and_decompress_block(data, index_off, index_size)
        if not idx_block:
            return entries

        # 3. Parse Data Block Handles from Index Block
        data_block_handles = self._parse_index_block_entries(idx_block)

        # 4. Decompress each Data Block and decode prefix-compressed entries
        for d_off, d_sz in data_block_handles:
            data_block = self._read_and_decompress_block(data, d_off, d_sz)
            if data_block:
                block_entries = self._decode_data_block_entries(data_block, ldb_path.name, d_off)
                entries.extend(block_entries)

        return entries

    def _read_and_decompress_block(self, file_data: bytes, block_off: int, block_sz: int) -> bytes:
        """Reads payload bytes and handles Snappy/Zstd/None decompression."""
        if block_off + block_sz + 5 > len(file_data):
            return b""

        payload = file_data[block_off:block_off + block_sz]
        comp_type = file_data[block_off + block_sz]  # 1 byte trailer

        if comp_type == 0x00:
            return payload
        elif comp_type == 0x01:
            try:
                return snappy_decompress(payload)
            except Exception as exc:
                logger.warning("Snappy block at %d unreadable, skipped: %s", block_off, exc)
                return b""
        elif comp_type == 0x02:
            try:
                import zstandard as zstd
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(payload)
            except Exception as exc:
                logger.debug("Zstd decompression failed: %s", exc)
                return b""

        return payload

    def _parse_index_block_entries(self, index_buf: bytes) -> List[Tuple[int, int]]:
        """Parses data block offset and size tuples from index block."""
        handles: List[Tuple[int, int]] = []
        B = len(index_buf)
        if B < 4:
            return handles

        num_restarts = struct.unpack("<I", index_buf[B - 4:B])[0]
        restarts_size = 4 * num_restarts
        e_end = B - 4 - restarts_size
        pos = 0

        while pos < e_end:
            try:
                shared, v1 = decode_le_varint(index_buf, pos)
                pos += v1
                unshared, v2 = decode_le_varint(index_buf, pos)
                pos += v2
                val_len, v3 = decode_le_varint(index_buf, pos)
                pos += v3

                # Skip key delta
                pos += unshared

                # Value contains data block offset and size varints
                v_slice = index_buf[pos:pos + val_len]
                pos += val_len

                d_off, hv1 = decode_le_varint(v_slice, 0)
                d_sz, _ = decode_le_varint(v_slice, hv1)
                handles.append((d_off, d_sz))
            except Exception:
                break

        return handles

    def _decode_data_block_entries(
        self,
        block_buf: bytes,
        source_name: str,
        base_offset: int
    ) -> List[Dict[str, Any]]:
        """Decodes prefix-compressed entries and strips 8-byte internal trailer."""
        entries: List[Dict[str, Any]] = []
        B = len(block_buf)
        if B < 4:
            return entries

        num_restarts = struct.unpack("<I", block_buf[B - 4:B])[0]
        restarts_size = 4 * num_restarts
        e_end = B - 4 - restarts_size
        pos = 0
        prev_key = b""

        while pos < e_end:
            try:
                entry_start = base_offset + pos
                shared, v1 = decode_le_varint(block_buf, pos)
                pos += v1
                unshared, v2 = decode_le_varint(block_buf, pos)
                pos += v2
                val_len, v3 = decode_le_varint(block_buf, pos)
                pos += v3

                if pos + unshared + val_len > e_end or shared > len(prev_key):
                    # Entry runs past the block (corrupt/truncated): stop rather than emit a short key or value.
                    logger.warning("LevelDB block entry at %d is inconsistent; remaining entries skipped", entry_start)
                    break
                key_delta = block_buf[pos:pos + unshared]
                pos += unshared
                val_bytes = block_buf[pos:pos + val_len]
                pos += val_len

                curr_internal_key = prev_key[:shared] + key_delta
                prev_key = curr_internal_key

                # Strip 8-byte trailer: (sequence_number << 8) | value_type
                if len(curr_internal_key) >= 8:
                    user_key = curr_internal_key[:-8]
                    tag = struct.unpack("<Q", curr_internal_key[-8:])[0]
                    seq_num = tag >> 8
                    val_type = tag & 0xFF

                    entries.append({
                        "user_key": user_key,
                        "sequence_number": seq_num,
                        "value_type": val_type,
                        "val_bytes": val_bytes,
                        "source_file": source_name,
                        "source_byte_offset": entry_start,
                    })
            except Exception:
                break

        return entries
