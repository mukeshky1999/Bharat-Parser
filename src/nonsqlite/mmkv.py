"""
Tencent MMKV Binary Decoder, Append-History Tracker & Mmap Slack Carver.
Adheres strictly to Specification Section 3 (Sub-Engine 2.3A).
"""

import json
import logging
import os
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.core.enums import ResidualConfidence
from src.nonsqlite.models import (
    InferredDataType,
    KVRecoveredRecord,
    ValueOperationType,
)
from src.nonsqlite.protobuf import decode_raw_protobuf
from src.nonsqlite.varint import decode_le_varint, decode_zigzag_64

logger = logging.getLogger(__name__)


def is_printable_ascii(b_slice: bytes) -> bool:
    """Checks whether bytes slice consists of valid printable ASCII characters."""
    return all(0x20 <= b <= 0x7E for b in b_slice)


def disambiguate_mmkv_value(val_bytes: bytes) -> Tuple[str, str]:
    """
    Decodes raw MMKV value bytes according to Section 3.4 Multi-Type Value Disambiguator.
    Returns `(inferred_data_type, decoded_text_or_json)`.
    """
    if not val_bytes:
        return InferredDataType.TOMBSTONE_NULL.value, ""

    L = len(val_bytes)

    # Check 1: Inner Length-Prefixed UTF-8 String or JSON
    try:
        inner_len, inner_varint_len = decode_le_varint(val_bytes, 0)
        if inner_varint_len + inner_len == L and inner_len > 0:
            text_slice = val_bytes[inner_varint_len:inner_varint_len + inner_len]
            decoded_text = text_slice.decode("utf-8")
            # If valid string
            if sum(1 for c in decoded_text if c.isprintable() or c in "\r\n\t") / len(decoded_text) >= 0.85:
                # Check if JSON
                stripped = decoded_text.strip()
                if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                    try:
                        parsed = json.loads(stripped)
                        return InferredDataType.JSON_OBJECT.value, json.dumps(parsed, sort_keys=True)
                    except Exception:
                        return InferredDataType.UTF8_STRING.value, decoded_text
                return InferredDataType.UTF8_STRING.value, decoded_text
    except Exception:
        decoded_text = None

    # Check 2: Inner Length-Prefixed Nested Protobuf
    try:
        inner_len, inner_varint_len = decode_le_varint(val_bytes, 0)
        if inner_varint_len + inner_len == L and inner_len > 0:
            pb_slice = val_bytes[inner_varint_len:inner_varint_len + inner_len]
            pb_dict, is_pb = decode_raw_protobuf(pb_slice)
            if is_pb and len(pb_dict) > 0:
                return InferredDataType.NESTED_PROTOBUF.value, json.dumps(pb_dict, sort_keys=True)
    except Exception:
        pb_dict = None

    # Check 3: Direct Raw Varint (bool, int32, uint32, int64, zigzag)
    if L <= 10:
        try:
            v, v_len = decode_le_varint(val_bytes, 0)
            if v_len == L:
                if L == 1 and v in (0, 1):
                    desc = f"{v} (false, if the field is a boolean)" if v == 0 else f"{v} (true, if the field is a boolean)"
                else:
                    zigzag = decode_zigzag_64(v)
                    desc = f"{v} (zigzag: {zigzag})"
                return InferredDataType.VARINT_INTEGER.value, desc
        except Exception:
            v = None

    # Check 4: Fixed Float32 or Double Float64
    if L == 4:
        f32 = struct.unpack("<f", val_bytes)[0]
        u32 = struct.unpack("<I", val_bytes)[0]
        return InferredDataType.FLOAT_DOUBLE.value, f"float32: {f32}, uint32: {u32}"
    elif L == 8:
        f64 = struct.unpack("<d", val_bytes)[0]
        u64 = struct.unpack("<Q", val_bytes)[0]
        return InferredDataType.FLOAT_DOUBLE.value, f"float64: {f64}, uint64: {u64}"

    return InferredDataType.RAW_BYTES_HEX.value, val_bytes.hex()


class MMKVDecoder:
    """Decodes Tencent MMKV memory-mapped stores, append histories, and mmap slack space."""

    def __init__(self):
        self.is_encrypted: bool = False

    def decode_mmkv_file(
        self,
        mmkv_path: Union[str, Path],
        crc_path: Optional[Union[str, Path]] = None,
        crypt_key_16: Optional[bytes] = None,
        kv_store_id: int = 1
    ) -> List[KVRecoveredRecord]:
        """
        Parses all three layers of an MMKV file:
        - Layer 1: Active live records (ORIGINAL_RECORD)
        - Layer 2: Superseded appends and deletion tombstones (HISTORICAL_COMMITTED_RECORD)
        - Layer 3: Unallocated mmap slack space (RESIDUAL_RECORD)
        """
        m_path = Path(mmkv_path)
        if not m_path.exists():
            return []

        file_bytes = m_path.read_bytes()
        file_size = len(file_bytes)
        if file_size < 8:
            return []

        # Step 1: Check .crc companion file for AES-128-CFB encryption
        c_path = Path(crc_path) if crc_path else m_path.parent / f"{m_path.name}.crc"
        if c_path.exists() and c_path.stat().st_size >= 28:
            crc_data = c_path.read_bytes()
            iv = crc_data[12:28]
            # If IV is non-zero and start of MMKV is high entropy, decrypt with AES-128-CFB
            if any(b != 0 for b in iv):
                # A non-zero IV means the store is encrypted. Parsing ciphertext as if it were plaintext
                # produces junk records, so without a working key nothing is returned (review R-20).
                if not (crypt_key_16 and len(crypt_key_16) == 16):
                    logger.warning("MMKV %s is encrypted (non-zero IV in .crc) and no 16-byte key was supplied: not decoded", m_path.name)
                    return []
                try:
                    cipher = Cipher(algorithms.AES(crypt_key_16), modes.CFB(iv))
                    decryptor = cipher.decryptor()
                    dec_payload = decryptor.update(file_bytes[4:]) + decryptor.finalize()
                    file_bytes = file_bytes[:4] + dec_payload
                    self.is_encrypted = True
                except Exception as exc:
                    logger.warning("AES-128-CFB decryption of MMKV %s failed: %s", m_path.name, exc)
                    return []

        actual_size = struct.unpack("<I", file_bytes[:4])[0]
        # Sanity check actual_size
        if actual_size > file_size - 4:
            actual_size = file_size - 4

        # Step 2: Parse Active Append Stream (Bytes 4 to 4 + actual_size)
        pos = 4
        active_stream_end = 4 + actual_size
        append_seq = 1

        # Key timeline: key_name -> list of tuples (append_seq, offset, val_container_len, raw_val)
        key_timeline_map: Dict[str, List[Tuple[int, int, int, bytes]]] = {}

        while pos < active_stream_end:
            try:
                entry_start = pos
                key_len, k_len_bytes = decode_le_varint(file_bytes, pos)
                if key_len <= 0 or pos + k_len_bytes + key_len > active_stream_end:
                    break
                pos += k_len_bytes

                key_bytes = file_bytes[pos:pos + key_len]
                key_name = key_bytes.decode("utf-8", errors="replace")
                pos += key_len

                val_len, v_len_bytes = decode_le_varint(file_bytes, pos)
                pos += v_len_bytes

                if pos + val_len > active_stream_end:
                    break

                val_slice = file_bytes[pos:pos + val_len]
                pos += val_len

                if key_name not in key_timeline_map:
                    key_timeline_map[key_name] = []
                key_timeline_map[key_name].append((append_seq, entry_start, val_len, val_slice))
                append_seq += 1
            except Exception as exc:
                logger.debug("MMKV append stream parse break at pos %d: %s", pos, exc)
                break

        records: List[KVRecoveredRecord] = []
        source_name = m_path.name

        # Step 3: Classify Layer 1 (Live) vs Layer 2 (Historical Superseded / Deletion Tombstones)
        for key_name, entries in key_timeline_map.items():
            K = len(entries)
            # Final entry
            final_seq, final_off, final_vlen, final_val = entries[-1]

            if final_vlen > 0:
                # Live active value
                inferred_type, decoded_text = disambiguate_mmkv_value(final_val)
                records.append(
                    KVRecoveredRecord(
                        kv_store_id=kv_store_id,
                        key_name_text=key_name,
                        sequence_or_append_order=final_seq,
                        value_operation_type=ValueOperationType.LIVE_VALUE.value,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        inferred_data_type=inferred_type,
                        decoded_value_text_or_json=decoded_text,
                        source_file_name=source_name,
                        source_byte_offset=final_off,
                    )
                )
            else:
                # Explicit Deletion Tombstone
                records.append(
                    KVRecoveredRecord(
                        kv_store_id=kv_store_id,
                        key_name_text=key_name,
                        sequence_or_append_order=final_seq,
                        value_operation_type=ValueOperationType.EXPLICIT_DELETION_TOMBSTONE.value,
                        recovery_classification=ResidualConfidence.HISTORICAL_COMMITTED_RECORD,
                        inferred_data_type=InferredDataType.TOMBSTONE_NULL.value,
                        decoded_value_text_or_json=None,
                        source_file_name=source_name,
                        source_byte_offset=final_off,
                    )
                )

            # All earlier entries are superseded historical versions
            for hist_seq, hist_off, hist_vlen, hist_val in entries[:-1]:
                if hist_vlen > 0:
                    inf_t, dec_t = disambiguate_mmkv_value(hist_val)
                else:
                    inf_t, dec_t = InferredDataType.TOMBSTONE_NULL.value, None

                records.append(
                    KVRecoveredRecord(
                        kv_store_id=kv_store_id,
                        key_name_text=key_name,
                        sequence_or_append_order=hist_seq,
                        value_operation_type=ValueOperationType.SUPERSEDED_OVERWRITTEN_VALUE.value,
                        recovery_classification=ResidualConfidence.HISTORICAL_COMMITTED_RECORD,
                        inferred_data_type=inf_t,
                        decoded_value_text_or_json=dec_t,
                        source_file_name=source_name,
                        source_byte_offset=hist_off,
                    )
                )

        # Step 4: Carve Layer 3 (Mmap Slack Space: Bytes 4 + actual_size to EOF)
        slack_pos = 4 + actual_size
        while slack_pos < file_size - 4:
            if file_bytes[slack_pos] == 0x00:
                slack_pos += 1
                continue

            try:
                cand_off = slack_pos
                cand_klen, k_var_len = decode_le_varint(file_bytes, slack_pos)

                # Strict sanity check on candidate key
                if 1 <= cand_klen <= 256 and slack_pos + k_var_len + cand_klen <= file_size:
                    k_slice = file_bytes[slack_pos + k_var_len:slack_pos + k_var_len + cand_klen]
                    if is_printable_ascii(k_slice):
                        val_pos = slack_pos + k_var_len + cand_klen
                        cand_vlen, v_var_len = decode_le_varint(file_bytes, val_pos)

                        if val_pos + v_var_len + cand_vlen <= file_size:
                            v_slice = file_bytes[val_pos + v_var_len:val_pos + v_var_len + cand_vlen]
                            cand_key_name = k_slice.decode("utf-8")
                            inf_t, dec_t = disambiguate_mmkv_value(v_slice)

                            records.append(
                                KVRecoveredRecord(
                                    kv_store_id=kv_store_id,
                                    key_name_text=cand_key_name,
                                    sequence_or_append_order=append_seq,
                                    value_operation_type=ValueOperationType.CARVED_SLACK_VALUE.value,
                                    recovery_classification=ResidualConfidence.RESIDUAL_RECORD,
                                    inferred_data_type=inf_t,
                                    decoded_value_text_or_json=dec_t,
                                    source_file_name=source_name,
                                    source_byte_offset=cand_off,
                                )
                            )
                            append_seq += 1
                            slack_pos = val_pos + v_var_len + cand_vlen
                            continue
            except Exception:
                slack_pos += 1
                continue

            slack_pos += 1

        return records
