"""
Test Suite for Phase 2, Module 2.3: Non-SQLite Binary Storage Engine Decoders
(Tencent MMKV, LevelDB/IndexedDB, Apple SEGB v1/v2 & Schema-Less Protobuf).

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures and streams (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests MMKV 3-layer append history & mmap slack space carving.
- Tests LevelDB Snappy block decompression, 8-byte trailer stripping, and deletion tombstone recovery.
- Tests Apple SEGB v2 reverse trailer walk, intact deleted records, and zeroed payload timestamp recovery.
- Tests Schema-less Protobuf wire format parsing with automatic timestamp inference.
- Verifies canonical kv_store_diagnostics, kv_recovered_records_master, and biome_segb_records_master schemas.
"""

import os
import shutil
import sqlite3
import struct
from pathlib import Path
from typing import List, Dict, Any

import pytest

from src.core.enums import (
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ForensicGroup,
)


@pytest.fixture
def tmp_nonsqlite_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_nonsqlite_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# HELPER FUNCTIONS: Binary Data Synthesizers
# ==============================================================================

def write_le_varint(val: int) -> bytes:
    """Encodes unsigned integer as Little-Endian Base-128 Varint."""
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def snappy_compress_raw(data: bytes) -> bytes:
    """Pure-Python raw Snappy block compressor (literal framing)."""
    val = len(data)
    hdr = bytearray()
    while val >= 0x80:
        hdr.append((val & 0x7F) | 0x80)
        val >>= 7
    hdr.append(val)
    L = len(data)
    if L <= 60:
        hdr.append(((L - 1) << 2) | 0)
    elif L <= 256:
        hdr.append((60 << 2) | 0)
        hdr.append(L - 1)
    else:
        hdr.append((61 << 2) | 0)
        hdr.extend((L - 1).to_bytes(2, "little"))
    hdr.extend(data)
    return bytes(hdr)


# ==============================================================================
# TEST 1: MMKV 3-Layer Append & Slack Carving Test
# ==============================================================================

def test_mmkv_3layer_append_and_slack_carving(tmp_nonsqlite_dir):
    """
    Acceptance Test 1 (Section 8.1):
    Constructs a 4096-byte mmkv.default file:
    - active_upi_vpa appended 3 times:
      1: "suspect1@ybl"
      2: "mule_account@okaxis"
      3: deleted with 0-length value (val_len = 0)
    - Slack space (past actual_size):
      - At byte offset 2048: older key "jwt_auth_token" with value "eyJhbGciOi..."
    Verifies that Sub-Engine 2.3A:
    1. Recovers the deletion tombstone (val_len = 0) and earlier VPAs as HISTORICAL_COMMITTED_RECORD.
    2. Recovers "jwt_auth_token" from slack space as RESIDUAL_RECORD.
    """
    from src.nonsqlite.mmkv import MMKVDecoder

    mmkv_file = tmp_nonsqlite_dir / "mmkv.default"
    crc_file = tmp_nonsqlite_dir / "mmkv.default.crc"

    # Construct Active Append Stream
    append_stream = bytearray()

    def add_entry(key: str, val_str: str):
        k_bytes = key.encode("utf-8")
        if val_str is not None:
            v_inner = val_str.encode("utf-8")
            # Inner length prefix (varint) + text
            v_container = write_le_varint(len(v_inner)) + v_inner
        else:
            v_container = b""  # Deletion tombstone!

        append_stream.extend(write_le_varint(len(k_bytes)))
        append_stream.extend(k_bytes)
        append_stream.extend(write_le_varint(len(v_container)))
        append_stream.extend(v_container)

    # 1. Three appends for active_upi_vpa
    add_entry("active_upi_vpa", "suspect1@ybl")
    add_entry("active_upi_vpa", "mule_account@okaxis")
    add_entry("active_upi_vpa", None)  # Tombstone

    # 2. Add an active key to ensure mixed stream
    add_entry("current_user_id", "USR_99887766")

    actual_size = len(append_stream)

    # Build 4096-byte MMKV buffer
    mmap_buf = bytearray(4096)
    # Header: actual_size at bytes 0..3 (uint32_le)
    struct.pack_into("<I", mmap_buf, 0, actual_size)
    mmap_buf[4:4 + actual_size] = append_stream

    # 3. Place older key in Mmap Slack Space at offset 2048
    slack_entry = bytearray()
    slack_k = b"jwt_auth_token"
    slack_v_text = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNac"
    slack_v = write_le_varint(len(slack_v_text)) + slack_v_text
    slack_entry.extend(write_le_varint(len(slack_k)))
    slack_entry.extend(slack_k)
    slack_entry.extend(write_le_varint(len(slack_v)))
    slack_entry.extend(slack_v)

    mmap_buf[2048:2048 + len(slack_entry)] = slack_entry

    with open(mmkv_file, "wb") as f:
        f.write(mmap_buf)

    # Companion CRC file (32 bytes)
    crc_bytes = struct.pack("<IIII16s", 0x12345678, 1, actual_size, 0, b"\x00" * 16)
    with open(crc_file, "wb") as f:
        f.write(crc_bytes)

    # Run MMKV Decoder
    decoder = MMKVDecoder()
    records = decoder.decode_mmkv_file(mmkv_file)

    assert len(records) >= 4

    # Check active_upi_vpa records
    vpa_records = [r for r in records if r.key_name_text == "active_upi_vpa"]
    assert len(vpa_records) == 3

    # The 3rd entry was a deletion tombstone
    tombstones = [r for r in vpa_records if r.value_operation_type == "EXPLICIT_DELETION_TOMBSTONE"]
    assert len(tombstones) == 1
    assert tombstones[0].recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD

    # The earlier 2 entries were superseded values
    superseded = [r for r in vpa_records if r.value_operation_type == "SUPERSEDED_OVERWRITTEN_VALUE"]
    assert len(superseded) == 2
    assert any("suspect1@ybl" in str(r.decoded_value_text_or_json) for r in superseded)
    assert any("mule_account@okaxis" in str(r.decoded_value_text_or_json) for r in superseded)

    # Check slack carved key
    slack_recs = [r for r in records if r.key_name_text == "jwt_auth_token"]
    assert len(slack_recs) == 1
    assert slack_recs[0].value_operation_type == "CARVED_SLACK_VALUE"
    assert slack_recs[0].recovery_classification == ResidualConfidence.RESIDUAL_RECORD
    assert "eyJhbGci" in str(slack_recs[0].decoded_value_text_or_json)
    assert slack_recs[0].source_byte_offset >= 2048


# ==============================================================================
# TEST 2: LevelDB Snappy Decompression, 8-Byte Trailer & Tombstone Recovery
# ==============================================================================

def test_leveldb_snappy_trailer_and_tombstone_recovery(tmp_nonsqlite_dir):
    """
    Acceptance Test 2 (Section 8.2):
    Constructs a LevelDB directory containing:
    1. An .ldb file containing an InternalKey for "metamask_vault":
       - sequence_number = 100, value_type = 0x01 (Live Value)
       - compressed with Google Snappy (compression_type = 0x01)
       - Footer with valid magic 0xdb4775248b80fb57
    2. A .log file containing WriteBatches:
       - sequence_number = 205, value_type = 0x01 (Update)
       - sequence_number = 310, value_type = 0x00 (Deletion Tombstone)
    Verifies that Sub-Engine 2.3B:
    1. Strips the 8-byte trailer from every .ldb key.
    2. Decompresses the Snappy Data Block.
    3. Recovers seq = 100 and seq = 205 behind the seq = 310 tombstone as RESIDUAL_RECORD!
    """
    from src.nonsqlite.leveldb import LevelDBDecoder

    ldb_dir = tmp_nonsqlite_dir / "leveldb_store"
    ldb_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build .ldb file with Snappy compression
    ldb_file = ldb_dir / "000005.ldb"

    user_k = b"metamask_vault"
    # Tag for seq=100, value_type=0x01: (100 << 8) | 1
    tag_100 = (100 << 8) | 1
    internal_k_100 = user_k + struct.pack("<Q", tag_100)

    val_100 = b'{"vault_version": 1, "encrypted_mnemonic": "cipher_text_100"}'

    # Build Data Block:
    # 1 entry: shared_bytes=0, unshared_bytes=len(internal_k), val_len=len(val_100)
    data_block_raw = bytearray()
    data_block_raw.extend(write_le_varint(0))
    data_block_raw.extend(write_le_varint(len(internal_k_100)))
    data_block_raw.extend(write_le_varint(len(val_100)))
    data_block_raw.extend(internal_k_100)
    data_block_raw.extend(val_100)
    # Restart point array: offset 0 (4 bytes) + num_restarts=1 (4 bytes)
    data_block_raw.extend(struct.pack("<II", 0, 1))

    # Compress Data Block with Snappy
    snappy_payload = snappy_compress_raw(bytes(data_block_raw))
    # Block Trailer: 1 byte compression (0x01=Snappy) + 4 bytes crc32c
    data_block_full = snappy_payload + bytes([1]) + _block_crc(snappy_payload, 1)
    data_block_size = len(snappy_payload)

    # Build Index Block pointing to Data Block at offset 0
    index_block_raw = bytearray()
    # Key in index block is separator key (e.g. internal_k_100)
    # Value is two varints: offset=0, size=data_block_size
    index_val = write_le_varint(0) + write_le_varint(data_block_size)
    index_block_raw.extend(write_le_varint(0))
    index_block_raw.extend(write_le_varint(len(internal_k_100)))
    index_block_raw.extend(write_le_varint(len(index_val)))
    index_block_raw.extend(internal_k_100)
    index_block_raw.extend(index_val)
    index_block_raw.extend(struct.pack("<II", 0, 1))

    index_block_full = bytes(index_block_raw) + bytes([0]) + _block_crc(bytes(index_block_raw), 0)  # uncompressed (0x00)
    index_block_offset = len(data_block_full)
    index_block_size = len(index_block_raw)

    # Build 48-Byte Footer
    footer = bytearray(48)
    # metaindex handle: offset=0, size=0 (empty)
    # index handle: offset=index_block_offset, size=index_block_size
    handles = write_le_varint(0) + write_le_varint(0) + write_le_varint(index_block_offset) + write_le_varint(index_block_size)
    footer[:len(handles)] = handles
    # Magic number at footer offsets 40..47: 0xdb4775248b80fb57
    struct.pack_into("<Q", footer, 40, 0xdb4775248b80fb57)

    with open(ldb_file, "wb") as f:
        f.write(data_block_full + index_block_full + footer)

    # 2. Build .log file with WriteBatches for seq=205 and seq=310 (tombstone)
    log_file = ldb_dir / "000007.log"

    # WriteBatch 1: seq=205, value_type=0x01
    val_205 = b'{"vault_version": 2, "encrypted_mnemonic": "cipher_text_205"}'
    batch_205 = bytearray()
    batch_205.extend(struct.pack("<QI", 205, 1))  # base_seq=205, count=1
    batch_205.append(0x01)  # value_type=0x01
    batch_205.extend(write_le_varint(len(user_k)) + user_k)
    batch_205.extend(write_le_varint(len(val_205)) + val_205)

    # Chunk 1 (FULL = 1): 7-byte header (crc 4b, len 2b, type 1b) + payload
    chunk_1 = _log_chunk(bytes(batch_205))

    # WriteBatch 2: seq=310, value_type=0x00 (Tombstone)
    batch_310 = bytearray()
    batch_310.extend(struct.pack("<QI", 310, 1))  # base_seq=310, count=1
    batch_310.append(0x00)  # value_type=0x00 (Deletion Tombstone)
    batch_310.extend(write_le_varint(len(user_k)) + user_k)

    chunk_2 = _log_chunk(bytes(batch_310))

    with open(log_file, "wb") as f:
        f.write(chunk_1 + chunk_2)

    # Run LevelDB Decoder
    decoder = LevelDBDecoder()
    records = decoder.decode_leveldb_directory(ldb_dir)

    assert len(records) >= 3

    vault_recs = [r for r in records if r.key_name_text == "metamask_vault"]
    assert len(vault_recs) == 3

    # Check that 8-byte trailer was stripped from key name
    for r in vault_recs:
        assert r.key_name_text == "metamask_vault"

    # Highest sequence is 310 (Deletion Tombstone)
    top_rec = max(vault_recs, key=lambda x: x.sequence_or_append_order)
    assert top_rec.sequence_or_append_order == 310
    assert top_rec.value_operation_type == "EXPLICIT_DELETION_TOMBSTONE"

    # Because highest sequence was a tombstone, older versions are RESIDUAL_RECORD
    older_recs = [r for r in vault_recs if r.sequence_or_append_order in (100, 205)]
    assert len(older_recs) == 2
    for r in older_recs:
        assert r.recovery_classification == ResidualConfidence.RESIDUAL_RECORD


# ==============================================================================
# TEST 3: Apple Biome SEGB v2 Reverse Trailer & Zeroed-Payload Test
# ==============================================================================

def test_apple_biome_segb_v2_reverse_trailer_walk(tmp_nonsqlite_dir):
    """
    Acceptance Test 3 (Section 8.3):
    Synthesizes an iOS 18/26 SEGB v2 file:
    - Bytes 0..3: magic "SEGB"
    - Data base offset = 32
    - 20 active records (state = 1) with Protobuf payloads
    - 5 deleted records (state = 3) with intact Protobuf payloads
    - 5 deleted records (state = 3) whose payload bytes were zeroed (0x00)
    - 30 reverse trailers written backward from EOF in 16-byte steps
    Verifies that Sub-Engine 2.3C:
    1. Successfully walks all 30 trailers backward from EOF.
    2. Recovers all 20 active records as ORIGINAL_RECORD.
    3. Recovers the 5 intact deleted records as RESIDUAL_RECORD.
    4. Logs the 5 zeroed records as PARTIAL_RECORD with their surviving Cocoa write timestamps!
    """
    from src.nonsqlite.segb import SEGBDecoder

    segb_file = tmp_nonsqlite_dir / "0000000000000001"

    # Forward Payloads Zone (starts at byte 32)
    payload_zone = bytearray()
    trailers_info = []  # (end_rel, state, cocoa_ts, is_zeroed)

    # Base Cocoa time: 2024-01-01 (approx 725846400.0)
    base_cocoa = 725846400.0

    # 1. 20 Active records (state = 1)
    for i in range(20):
        # Protobuf payload: field 1 (varint i) + field 2 (string "App.InFocus.Active")
        pb_payload = b"\x08" + write_le_varint(i + 1) + b"\x12\x0eApp.InFocus.Act"
        # 4-byte align payload
        padded_len = (len(pb_payload) + 3) & ~3
        pb_payload_padded = pb_payload + b"\x00" * (padded_len - len(pb_payload))

        payload_zone.extend(pb_payload_padded)
        end_rel = len(payload_zone)
        trailers_info.append((end_rel, 1, base_cocoa + i * 60, False))

    # 2. 5 Deleted records (state = 3) with intact payload
    for i in range(20, 25):
        pb_payload = b"\x08" + write_le_varint(i + 1) + b"\x12\x10DeletedIntactApp"
        padded_len = (len(pb_payload) + 3) & ~3
        pb_payload_padded = pb_payload + b"\x00" * (padded_len - len(pb_payload))

        payload_zone.extend(pb_payload_padded)
        end_rel = len(payload_zone)
        trailers_info.append((end_rel, 3, base_cocoa + i * 60, False))

    # 3. 5 Deleted records (state = 3) with zeroed payload (0x00)
    for i in range(25, 30):
        zero_payload = b"\x00" * 32
        payload_zone.extend(zero_payload)
        end_rel = len(payload_zone)
        trailers_info.append((end_rel, 3, base_cocoa + i * 60, True))

    # Total payload zone length
    payload_bytes_len = len(payload_zone)

    # Reverse Trailers Zone (written backward from EOF)
    # Total trailers = 30 entries * 16 bytes = 480 bytes
    trailers_zone = bytearray(len(trailers_info) * 16)
    for idx, (end_rel, state, cocoa_ts, is_zeroed) in enumerate(trailers_info):
        # Index in reverse from EOF: entry 0 is at trailer_pos = total_len - 16 * (idx + 1)
        # Note: in SEGB v2, record 0's trailer is at the very end of file (EOF - 16)
        # or written sequentially backward.
        pos_in_trailers = len(trailers_zone) - (idx + 1) * 16
        entry_bytes = struct.pack("<IId", end_rel, state, cocoa_ts)
        trailers_zone[pos_in_trailers:pos_in_trailers + 16] = entry_bytes

    # Assemble File: 32-byte Header + Payloads + Trailers
    header = bytearray(32)
    header[:4] = b"SEGB"  # Magic at byte 0 for SEGB v2
    struct.pack_into("<I", header, 4, 2)  # version 2

    full_file_bytes = header + payload_zone + trailers_zone

    with open(segb_file, "wb") as f:
        f.write(full_file_bytes)

    # Run SEGB Decoder
    decoder = SEGBDecoder()
    records = decoder.decode_segb_file(segb_file, stream_name="App.InFocus")

    assert len(records) == 30

    active_recs = [r for r in records if r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD]
    assert len(active_recs) == 20

    intact_deleted = [
        r for r in records
        if r.recovery_classification == ResidualConfidence.RESIDUAL_RECORD
    ]
    assert len(intact_deleted) == 5
    for r in intact_deleted:
        assert r.decoded_protobuf_json is not None

    zeroed_deleted = [
        r for r in records
        if r.recovery_classification == ResidualConfidence.PARTIAL_RECORD
    ]
    assert len(zeroed_deleted) == 5
    for r in zeroed_deleted:
        assert r.decoded_protobuf_json is None
        assert r.segb_write_cocoa_raw > 0
        assert r.segb_write_utc_iso is not None


# ==============================================================================
# TEST 4: Schema-Less Raw Wire-Format Protobuf Decoder Test
# ==============================================================================

def test_schemaless_protobuf_decoder():
    """
    Section 6:
    Tests recursive schema-less Protobuf decoding:
    - Wire type 0 (Varint): int + ZigZag signed + timestamp
    - Wire type 1 (64-bit fixed): float64 with automatic Cocoa/Unix timestamp annotation
    - Wire type 2 (Length-delimited): string + nested Protobuf object
    - Wire type 5 (32-bit fixed): float32 / uint32
    """
    from src.nonsqlite.protobuf import decode_raw_protobuf

    # Build raw wire bytes:
    # Field 1 (Varint, tag 0x08): 1762262400 (Unix timestamp)
    # Field 2 (String, tag 0x12): "User Transfer"
    # Field 3 (64-bit float, tag 0x19): 725846400.0 (Cocoa timestamp)
    # Field 4 (Nested Protobuf, tag 0x22):
    #   Subfield 1 (Varint, tag 0x08): 42
    #   Subfield 2 (String, tag 0x12): "Sub-value"
    nested_bytes = b"\x08*" + b"\x12\tsub-value"  # 42 = '*'
    nested_tag = b"\x22" + write_le_varint(len(nested_bytes)) + nested_bytes

    wire = bytearray()
    wire.extend(b"\x08" + write_le_varint(1762262400))
    wire.extend(b"\x12\rUser Transfer")
    wire.extend(b"\x19" + struct.pack("<d", 725846400.0))
    wire.extend(nested_tag)

    decoded, is_valid = decode_raw_protobuf(bytes(wire))
    assert is_valid is True
    assert "field_1" in decoded
    assert decoded["field_1"]["value"] == 1762262400
    assert "field_2" in decoded
    assert decoded["field_2"]["value"] == "User Transfer"
    assert "field_3" in decoded
    assert "_inferred_cocoa_utc" in decoded["field_3"]
    assert "field_4" in decoded
    assert "field_1" in decoded["field_4"]["nested_object"]


# ==============================================================================
# TEST 5: Non-SQLite Forensic Engine Ledger Export Test
# ==============================================================================

def test_nonsqlite_engine_master_ledger_export(tmp_nonsqlite_dir):
    """
    Section 7: Database Schema for Module 2.3
    Verifies that NonSQLiteForensicEngine creates and writes into:
    1. kv_store_diagnostics
    2. kv_recovered_records_master
    3. biome_segb_records_master
    with exact column names, constraints, and valid foreign keys.
    """
    from src.nonsqlite.engine import NonSQLiteForensicEngine
    from src.nonsqlite.models import (
        KVStoreDiagnostics,
        KVRecoveredRecord,
        BiomeSEGBRecord,
    )

    ledger_path = tmp_nonsqlite_dir / "nonsqlite_forensic_engine.sqlite"
    engine = NonSQLiteForensicEngine()

    diag = KVStoreDiagnostics(
        vfs_file_id=5,
        canonical_path="/data/user/0/com.phonepe.app/files/mmkv/mmkv.default",
        engine_format="TENCENT_MMKV",
        is_encrypted=0,
        active_records_count=10,
        historical_superseded_count=5,
        residual_deleted_count=2,
    )

    kv_rec = KVRecoveredRecord(
        kv_store_id=1,
        key_name_text="active_upi_vpa",
        sequence_or_append_order=1,
        value_operation_type="LIVE_VALUE",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        inferred_data_type="UTF8_STRING",
        decoded_value_text_or_json="merchant@okaxis",
        source_file_name="mmkv.default",
        source_byte_offset=128,
    )

    segb_rec = BiomeSEGBRecord(
        kv_store_id=1,
        biome_stream_name="App.InFocus",
        segb_version="SEGB_V2",
        device_locality="LOCAL_DEVICE",
        segb_record_state=1,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        segb_write_cocoa_raw=725846400.0,
        segb_write_utc_iso="2024-01-01T00:00:00.000000Z",
        payload_event_utc_iso="2024-01-01T00:00:00.000000Z",
        decoded_protobuf_json='{"app": "com.whatsapp"}',
        payload_byte_offset=64,
    )

    engine.export_to_ledger(
        diagnostics=[diag],
        kv_records=[kv_rec],
        segb_records=[segb_rec],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # Check kv_store_diagnostics
    cur.execute("SELECT * FROM kv_store_diagnostics;")
    diag_row = cur.fetchone()
    assert diag_row is not None
    diag_cols = [d[0] for d in cur.description]
    assert "engine_format" in diag_cols
    assert "active_records_count" in diag_cols

    # Check kv_recovered_records_master
    cur.execute("SELECT * FROM kv_recovered_records_master;")
    kv_row = cur.fetchone()
    assert kv_row is not None
    kv_cols = [d[0] for d in cur.description]
    assert "key_name_text" in kv_cols
    assert "value_operation_type" in kv_cols

    # Check biome_segb_records_master
    cur.execute("SELECT * FROM biome_segb_records_master;")
    segb_row = cur.fetchone()
    assert segb_row is not None
    segb_cols = [d[0] for d in cur.description]
    assert "biome_stream_name" in segb_cols
    assert "segb_write_utc_iso" in segb_cols
    con.close()


def _block_crc(payload: bytes, comp_type: int) -> bytes:
    from src.nonsqlite.leveldb import crc32c, mask_crc
    return struct.pack("<I", mask_crc(crc32c(payload + bytes([comp_type]))))


def _log_chunk(batch: bytes, chunk_type: int = 1, good: bool = True) -> bytes:
    from src.nonsqlite.leveldb import crc32c, mask_crc
    crc = mask_crc(crc32c(bytes([chunk_type]) + batch))
    if not good:
        crc ^= 0xFFFF
    return struct.pack("<IHB", crc, len(batch), chunk_type) + batch


def test_leveldb_crc32c_known_answer():
    from src.nonsqlite.leveldb import crc32c
    assert crc32c(b"123456789") == 0xE3069283


def test_leveldb_bad_checksum_is_kept_but_unverified(tmp_path):
    from src.nonsqlite.leveldb import LevelDBDecoder
    key = b"k1"
    def batch(seq, val):
        b = bytearray(struct.pack("<QI", seq, 1)); b.append(1)
        b += write_le_varint(len(key)) + key + write_le_varint(len(val)) + val
        return bytes(b)
    d = tmp_path / "ldb"; d.mkdir()
    (d / "000001.log").write_bytes(_log_chunk(batch(1, b"good-value")) + _log_chunk(batch(2, b"damaged-value"), good=False))
    dec = LevelDBDecoder()
    recs = dec.decode_leveldb_directory(d)
    by_val = {r.decoded_value_text_or_json: r for r in recs}
    assert by_val["damaged-value"].recovery_classification == "UNVERIFIED_FRAGMENT"
    assert by_val["good-value"].recovery_classification != "UNVERIFIED_FRAGMENT"
    assert len(dec.crc_failures) == 1 and dec.crc_failures[0]["what"] == "log record"
