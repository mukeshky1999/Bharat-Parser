"""
Domain Models and Enums for Non-SQLite Binary Storage Engines.
Adheres strictly to Specification Section 7 and AGENTS.md Forensic Invariants.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class EngineFormat(str, Enum):
    """Storage engine format classification."""
    TENCENT_MMKV = "TENCENT_MMKV"
    GOOGLE_LEVELDB = "GOOGLE_LEVELDB"
    CHROMIUM_INDEXEDDB = "CHROMIUM_INDEXEDDB"
    APPLE_SEGB_V1 = "APPLE_SEGB_V1"
    APPLE_SEGB_V2 = "APPLE_SEGB_V2"
    RAW_PROTOBUF_FILE = "RAW_PROTOBUF_FILE"


@unique
class ValueOperationType(str, Enum):
    """Key-value state and historical operation type."""
    LIVE_VALUE = "LIVE_VALUE"
    SUPERSEDED_OVERWRITTEN_VALUE = "SUPERSEDED_OVERWRITTEN_VALUE"
    EXPLICIT_DELETION_TOMBSTONE = "EXPLICIT_DELETION_TOMBSTONE"
    CARVED_SLACK_VALUE = "CARVED_SLACK_VALUE"


@unique
class InferredDataType(str, Enum):
    """Inferred data type of decoded value payload."""
    UTF8_STRING = "UTF8_STRING"
    JSON_OBJECT = "JSON_OBJECT"
    NESTED_PROTOBUF = "NESTED_PROTOBUF"
    VARINT_INTEGER = "VARINT_INTEGER"
    FLOAT_DOUBLE = "FLOAT_DOUBLE"
    V8_SERIALIZED_OBJECT = "V8_SERIALIZED_OBJECT"
    RAW_BYTES_HEX = "RAW_BYTES_HEX"
    TOMBSTONE_NULL = "TOMBSTONE_NULL"


@unique
class SEGBVersion(str, Enum):
    """Apple Biome SEGB format version."""
    SEGB_V1 = "SEGB_V1"
    SEGB_V2 = "SEGB_V2"


@dataclass(slots=True)
class KVStoreDiagnostics:
    """Diagnostic profile for a processed non-SQLite storage file or directory."""
    vfs_file_id: int
    canonical_path: str
    engine_format: str
    is_encrypted: int = 0
    active_records_count: int = 0
    historical_superseded_count: int = 0
    residual_deleted_count: int = 0
    app_instance_id: Optional[int] = None
    kv_store_id: Optional[int] = None


@dataclass(slots=True)
class KVRecoveredRecord:
    """Represents a record extracted from MMKV, LevelDB, or Chromium IndexedDB."""
    kv_store_id: int
    key_name_text: str
    sequence_or_append_order: int
    value_operation_type: str
    recovery_classification: ResidualConfidence
    inferred_data_type: str
    decoded_value_text_or_json: Optional[str]
    source_file_name: str
    source_byte_offset: int
    kv_record_uid: Optional[int] = None


@dataclass(slots=True)
class BiomeSEGBRecord:
    """Represents an extracted Apple Biome SEGB v1 or v2 record."""
    kv_store_id: int
    biome_stream_name: str
    segb_version: str
    device_locality: str
    segb_record_state: int
    recovery_classification: ResidualConfidence
    segb_write_cocoa_raw: float
    segb_write_utc_iso: str
    payload_byte_offset: int
    payload_event_utc_iso: Optional[str] = None
    decoded_protobuf_json: Optional[str] = None
    segb_record_uid: Optional[int] = None
