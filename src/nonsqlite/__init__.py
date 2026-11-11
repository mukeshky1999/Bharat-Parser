"""
Non-SQLite Binary Storage Engine Decoders:
Tencent MMKV, Google LevelDB / Chromium IndexedDB, Apple Biome SEGB v1/v2,
and Schema-Less Raw Wire-Format Protocol Buffers.
"""

from src.nonsqlite.engine import NonSQLiteForensicEngine
from src.nonsqlite.leveldb import LevelDBDecoder
from src.nonsqlite.mmkv import MMKVDecoder
from src.nonsqlite.models import (
    BiomeSEGBRecord,
    EngineFormat,
    InferredDataType,
    KVRecoveredRecord,
    KVStoreDiagnostics,
    SEGBVersion,
    ValueOperationType,
)
from src.nonsqlite.protobuf import decode_raw_protobuf
from src.nonsqlite.segb import SEGBDecoder
from src.nonsqlite.snappy import snappy_decompress_raw
from src.nonsqlite.varint import (
    decode_le_varint,
    decode_zigzag_64,
    encode_le_varint,
    encode_zigzag_64,
)

__all__ = [
    "EngineFormat",
    "ValueOperationType",
    "InferredDataType",
    "SEGBVersion",
    "KVStoreDiagnostics",
    "KVRecoveredRecord",
    "BiomeSEGBRecord",
    "decode_le_varint",
    "encode_le_varint",
    "decode_zigzag_64",
    "encode_zigzag_64",
    "snappy_decompress_raw",
    "decode_raw_protobuf",
    "MMKVDecoder",
    "LevelDBDecoder",
    "SEGBDecoder",
    "NonSQLiteForensicEngine",
]
