"""
Data models and canonical enums for Phase 8, Module 8.2:
Zero-Omission Accounting, Entropy Analysis, Fallback Introspector, and Dual FTS5 Search.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AccountingState(str, Enum):
    """The 4 Mandatory VFS Accounting States enforcing zero silent omission."""
    STATE_1_PARSED_AND_VERIFIED = "STATE_1_PARSED_AND_VERIFIED"
    STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED = "STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED"
    STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE = "STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE"
    STATE_4_UNK_UNPARSED_USER_ARTIFACT = "STATE_4_UNK_UNPARSED_USER_ARTIFACT"


class DetectedMagicSignature(str, Enum):
    """Master binary magic signatures for discrepancy detection."""
    SQLITE_3_DATABASE = "SQLITE_3_DATABASE"
    SQLITE_WAL_JOURNAL = "SQLITE_WAL_JOURNAL"
    APPLE_BINARY_PLIST = "APPLE_BINARY_PLIST"
    ANDROID_BINARY_XML_ABX = "ANDROID_BINARY_XML_ABX"
    APPLE_BIOME_SEGB = "APPLE_BIOME_SEGB"
    LEVELDB_SSTABLE_LDB = "LEVELDB_SSTABLE_LDB"
    JAVA_DALVIK_DEX = "JAVA_DALVIK_DEX"
    ELF_EXECUTABLE_OR_SO = "ELF_EXECUTABLE_OR_SO"
    ZIP_APK_JAR_DOCX_XLSX = "ZIP_APK_JAR_DOCX_XLSX"
    RAR_OR_7ZIP_ARCHIVE = "RAR_OR_7ZIP_ARCHIVE"
    GZIP_ZSTD_LZ4_BZIP2 = "GZIP_ZSTD_LZ4_BZIP2"
    PDF_DOCUMENT = "PDF_DOCUMENT"
    JPEG_PNG_WEBP_HEIC_GIF = "JPEG_PNG_WEBP_HEIC_GIF"
    KTX_GPU_TEXTURE = "KTX_GPU_TEXTURE"
    WHATSAPP_CRYPT_BACKUP = "WHATSAPP_CRYPT_BACKUP"
    LUKS_OR_VERACRYPT_HEADER = "LUKS_OR_VERACRYPT_HEADER"
    OPENPGP_OR_AGE_ARMOR = "OPENPGP_OR_AGE_ARMOR"
    PKCS12_OR_PEM_PRIVATE_KEY = "PKCS12_OR_PEM_PRIVATE_KEY"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    EMPTY_FILE = "EMPTY_FILE"


class EntropyCryptoClassification(str, Enum):
    """Statistical classification of binary payload randomness."""
    UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB = "UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB"
    HIGH_ENTROPY_ENCRYPTED_BLOB_OR_CONTAINER = "HIGH_ENTROPY_ENCRYPTED_BLOB_OR_CONTAINER"
    COMPRESSED_OR_PROPRIETARY_BINARY_STREAM = "COMPRESSED_OR_PROPRIETARY_BINARY_STREAM"
    LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED = "LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED"


class ContainerStructureType(str, Enum):
    """Container structure classification for introspected UNK files."""
    UNK_SQLITE_ACTIVE_ROW = "UNK_SQLITE_ACTIVE_ROW"
    UNK_SQLITE_WAL_OR_FREELIST_ROW = "UNK_SQLITE_WAL_OR_FREELIST_ROW"
    UNK_JSON_OR_XML_NODE = "UNK_JSON_OR_XML_NODE"
    UNK_MMKV_OR_LEVELDB_KV = "UNK_MMKV_OR_LEVELDB_KV"
    UNK_PROTOBUF_TREE = "UNK_PROTOBUF_TREE"
    UNK_CARVED_UTF8_UTF16_STRING = "UNK_CARVED_UTF8_UTF16_STRING"


class DetectedIndicatorCategory(str, Enum):
    """10-Indicator forensic sweeper category tags."""
    GENERIC_TIMESTAMPED_MESSAGE_OR_RECORD = "GENERIC_TIMESTAMPED_MESSAGE_OR_RECORD"
    VALIDATED_UPI_UTR_12_DIGIT = "VALIDATED_UPI_UTR_12_DIGIT"
    VALIDATED_UPI_VPA = "VALIDATED_UPI_VPA"
    VALIDATED_IFSC_AND_BANK = "VALIDATED_IFSC_AND_BANK"
    VALIDATED_CRYPTO_ADDRESS = "VALIDATED_CRYPTO_ADDRESS"
    VALIDATED_BIP39_OR_XMR_SEED = "VALIDATED_BIP39_OR_XMR_SEED"
    VALIDATED_PAN_AADHAAR_GSTIN = "VALIDATED_PAN_AADHAAR_GSTIN"
    PHONE_NUMBER_E164 = "PHONE_NUMBER_E164"
    OPSEC_HANDLE_OR_C2_URL = "OPSEC_HANDLE_OR_C2_URL"
    WGS84_GPS_COORDINATE_PAIR = "WGS84_GPS_COORDINATE_PAIR"


class ResidualRecoveryConfidence(str, Enum):
    """6-Tier Residual Recovery Confidence Classification."""
    ORIGINAL_RECORD = "ORIGINAL_RECORD"
    HISTORICAL_COMMITTED_RECORD = "HISTORICAL_COMMITTED_RECORD"
    RESIDUAL_RECORD = "RESIDUAL_RECORD"
    PARTIAL_RECORD = "PARTIAL_RECORD"
    RECONSTRUCTED_RECORD = "RECONSTRUCTED_RECORD"
    UNVERIFIED_FRAGMENT = "UNVERIFIED_FRAGMENT"


@dataclass
class MagicInspectionResult:
    """Outcome of binary magic header discrepancy inspection."""
    detected_magic_signature: str
    is_extension_spoofed_mismatch: int
    raw_magic_hex: str


@dataclass
class EntropyAnalysisResult:
    """Outcome of Shannon entropy and Chi-Square uniformity evaluation."""
    shannon_entropy_bits: float
    chi_square_uniformity_score: float
    classification: EntropyCryptoClassification


@dataclass
class VfsAccountingRecord:
    """100% VFS File Accounting Record for Table 1."""
    vfs_file_id: int
    canonical_vfs_path: str
    owning_app_package_or_domain: Optional[str] = None
    file_byte_size: int = 0
    accounting_state: AccountingState = AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT
    consumed_by_modules_json: Optional[str] = "[]"
    extracted_records_count: int = 0
    filename_extension: Optional[str] = None
    detected_magic_signature: str = DetectedMagicSignature.UNKNOWN_BINARY.value
    is_extension_spoofed_mismatch: int = 0
    shannon_entropy_bits: Optional[float] = None
    chi_square_uniformity_score: Optional[float] = None
    entropy_crypto_classification: Optional[str] = None
    unk_introspection_hit_count: int = 0


@dataclass
class UnkGenericFinding:
    """Evidence extracted from unrecognized apps and STATE_4_UNK files for Table 2."""
    vfs_file_id: int
    owning_app_package: str
    container_structure_type: ContainerStructureType
    table_or_object_path: str
    detected_indicator_category: DetectedIndicatorCategory
    extracted_indicator_value: str
    full_row_or_context_json: str
    unk_finding_uid: Optional[int] = None
    inferred_timestamp_utc_iso: Optional[str] = None
    recovery_classification: ResidualRecoveryConfidence = ResidualRecoveryConfidence.ORIGINAL_RECORD


@dataclass
class SearchDocument:
    """Unified document representation for master search catalog Table 3."""
    originating_phase_module: str
    artifact_domain: str
    source_record_pointer: str
    recovery_classification: str
    doc_uid: Optional[int] = None
    timeline_event_uid: Optional[int] = None
    app_package: Optional[str] = None
    source_vfs_file_id: Optional[int] = None
    timestamp_utc_ns: Optional[int] = None
    actor_names_and_handles_nfc: str = ""
    searchable_body_text_nfc: str = ""


@dataclass
class RoaringFacetEntry:
    """Pre-computed 32-bit Roaring Bitmap facet record for Table 4."""
    target_table_scope: str
    facet_dimension_name: str
    facet_value_key: str
    total_matching_cardinality: int
    serialized_roaring_bitmap_blob: bytes
    facet_bitmap_uid: Optional[int] = None
