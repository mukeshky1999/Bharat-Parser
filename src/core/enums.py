"""
Canonical Enums and Evidentiary State Models.
Complies with Section 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

from dataclasses import dataclass, field
from enum import Enum, unique


@unique
class ContainerType(str, Enum):
    """Supported forensic container and extraction types."""
    IOS_BACKUP_DIR = "IOS_BACKUP_DIR"
    UFED_PACKAGE_DIR = "UFED_PACKAGE_DIR"
    UNPACKED_FS_DIR = "UNPACKED_FS_DIR"
    ZIP_OR_UFDR = "ZIP_OR_UFDR"
    STANDARD_ZIP = "STANDARD_ZIP"
    CELLEBRITE_UFDR = "CELLEBRITE_UFDR"
    TAR_UNCOMPRESSED = "TAR_UNCOMPRESSED"
    TAR_GZ_COMPRESSED = "TAR_GZ_COMPRESSED"
    ANDROID_AB_BACKUP = "ANDROID_AB_BACKUP"
    ENCASE_E01_IMAGE = "ENCASE_E01_IMAGE"
    RAW_DISK_OR_APFS = "RAW_DISK_OR_APFS"
    UNKNOWN = "UNKNOWN"


@unique
class EntryType(str, Enum):
    """File-system entry classification."""
    REGULAR_FILE = "REGULAR_FILE"
    DIRECTORY = "DIRECTORY"
    SYMLINK = "SYMLINK"
    HARDLINK = "HARDLINK"


@unique
class CompressionMethod(str, Enum):
    """Archive payload compression method."""
    RAW_STORED = "RAW_STORED"
    ZIP_DEFLATE = "ZIP_DEFLATE"
    ZIP_ZSTD = "ZIP_ZSTD"
    TAR_GZ_STREAM = "TAR_GZ_STREAM"
    IOS_BACKUP_FILE = "IOS_BACKUP_FILE"
    ANDROID_AB_STREAM = "ANDROID_AB_STREAM"
    E01_CHUNK = "E01_CHUNK"


@unique
class EvidentiaryExistence(str, Enum):
    """Dim A (Existence): Observed vs Absent vs Scoped Extraction Limit."""
    OBSERVED = "OBSERVED"
    ABSENT = "ABSENT"
    NOT_OBSERVED = "NOT_OBSERVED"


@unique
class EvidentiaryAccess(str, Enum):
    """Dim B (Access/Encryption): Plaintext vs Decrypted vs Encrypted vs Corrupt."""
    PLAINTEXT = "PLAINTEXT"
    DECRYPTED = "DECRYPTED"
    ENCRYPTED_GATED = "ENCRYPTED_GATED"
    CORRUPTED = "CORRUPTED"


@unique
class EvidentiaryStorage(str, Enum):
    """Dim C (Storage Layer): Physical storage medium location."""
    LIVE_RECORD = "LIVE_RECORD"
    WAL_OR_JOURNAL = "WAL_OR_JOURNAL"
    FREELIST_OR_UNALLOCATED = "FREELIST_OR_UNALLOCATED"
    MMKV_OR_SLACK = "MMKV_OR_SLACK"
    VISUAL_OR_NOTIFICATION_RESIDUAL = "VISUAL_OR_NOTIFICATION_RESIDUAL"


@unique
class ResidualConfidence(str, Enum):
    """Section 4.4: 6-Tier Residual Recovery Confidence Classification."""
    ORIGINAL_RECORD = "ORIGINAL_RECORD"
    HISTORICAL_COMMITTED_RECORD = "HISTORICAL_COMMITTED_RECORD"
    RESIDUAL_RECORD = "RESIDUAL_RECORD"
    PARTIAL_RECORD = "PARTIAL_RECORD"
    RECONSTRUCTED_RECORD = "RECONSTRUCTED_RECORD"
    UNVERIFIED_FRAGMENT = "UNVERIFIED_FRAGMENT"


@unique
class FinancialTransactionStatus(str, Enum):
    """Section 4.5: 7-Tier Financial & UPI Transaction State Classification."""
    INITIATED = "INITIATED"
    AUTHORIZED = "AUTHORIZED"
    PENDING = "PENDING"
    SETTLED = "SETTLED"
    FAILED = "FAILED"
    REVERSED = "REVERSED"
    COLLECT_REQUEST_SCAM = "COLLECT_REQUEST_SCAM"


@unique
class C2PAValidationState(str, Enum):
    """Section 4.6: 6-Tier C2PA Content Credentials Validation Hierarchy."""
    MANIFEST_ABSENT = "MANIFEST_ABSENT"
    PRESENT_UNVALIDATED = "PRESENT_UNVALIDATED"
    WELL_FORMED = "WELL_FORMED"
    VALID = "VALID"
    TRUSTED = "TRUSTED"
    INVALID = "INVALID"


@unique
class ForensicGroup(str, Enum):
    """Section 4.8: Canonical 18 Forensic Groups Registry."""
    G01_INGESTION_AND_OWNERSHIP = "G01_INGESTION_AND_OWNERSHIP"
    G02_UPI_AND_WALLETS = "G02_UPI_AND_WALLETS"
    G03_DOMESTIC_AND_CORP_BANKING = "G03_DOMESTIC_AND_CORP_BANKING"
    G04_FINANCIAL_SMS_AND_NOTIFICATIONS = "G04_FINANCIAL_SMS_AND_NOTIFICATIONS"
    G05_CRYPTO_SELF_CUSTODY_WALLETS = "G05_CRYPTO_SELF_CUSTODY_WALLETS"
    G06_CRYPTO_EXCHANGES_AND_SEEDS = "G06_CRYPTO_EXCHANGES_AND_SEEDS"
    G07_MAINSTREAM_AND_MODDED_CHATS = "G07_MAINSTREAM_AND_MODDED_CHATS"
    G08_HIGH_OPSEC_CRIMINAL_CHATS = "G08_HIGH_OPSEC_CRIMINAL_CHATS"
    G09_VOIP_REGIONAL_AND_COVERT_CHATS = "G09_VOIP_REGIONAL_AND_COVERT_CHATS"
    G10_CALL_LOGS_AND_CONTACTS = "G10_CALL_LOGS_AND_CONTACTS"
    G11_WEBVIEW_AND_BROWSER_SANDBOXES = "G11_WEBVIEW_AND_BROWSER_SANDBOXES"
    G12_OS_GEOLOCATION_AND_TIMELINE = "G12_OS_GEOLOCATION_AND_TIMELINE"
    G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL = "G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL"
    G14_NETWORK_WIFI_BT_AND_DATAUSAGE = "G14_NETWORK_WIFI_BT_AND_DATAUSAGE"
    G15_OS_BEHAVIORAL_TELEMETRY = "G15_OS_BEHAVIORAL_TELEMETRY"
    G16_SECURITY_KEYCHAIN_AND_TAMPER = "G16_SECURITY_KEYCHAIN_AND_TAMPER"
    G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS = "G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS"
    G18_DOCUMENTS_APKS_AND_OCR_INDEX = "G18_DOCUMENTS_APKS_AND_OCR_INDEX"


@dataclass(slots=True)
class EvidentiaryState:
    """Section 4.3: 5D Evidentiary State Matrix Contract."""
    existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    storage_layer: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    provenance_pointer: str = ""
    corroboration_score: float = 0.0
    linked_artifact_ids: list[str] = field(default_factory=list)
    forensic_group: ForensicGroup = ForensicGroup.G01_INGESTION_AND_OWNERSHIP
