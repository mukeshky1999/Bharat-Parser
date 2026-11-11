"""
Domain models and Canonical Enums for the Cryptographic Key Broker.
Adheres strictly to Specification Section 7 and AGENTS.md Forensic Invariants.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional


@unique
class KeySourceCategory(str, Enum):
    """Origin of harvested cryptographic key material."""
    IOS_VENDOR_KEYCHAIN_EXPORT = "IOS_VENDOR_KEYCHAIN_EXPORT"
    IOS_BACKUP_KEYCHAIN_PLIST = "IOS_BACKUP_KEYCHAIN_PLIST"
    IOS_RAW_KEYCHAIN_DB = "IOS_RAW_KEYCHAIN_DB"
    ANDROID_SANDBOX_KEY_FILE = "ANDROID_SANDBOX_KEY_FILE"
    ANDROID_SHARED_PREFS = "ANDROID_SHARED_PREFS"
    ANDROID_KEYSTORE_2_DB = "ANDROID_KEYSTORE_2_DB"
    DERIVED_FORMULA = "DERIVED_FORMULA"
    EXAMINER_SUPPLIED = "EXAMINER_SUPPLIED"


@unique
class KeyAccessibility(str, Enum):
    """Accessibility and unwrapped state of harvested key."""
    UNWRAPPED_READY = "UNWRAPPED_READY"
    WRAPPED_NEEDS_USER_PASSWORD = "WRAPPED_NEEDS_USER_PASSWORD"
    HARDWARE_BOUND_UNAVAILABLE = "HARDWARE_BOUND_UNAVAILABLE"


@unique
class KeyFormatType(str, Enum):
    """Format and byte representation of harvested key."""
    RAW_AES_256_HEX_64 = "RAW_AES_256_HEX_64"
    RAW_KEY_AND_SALT_HEX_96 = "RAW_KEY_AND_SALT_HEX_96"
    PASSPHRASE_UTF8 = "PASSPHRASE_UTF8"
    AES_GCM_JSON_BLOB = "AES_GCM_JSON_BLOB"
    TINK_KEYSET = "TINK_KEYSET"
    OPAQUE_HARDWARE_BLOB = "OPAQUE_HARDWARE_BLOB"


@unique
class EncryptionScheme(str, Enum):
    """Detected cryptographic scheme for database or storage container."""
    SQLCIPHER_V4 = "SQLCIPHER_V4"
    SQLCIPHER_V3 = "SQLCIPHER_V3"
    TENCENT_WCDB = "TENCENT_WCDB"
    WHATSAPP_CRYPT14 = "WHATSAPP_CRYPT14"
    WHATSAPP_CRYPT15 = "WHATSAPP_CRYPT15"
    JETPACK_TINK_XML = "JETPACK_TINK_XML"
    REALM_ENCRYPTED = "REALM_ENCRYPTED"
    UNKNOWN_HIGH_ENTROPY = "UNKNOWN_HIGH_ENTROPY"


@unique
class DecryptionStatus(str, Enum):
    """Decryption outcome for an encrypted database."""
    DECRYPTED_VERIFIED = "DECRYPTED_VERIFIED"
    AWAITING_EXAMINER_KEY = "AWAITING_EXAMINER_KEY"
    BLOCKED_BY_HARDWARE_TEE_SEP = "BLOCKED_BY_HARDWARE_TEE_SEP"
    DECRYPTION_FAILED_BAD_KEY = "DECRYPTION_FAILED_BAD_KEY"


@dataclass(slots=True)
class KeyringEntry:
    """Represents a harvested cryptographic credential in case_cryptographic_keyring."""
    source_category: str
    app_instance_id: Optional[int] = None
    access_group_or_pkg: Optional[str] = None
    service_or_alias: Optional[str] = None
    account_name: Optional[str] = None
    protection_class_domain: Optional[str] = None
    key_accessibility: str = KeyAccessibility.UNWRAPPED_READY.value
    key_format_type: str = KeyFormatType.RAW_AES_256_HEX_64.value
    unwrapped_key_hex: Optional[str] = None
    created_utc_iso: Optional[str] = None
    modified_utc_iso: Optional[str] = None
    key_id: Optional[int] = None


@dataclass(slots=True)
class EncryptedDatabaseEntry:
    """Represents an encrypted database record in encrypted_database_registry."""
    vfs_file_id: int
    canonical_path: str
    encryption_scheme: str
    decryption_status: str
    app_instance_id: Optional[int] = None
    matched_key_id: Optional[int] = None
    derivative_staging_id: Optional[int] = None
    decrypted_wal_frames: int = 0
    enc_target_id: Optional[int] = None
