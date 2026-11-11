"""
Cryptographic Key Broker & Database Unwrapper Package.
Phase 2, Module 2.2 of Forensic Data Parser.
"""

from src.crypto.engine import CryptographicKeyBrokerEngine
from src.crypto.models import (
    KeyringEntry,
    EncryptedDatabaseEntry,
    KeySourceCategory,
    KeyAccessibility,
    KeyFormatType,
    EncryptionScheme,
    DecryptionStatus,
)
from src.crypto.sqlcipher import SQLCipherDecryptor, SQLCipherProfile, STANDARD_PROFILES
from src.crypto.whatsapp import derive_crypt15_key, decrypt_crypt15_backup, decrypt_crypt12_or_crypt14_backup
from src.crypto.wcdb import derive_wcdb_password, get_candidate_wcdb_passwords
from src.crypto.applenotes import decrypt_apple_notes_body
from src.crypto.keyring import CredentialHarvester

__all__ = [
    "CryptographicKeyBrokerEngine",
    "KeyringEntry",
    "EncryptedDatabaseEntry",
    "KeySourceCategory",
    "KeyAccessibility",
    "KeyFormatType",
    "EncryptionScheme",
    "DecryptionStatus",
    "SQLCipherDecryptor",
    "SQLCipherProfile",
    "STANDARD_PROFILES",
    "derive_crypt15_key",
    "decrypt_crypt15_backup",
    "decrypt_crypt12_or_crypt14_backup",
    "derive_wcdb_password",
    "get_candidate_wcdb_passwords",
    "decrypt_apple_notes_body",
    "CredentialHarvester",
]
