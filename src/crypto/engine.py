"""
Master Cryptographic Key Broker & Database Unwrapper Engine.
Adheres strictly to Specification Section 1 through Section 7.
"""

import logging
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from src.crypto.keyring import CredentialHarvester
from src.crypto.models import (
    DecryptionStatus,
    EncryptedDatabaseEntry,
    EncryptionScheme,
    KeyAccessibility,
    KeyFormatType,
    KeyringEntry,
    KeySourceCategory,
)
from src.crypto.sqlcipher import SQLCipherDecryptor, SQLCipherProfile
from src.crypto.whatsapp import (
    decrypt_crypt12_or_crypt14_backup,
    decrypt_crypt15_backup,
    derive_crypt15_key,
)
from src.crypto.wcdb import derive_wcdb_password, get_candidate_wcdb_passwords
from src.evidentiary.enums import DimensionBAccessibility

logger = logging.getLogger(__name__)


class CryptographicKeyBrokerEngine:
    """Coordinates credential harvesting, key-matching, and automated database unwrapping."""

    def __init__(self):
        self.harvester = CredentialHarvester()
        self.keyring: List[KeyringEntry] = []
        self.encrypted_targets: List[EncryptedDatabaseEntry] = []
        self.sqlcipher_decryptor = SQLCipherDecryptor()

    def register_uid_package_mapping(self, uid: int, package_name: str) -> None:
        """Registers Linux UID to Package Name mapping from Module 1.3."""
        self.harvester.register_uid_package_mapping(uid, package_name)

    def harvest_android_keystore_database(
        self,
        persistent_sqlite_path: Union[str, Path]
    ) -> List[KeyringEntry]:
        """Harvests hardware-bound keys from Android Keystore 2.0 persistent.sqlite."""
        entries = self.harvester.harvest_android_keystore_2_db(persistent_sqlite_path)
        self.keyring.extend(entries)
        return entries

    def evaluate_dimension_b(
        self,
        package_name: str,
        target_path: str
    ) -> DimensionBAccessibility:
        """
        Evaluates 5D Matrix Dimension B (Access / Encryption) state for an application target.
        If the app's key is bound by Android TEE/StrongBox or iOS SEP without an unwrapped export,
        it evaluates to ENCRYPTED_GATED_BY_HARDWARE.
        """
        for k in self.keyring:
            if k.access_group_or_pkg == package_name:
                if k.key_accessibility == KeyAccessibility.HARDWARE_BOUND_UNAVAILABLE.value:
                    return DimensionBAccessibility.ENCRYPTED_GATED_BY_HARDWARE
                elif k.key_accessibility == KeyAccessibility.WRAPPED_NEEDS_USER_PASSWORD.value:
                    return DimensionBAccessibility.ENCRYPTED_GATED_BY_PIN_OR_PASS

        return DimensionBAccessibility.PLAINTEXT

    def export_to_ledger(
        self,
        keyring_entries: List[KeyringEntry],
        db_entries: List[EncryptedDatabaseEntry],
        ledger_path: Union[str, Path]
    ) -> None:
        """
        Creates and writes the cryptographic audit trail into case_cryptographic_keyring
        and encrypted_database_registry tables.
        """
        out_path = Path(ledger_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(out_path)
        cur = con.cursor()

        # Schema Table 1: case_cryptographic_keyring
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS case_cryptographic_keyring (
                key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_category TEXT NOT NULL,
                app_instance_id INTEGER NULL,
                access_group_or_pkg TEXT NULL,
                service_or_alias TEXT NULL,
                account_name TEXT NULL,
                protection_class_domain TEXT NULL,
                key_accessibility TEXT NOT NULL,
                key_format_type TEXT NOT NULL,
                unwrapped_key_hex TEXT NULL,
                created_utc_iso TEXT NULL,
                modified_utc_iso TEXT NULL
            );
            """
        )

        # Schema Table 2: encrypted_database_registry
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS encrypted_database_registry (
                enc_target_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vfs_file_id INTEGER NOT NULL,
                app_instance_id INTEGER NULL,
                canonical_path TEXT NOT NULL,
                encryption_scheme TEXT NOT NULL,
                matched_key_id INTEGER NULL,
                decryption_status TEXT NOT NULL,
                derivative_staging_id INTEGER NULL,
                decrypted_wal_frames INTEGER DEFAULT 0,
                FOREIGN KEY (matched_key_id) REFERENCES case_cryptographic_keyring (key_id)
            );
            """
        )

        # Insert Keyring Entries
        for k in keyring_entries:
            cur.execute(
                """
                INSERT INTO case_cryptographic_keyring (
                    source_category, app_instance_id, access_group_or_pkg,
                    service_or_alias, account_name, protection_class_domain,
                    key_accessibility, key_format_type, unwrapped_key_hex,
                    created_utc_iso, modified_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    k.source_category,
                    k.app_instance_id,
                    k.access_group_or_pkg,
                    k.service_or_alias,
                    k.account_name,
                    k.protection_class_domain,
                    k.key_accessibility,
                    k.key_format_type,
                    k.unwrapped_key_hex,
                    k.created_utc_iso,
                    k.modified_utc_iso,
                ),
            )
            k.key_id = cur.lastrowid

        # Insert Database Entries
        for d in db_entries:
            cur.execute(
                """
                INSERT INTO encrypted_database_registry (
                    vfs_file_id, app_instance_id, canonical_path,
                    encryption_scheme, matched_key_id, decryption_status,
                    derivative_staging_id, decrypted_wal_frames
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    d.vfs_file_id,
                    d.app_instance_id,
                    d.canonical_path,
                    d.encryption_scheme,
                    d.matched_key_id,
                    d.decryption_status,
                    d.derivative_staging_id,
                    d.decrypted_wal_frames,
                ),
            )
            d.enc_target_id = cur.lastrowid

        con.commit()
        con.close()
