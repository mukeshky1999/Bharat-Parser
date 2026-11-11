"""
Cryptographic Credential Harvester for iOS Keychain and Android Keystore.
Adheres strictly to Specification Section 3 and Section 4.
"""

import base64
import json
import logging
import plistlib
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.crypto.models import (
    KeyAccessibility,
    KeyFormatType,
    KeyringEntry,
    KeySourceCategory,
)

logger = logging.getLogger(__name__)


class CredentialHarvester:
    """Harvests cryptographic credentials from iOS Keychain and Android Keystore stores."""

    def __init__(self, uid_to_pkg_map: Optional[Dict[int, str]] = None):
        self.uid_to_pkg_map = uid_to_pkg_map or {}

    def register_uid_package_mapping(self, uid: int, package_name: str) -> None:
        """Registers Linux UID to Android Package Name mapping from Module 1.3."""
        self.uid_to_pkg_map[uid] = package_name

    def harvest_ios_keychain_plist(
        self,
        plist_path: Union[str, Path],
        app_instance_id: Optional[int] = None
    ) -> List[KeyringEntry]:
        """
        Parses pre-decrypted iOS Keychain plist/XML from vendor FFS extractions (GrayKey, Cellebrite).
        """
        p_path = Path(plist_path)
        if not p_path.exists():
            return []

        entries: List[KeyringEntry] = []
        try:
            with open(p_path, "rb") as f:
                data = plistlib.load(f)

            items_list = data if isinstance(data, list) else data.get("items", [])
            for item in items_list:
                if not isinstance(item, dict):
                    continue

                agrp = item.get("agrp")
                svce = item.get("svce")
                acct = item.get("acct")
                pdmn = item.get("pdmn")
                raw_val = item.get("v_Data") or item.get("data")

                unwrapped_hex = None
                key_fmt = KeyFormatType.RAW_AES_256_HEX_64.value

                if isinstance(raw_val, bytes):
                    unwrapped_hex = raw_val.hex().lower()
                    if len(raw_val) == 48:
                        key_fmt = KeyFormatType.RAW_KEY_AND_SALT_HEX_96.value
                    elif len(raw_val) == 32:
                        key_fmt = KeyFormatType.RAW_AES_256_HEX_64.value
                elif isinstance(raw_val, str):
                    unwrapped_hex = raw_val.lower()

                entries.append(
                    KeyringEntry(
                        source_category=KeySourceCategory.IOS_VENDOR_KEYCHAIN_EXPORT.value,
                        app_instance_id=app_instance_id,
                        access_group_or_pkg=agrp,
                        service_or_alias=svce,
                        account_name=acct,
                        protection_class_domain=pdmn,
                        key_accessibility=KeyAccessibility.UNWRAPPED_READY.value,
                        key_format_type=key_fmt,
                        unwrapped_key_hex=unwrapped_hex,
                    )
                )
        except Exception as exc:
            logger.debug("Failed parsing iOS Keychain plist %s: %s", plist_path, exc)

        return entries

    def harvest_android_shared_prefs_xml(
        self,
        xml_path: Union[str, Path],
        package_name: str,
        app_instance_id: Optional[int] = None
    ) -> List[KeyringEntry]:
        """
        Scans Android shared_prefs XML files for embedded keys, encrypted JSON secrets,
        or Jetpack EncryptedSharedPreferences keysets.
        """
        x_path = Path(xml_path)
        if not x_path.exists():
            return []

        entries: List[KeyringEntry] = []
        try:
            tree = ET.parse(x_path)
            root = tree.getroot()

            for elem in root:
                name = elem.attrib.get("name", "")
                text_val = elem.text or ""

                if "database_encrypted_secret" in name or "SignalSecret" in name:
                    # JSON object: {"data": "...", "iv": "..."}
                    entries.append(
                        KeyringEntry(
                            source_category=KeySourceCategory.ANDROID_SHARED_PREFS.value,
                            app_instance_id=app_instance_id,
                            access_group_or_pkg=package_name,
                            service_or_alias=name,
                            protection_class_domain="TEE_STRONG_BOX",
                            key_accessibility=KeyAccessibility.WRAPPED_NEEDS_USER_PASSWORD.value,
                            key_format_type=KeyFormatType.AES_GCM_JSON_BLOB.value,
                            unwrapped_key_hex=None,
                        )
                    )
                elif "pref_database_unencrypted_secret" in name:
                    entries.append(
                        KeyringEntry(
                            source_category=KeySourceCategory.ANDROID_SHARED_PREFS.value,
                            app_instance_id=app_instance_id,
                            access_group_or_pkg=package_name,
                            service_or_alias=name,
                            protection_class_domain="PLAINTEXT_SANDBOX",
                            key_accessibility=KeyAccessibility.UNWRAPPED_READY.value,
                            key_format_type=KeyFormatType.RAW_AES_256_HEX_64.value,
                            unwrapped_key_hex=text_val.strip().lower(),
                        )
                    )
        except Exception as exc:
            logger.debug("Failed parsing shared_prefs XML %s: %s", xml_path, exc)

        return entries

    def harvest_android_keystore_2_db(
        self,
        persistent_sqlite_path: Union[str, Path]
    ) -> List[KeyringEntry]:
        """
        Parses Android Keystore 2.0 persistent.sqlite database.
        Maps namespace UIDs to Android packages and records hardware-bound keys.
        """
        db_path = Path(persistent_sqlite_path)
        if not db_path.exists():
            return []

        entries: List[KeyringEntry] = []
        try:
            con = sqlite3.connect(db_path)
            cur = con.cursor()
            cur.execute("SELECT id, key_type, namespace, alias FROM keyentry;")
            rows = cur.fetchall()

            for row in rows:
                key_id, key_type, namespace, alias = row
                pkg_name = self.uid_to_pkg_map.get(namespace, f"uid_{namespace}")

                entries.append(
                    KeyringEntry(
                        source_category=KeySourceCategory.ANDROID_KEYSTORE_2_DB.value,
                        access_group_or_pkg=pkg_name,
                        service_or_alias=alias,
                        account_name=str(key_type),
                        protection_class_domain="TEE_STRONG_BOX",
                        key_accessibility=KeyAccessibility.HARDWARE_BOUND_UNAVAILABLE.value,
                        key_format_type=KeyFormatType.OPAQUE_HARDWARE_BLOB.value,
                        unwrapped_key_hex=None,
                    )
                )
            con.close()
        except Exception as exc:
            logger.debug("Failed parsing Android Keystore DB %s: %s", persistent_sqlite_path, exc)

        return entries
