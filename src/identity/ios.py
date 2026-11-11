"""
iOS Container Scanner, Shared App Group Linker, and Bundle Resolver.
Phase 1, Module 1.3, Section 3.
"""

import logging
import plistlib
import re
from pathlib import Path
from typing import Optional, Dict, Any

from src.identity.catalog import IdentitySandboxCatalog

logger = logging.getLogger(__name__)


class IOSIdentityResolver:
    """Scans the 5 iOS container roots and binds Shared App Groups back to parent applications."""

    # Built-in forensic dictionary for top shared app groups
    KNOWN_APP_GROUPS = {
        "group.net.whatsapp.WhatsApp.shared": "net.whatsapp.WhatsApp",
        "group.net.whatsapp.WhatsAppSMB.shared": "net.whatsapp.WhatsAppSMB",
        "group.org.whispersystems.signal.group": "org.whispersystems.signal",
        "group.org.telegram.messenger": "ph.telegra.Telegraph",
        "group.ph.telegra.Telegraph": "ph.telegra.Telegraph",
        "group.com.phonepe.PhonePeApp": "com.phonepe.PhonePeApp",
        "group.net.one97.paytm": "net.one97.paytm",
        "group.com.google.chrome.ios": "com.google.chrome.ios",
        "group.io.metamask.MetaMask": "io.metamask.MetaMask",
    }

    def __init__(self, catalog: IdentitySandboxCatalog):
        self.catalog = catalog
        # Ensure default iOS User 0 is present
        self.catalog.register_user_profile(user_id=0, os_platform="IOS", profile_type="PRIMARY_OWNER", display_name="iOS User")

    def ingest_container_metadata(self, canonical_path: str, metadata_plist_bytes: bytes) -> None:
        """
        Parses .com.apple.mobile_container_manager.metadata.plist and links container UUIDs.
        """
        try:
            plist_data = plistlib.loads(metadata_plist_bytes)
        except Exception as err:
            logger.debug("Failed parsing iOS metadata plist at %s: %s", canonical_path, err)
            return

        if not isinstance(plist_data, dict):
            return

        identifier = str(plist_data.get("MCMMetadataIdentifier", ""))
        content_class = int(plist_data.get("MCMMetadataContentClass", 0))
        if not identifier:
            return

        container_dir = str(Path(canonical_path).parent).replace("\\", "/")
        uuid_str = Path(container_dir).name

        if content_class == 2:  # App Data Sandbox
            inst_id = self.catalog.register_app_instance(
                os_platform="IOS",
                user_id=0,
                app_identifier=identifier,
                display_name=identifier.split(".")[-1],
                install_status="INSTALLED_ACTIVE",
                effective_linux_uid=501
            )
            self.catalog.register_storage_mount(
                app_instance_id=inst_id,
                mount_category="IOS_DATA_SANDBOX",
                canonical_root_path=container_dir,
                encryption_domain="IOS_AFU_SANDBOX",
                container_uuid_or_group=uuid_str
            )

        elif content_class == 7:  # Shared App Group
            parent_bundle_id = self._resolve_app_group_parent(identifier)
            inst_id = self.catalog.register_app_instance(
                os_platform="IOS",
                user_id=0,
                app_identifier=parent_bundle_id,
                display_name=parent_bundle_id.split(".")[-1],
                install_status="INSTALLED_ACTIVE",
                effective_linux_uid=501
            )
            self.catalog.register_storage_mount(
                app_instance_id=inst_id,
                mount_category="IOS_SHARED_APP_GROUP",
                canonical_root_path=container_dir,
                encryption_domain="IOS_AFU_SANDBOX",
                container_uuid_or_group=identifier
            )

        elif content_class == 1:  # App Bundle (.app)
            inst_id = self.catalog.register_app_instance(
                os_platform="IOS",
                user_id=0,
                app_identifier=identifier,
                display_name=identifier.split(".")[-1],
                install_status="INSTALLED_ACTIVE",
                effective_linux_uid=501
            )
            self.catalog.register_storage_mount(
                app_instance_id=inst_id,
                mount_category="IOS_APP_BUNDLE",
                canonical_root_path=container_dir,
                encryption_domain="IOS_AFU_SANDBOX",
                container_uuid_or_group=uuid_str
            )

        elif content_class == 4:  # PluginKit / Extension
            inst_id = self.catalog.register_app_instance(
                os_platform="IOS",
                user_id=0,
                app_identifier=identifier,
                install_status="INSTALLED_ACTIVE",
                effective_linux_uid=501
            )
            self.catalog.register_storage_mount(
                app_instance_id=inst_id,
                mount_category="IOS_PLUGINKIT",
                canonical_root_path=container_dir,
                encryption_domain="IOS_AFU_SANDBOX",
                container_uuid_or_group=uuid_str
            )

    def _resolve_app_group_parent(self, group_identifier: str) -> str:
        """Determines the owning Bundle ID for a Shared App Group identifier."""
        if group_identifier in self.KNOWN_APP_GROUPS:
            return self.KNOWN_APP_GROUPS[group_identifier]

        # Strip leading group.
        stripped = re.sub(r"^group\.", "", group_identifier, flags=re.IGNORECASE)

        # Remove trailing .shared or .group
        stripped = re.sub(r"\.(?:shared|group|appgroup)$", "", stripped, flags=re.IGNORECASE)

        # Check existing apps in catalog
        existing = self.catalog.resolve_app_targets([stripped])
        if existing:
            return stripped

        return stripped

    def enrich_app_bundle(
        self,
        bundle_id: str,
        display_name: str,
        version_string: str,
        itunes_metadata: Dict[str, Any]
    ) -> None:
        """Enriches the application entry with Apple ID email and App Store purchase metadata."""
        apple_id = itunes_metadata.get("appleId") or itunes_metadata.get("userName")
        purchase_date = itunes_metadata.get("purchaseDate")

        self.catalog.register_app_instance(
            os_platform="IOS",
            user_id=0,
            app_identifier=bundle_id,
            display_name=display_name,
            install_status="INSTALLED_ACTIVE",
            version_string=version_string,
            purchasing_account_id=apple_id,
            first_install_utc_iso=purchase_date
        )
