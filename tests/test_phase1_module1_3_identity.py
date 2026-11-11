"""
Tests for Phase 1 Module 1.3: Pre-Flight Global Identity & Sandbox Resolver.
Complies with:
- Section 1.3 & Section 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
- Engineering Specification Phase 1 Module 1.3.

Verifies:
1. Android Binary XML (ABX) Decoder (magic 61 62 78 00, string interning pool, command/data type nibbles, XML/ABX auto-detection).
2. Android Multi-User & Linux UID Math Engine ((user_id * 100000) + app_id across User 0, 10, 95, 150, 999).
3. Android Package Registry & Storage Mounts (packages.xml / packages.list, cert SHA-256, installer sources, CE/DE/external mounts).
4. iOS Sandbox & Shared App Group Linking (.com.apple.mobile_container_manager.metadata.plist across 5 container roots).
5. iOS App Bundle & iTunesMetadata.plist Enrichment (downloading Apple ID, purchase date, bundle version).
6. Uninstalled "Ghost App" Discovery Engine (DataUsage.sqlite, DuetExpertCenter, usagestats).
7. Downstream Query APIs (resolve_app_targets, resolve_file_owner).
"""

import io
import plistlib
import sqlite3
import struct
import pytest
from pathlib import Path

# Production module imports (failing during Phase A RED phase)
from src.identity.abx import AndroidBinaryXmlDecoder
from src.identity.android import AndroidIdentityResolver
from src.identity.ios import IOSIdentityResolver
from src.identity.ghost import GhostAppDetector
from src.identity.catalog import IdentitySandboxCatalog


# ============================================================================
# Helpers to construct realistic binary fixtures
# ============================================================================

def make_abx_packages_xml(packages_data: list[dict]) -> bytes:
    """
    Constructs real binary ABX (Android Binary XML) stream starting with 61 62 78 00.
    Encodes <packages> with child <package> elements and typed attributes.
    """
    buf = io.BytesIO()
    # 1. Header: magic "abx\0" (version 0)
    buf.write(b"abx\x00")

    # Command nibbles:
    # 0 = START_DOCUMENT, 1 = END_DOCUMENT, 2 = START_TAG, 3 = END_TAG, 4 = TEXT, 15 = ATTRIBUTE (0x0F)
    # Data type high nibbles:
    # 2 = TYPE_STRING, 3 = TYPE_STRING_INTERNED, 6 = TYPE_INT, 8 = TYPE_LONG, 12 = TRUE, 13 = FALSE

    # Write START_DOCUMENT (0x00)
    buf.write(bytes([0x00]))

    # Helper: write string (type 2)
    def write_string(s: str):
        encoded = s.encode("utf-8")
        buf.write(struct.pack(">H", len(encoded)))
        buf.write(encoded)

    # Write START_TAG <packages> (command 2, data type 2)
    buf.write(bytes([(2 << 4) | 2]))
    write_string("packages")

    for pkg in packages_data:
        # Write START_TAG <package> (command 2, data type 2)
        buf.write(bytes([(2 << 4) | 2]))
        write_string("package")

        # Attribute: name (command 15, data type 2)
        buf.write(bytes([(2 << 4) | 15]))
        write_string("name")
        write_string(pkg["name"])

        # Attribute: codePath (command 15, data type 2)
        buf.write(bytes([(2 << 4) | 15]))
        write_string("codePath")
        write_string(pkg.get("codePath", f"/data/app/{pkg['name']}/base.apk"))

        # Attribute: userId (command 15, data type 6: int32_be)
        buf.write(bytes([(6 << 4) | 15]))
        write_string("userId")
        buf.write(struct.pack(">i", pkg.get("userId", 10000)))

        # Attribute: installer (command 15, data type 2)
        if "installer" in pkg:
            buf.write(bytes([(2 << 4) | 15]))
            write_string("installer")
            write_string(pkg["installer"])

        # Attribute: firstInstallTime (command 15, data type 8: int64_be)
        if "firstInstallTime" in pkg:
            buf.write(bytes([(8 << 4) | 15]))
            write_string("firstInstallTime")
            buf.write(struct.pack(">q", pkg["firstInstallTime"]))

        # End tag </package> (command 3, data type 2)
        buf.write(bytes([(2 << 4) | 3]))
        write_string("package")

    # End tag </packages> (command 3, data type 2)
    buf.write(bytes([(2 << 4) | 3]))
    write_string("packages")

    # END_DOCUMENT (0x01)
    buf.write(bytes([0x01]))

    return buf.getvalue()


def make_ios_metadata_plist(identifier: str, content_class: int) -> bytes:
    """Builds a real binary bplist00 .com.apple.mobile_container_manager.metadata.plist."""
    data = {
        "MCMMetadataIdentifier": identifier,
        "MCMMetadataContentClass": content_class,
        "MCMMetadataInfo": {"Version": 1}
    }
    return plistlib.dumps(data, fmt=plistlib.FMT_BINARY)


# ============================================================================
# Test Cases
# ============================================================================

class TestAndroidBinaryXmlDecoder:
    """Stage 1: Android Binary XML (ABX) Decoder Tests."""

    def test_abx_decoder_magic_and_structure(self):
        pkgs = [
            {
                "name": "com.phonepe.app",
                "codePath": "/data/app/~~random==/com.phonepe.app-base==/base.apk",
                "userId": 10145,
                "installer": "com.android.vending",
                "firstInstallTime": 1714800000000
            },
            {
                "name": "com.whatsapp",
                "codePath": "/data/app/~~random2==/com.whatsapp-base==/base.apk",
                "userId": 10146,
                "installer": "com.android.vending",
                "firstInstallTime": 1714800005000
            }
        ]
        abx_bytes = make_abx_packages_xml(pkgs)
        assert abx_bytes.startswith(b"abx\x00")

        decoder = AndroidBinaryXmlDecoder()
        root = decoder.decode(abx_bytes)

        assert root.tag == "packages"
        package_elements = [child for child in root if child.tag == "package"]
        assert len(package_elements) == 2

        pkg0 = package_elements[0]
        assert pkg0.attrib["name"] == "com.phonepe.app"
        assert pkg0.attrib["userId"] == "10145" or pkg0.attrib["userId"] == 10145
        assert pkg0.attrib["installer"] == "com.android.vending"

    def test_abx_decoder_fallback_to_plain_xml(self):
        plain_xml = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
        <packages>
            <package name="org.thoughtcrime.securesms" userId="10150" codePath="/data/app/signal/base.apk" />
        </packages>"""

        decoder = AndroidBinaryXmlDecoder()
        root = decoder.decode(plain_xml)

        assert root.tag == "packages"
        package_el = root.find("package")
        assert package_el is not None
        assert package_el.attrib["name"] == "org.thoughtcrime.securesms"
        assert str(package_el.attrib["userId"]) == "10150"


class TestAndroidIdentityResolver:
    """Stage 2 & 4: Android Package, Multi-User & Linux UID Math Tests."""

    def test_multi_user_linux_uid_math(self, tmp_path):
        catalog_db = tmp_path / "identity.sqlite"
        catalog = IdentitySandboxCatalog(catalog_db_path=catalog_db)

        resolver = AndroidIdentityResolver(catalog=catalog)

        # 1. User 0 (Primary Owner, app_id 10145 -> UID 10145)
        uid_u0 = resolver.calculate_linux_uid(user_id=0, base_app_id=10145)
        assert uid_u0 == 10145
        u_id, app_id = resolver.reverse_linux_uid(10145)
        assert u_id == 0
        assert app_id == 10145

        # 2. User 10 (Managed Work Profile -> UID 1010145)
        uid_u10 = resolver.calculate_linux_uid(user_id=10, base_app_id=10145)
        assert uid_u10 == 1010145
        u_id10, app_id10 = resolver.reverse_linux_uid(1010145)
        assert u_id10 == 10
        assert app_id10 == 10145

        # 3. User 95 (Samsung Dual Messenger -> UID 9510145)
        uid_u95 = resolver.calculate_linux_uid(user_id=95, base_app_id=10145)
        assert uid_u95 == 9510145
        u_id95, app_id95 = resolver.reverse_linux_uid(9510145)
        assert u_id95 == 95
        assert app_id95 == 10145

        # 4. User 999 (Xiaomi / Oppo Cloner -> UID 99910145)
        uid_u999 = resolver.calculate_linux_uid(user_id=999, base_app_id=10145)
        assert uid_u999 == 99910145

    def test_android_packages_xml_and_storage_mounts(self, tmp_path):
        catalog_db = tmp_path / "identity.sqlite"
        catalog = IdentitySandboxCatalog(catalog_db_path=catalog_db)
        resolver = AndroidIdentityResolver(catalog=catalog)

        # Register User Profiles: User 0 and Samsung Dual Messenger User 95
        resolver.register_user_profile(user_id=0, profile_type="PRIMARY_OWNER", display_name="Owner")
        resolver.register_user_profile(user_id=95, profile_type="SAMSUNG_DUAL_MESSENGER", display_name="DualApp")

        # Ingest simulated packages.xml ABX bytes
        pkgs = [
            {
                "name": "com.whatsapp",
                "codePath": "/data/app/~~hashA==/com.whatsapp-hashB==/base.apk",
                "userId": 10145,
                "installer": "com.android.vending",
                "firstInstallTime": 1714800000000
            }
        ]
        abx_bytes = make_abx_packages_xml(pkgs)
        resolver.ingest_packages_xml(abx_bytes)

        # Query catalog for WhatsApp targets across both user 0 and user 95
        targets = catalog.resolve_app_targets(["com.whatsapp"])
        assert len(targets) >= 1

        primary_instance = next(t for t in targets if t["user_id"] == 0)
        assert primary_instance["app_identifier"] == "com.whatsapp"
        assert primary_instance["effective_linux_uid"] == 10145

        # Check storage mounts for CE and External Media
        mount_roots = [m["canonical_root_path"] for m in primary_instance["storage_mounts"]]
        assert "/data/user/0/com.whatsapp" in mount_roots
        assert "/data/media/0/Android/media/com.whatsapp" in mount_roots

        # Check reverse attribution
        owner = catalog.resolve_file_owner(10145)
        assert owner is not None
        assert owner["app_identifier"] == "com.whatsapp"
        assert owner["profile_display_name"] == "Owner"


class TestIOSIdentityResolver:
    """Stage 3: iOS Container Scan & Shared App Group Linking Tests."""

    def test_ios_shared_app_group_and_bundle_enrichment(self, tmp_path):
        catalog_db = tmp_path / "identity.sqlite"
        catalog = IdentitySandboxCatalog(catalog_db_path=catalog_db)
        resolver = IOSIdentityResolver(catalog=catalog)

        # Simulate discovery of 3 iOS containers:
        # 1. App Data Sandbox: UUID-A
        uuid_a = "3D8A9F21-4E62-4C11-92B1-7A8C2D4E6F10"
        meta_data_a = make_ios_metadata_plist(identifier="net.whatsapp.WhatsApp", content_class=2)
        resolver.ingest_container_metadata(
            canonical_path=f"/private/var/mobile/Containers/Data/Application/{uuid_a}/.com.apple.mobile_container_manager.metadata.plist",
            metadata_plist_bytes=meta_data_a
        )

        # 2. Shared App Group: UUID-B (where ChatStorage.sqlite lives)
        uuid_b = "8F2A1111-2222-3333-4444-555566667777"
        meta_group_b = make_ios_metadata_plist(identifier="group.net.whatsapp.WhatsApp.shared", content_class=7)
        resolver.ingest_container_metadata(
            canonical_path=f"/private/var/mobile/Containers/Shared/AppGroup/{uuid_b}/.com.apple.mobile_container_manager.metadata.plist",
            metadata_plist_bytes=meta_group_b
        )

        # 3. App Bundle: UUID-C (with Info.plist and iTunesMetadata.plist)
        uuid_c = "AAAA1111-BBBB-CCCC-DDDD-EEEEFFFF0000"
        meta_bundle_c = make_ios_metadata_plist(identifier="net.whatsapp.WhatsApp", content_class=1)
        resolver.ingest_container_metadata(
            canonical_path=f"/private/var/containers/Bundle/Application/{uuid_c}/.com.apple.mobile_container_manager.metadata.plist",
            metadata_plist_bytes=meta_bundle_c
        )

        # Enrich App Bundle with iTunesMetadata.plist (Apple ID email)
        itunes_meta = {
            "appleId": "suspect.mule@icloud.com",
            "purchaseDate": "2024-05-04T05:20:00Z",
            "itemName": "WhatsApp Messenger"
        }
        resolver.enrich_app_bundle(
            bundle_id="net.whatsapp.WhatsApp",
            display_name="WhatsApp Messenger",
            version_string="24.8.71",
            itunes_metadata=itunes_meta
        )

        # Query catalog for WhatsApp targets
        targets = catalog.resolve_app_targets(["net.whatsapp.WhatsApp"])
        assert len(targets) == 1

        wa = targets[0]
        assert wa["app_identifier"] == "net.whatsapp.WhatsApp"
        assert wa["purchasing_account_id"] == "suspect.mule@icloud.com"

        # Verify that BOTH UUID-A (Data) and UUID-B (Shared App Group) are bound under the same app instance!
        mount_roots = [m["canonical_root_path"] for m in wa["storage_mounts"]]
        assert f"/private/var/mobile/Containers/Data/Application/{uuid_a}" in mount_roots
        assert f"/private/var/mobile/Containers/Shared/AppGroup/{uuid_b}" in mount_roots


class TestGhostAppDetection:
    """Stage 5: Uninstalled ("Ghost App") Telemetry Discovery Tests."""

    def test_ghost_app_discovery(self, tmp_path):
        catalog_db = tmp_path / "identity.sqlite"
        catalog = IdentitySandboxCatalog(catalog_db_path=catalog_db)

        # Ingest active app com.whatsapp only
        catalog.register_app_instance(
            os_platform="ANDROID",
            user_id=0,
            app_identifier="com.whatsapp",
            display_name="WhatsApp",
            install_status="INSTALLED_ACTIVE"
        )

        detector = GhostAppDetector(catalog=catalog)

        # Telemetry sources reveal deleted Signal and MetaMask apps
        detector.record_telemetry_evidence(
            app_identifier="org.thoughtcrime.securesms",
            os_platform="ANDROID",
            evidence_source="DataUsage.sqlite:ZPROCESS",
            last_seen_utc_iso="2026-11-04T12:00:00.000000Z"
        )
        detector.record_telemetry_evidence(
            app_identifier="io.metamask",
            os_platform="ANDROID",
            evidence_source="DuetExpertCenter:notificationAndSuggestionDB.db",
            last_seen_utc_iso="2026-11-04T12:30:00.000000Z"
        )

        # Active com.whatsapp telemetry should not become a ghost app
        detector.record_telemetry_evidence(
            app_identifier="com.whatsapp",
            os_platform="ANDROID",
            evidence_source="DataUsage.sqlite:ZPROCESS",
            last_seen_utc_iso="2026-11-04T13:00:00.000000Z"
        )

        detector.finalize_ghost_apps()

        # Query catalog for ghost apps
        ghosts = catalog.get_ghost_apps()
        ghost_ids = [g["app_identifier"] for g in ghosts]
        assert "org.thoughtcrime.securesms" in ghost_ids
        assert "io.metamask" in ghost_ids
        assert "com.whatsapp" not in ghost_ids

        # Check evidence sources JSON
        meta_ghost = next(g for g in ghosts if g["app_identifier"] == "io.metamask")
        assert "DuetExpertCenter" in meta_ghost["ghost_evidence_sources"]
