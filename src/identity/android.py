"""
Android Package, Multi-User Profile, and Linux UID Math Resolver.
Phase 1, Module 1.3, Section 4.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union, Tuple, List, Dict, Any

from src.identity.abx import AndroidBinaryXmlDecoder
from src.identity.catalog import IdentitySandboxCatalog


class AndroidIdentityResolver:
    """Resolves Android packages, cloned user profiles, Linux kernel UIDs, and storage mounts."""

    def __init__(self, catalog: IdentitySandboxCatalog):
        self.catalog = catalog
        self.abx_decoder = AndroidBinaryXmlDecoder()

    def calculate_linux_uid(self, user_id: int, base_app_id: int) -> int:
        """
        Computes the effective Linux kernel UID across user profiles:
        Linux UID = (user_id * 100000) + base_app_id
        """
        return (user_id * 100000) + base_app_id

    def reverse_linux_uid(self, linux_uid: int) -> Tuple[int, int]:
        """
        Deconstructs an effective Linux kernel UID into (user_id, base_app_id).
        """
        return (linux_uid // 100000, linux_uid % 100000)

    def register_user_profile(
        self,
        user_id: int,
        profile_type: str = "PRIMARY_OWNER",
        display_name: Optional[str] = None,
        created_utc_iso: Optional[str] = None,
        last_login_utc_iso: Optional[str] = None
    ) -> int:
        """Registers an Android user profile, Work Profile, or OEM Cloned space."""
        return self.catalog.register_user_profile(
            user_id=user_id,
            os_platform="ANDROID",
            profile_type=profile_type,
            display_name=display_name,
            created_utc_iso=created_utc_iso,
            last_login_utc_iso=last_login_utc_iso
        )

    def ingest_packages_xml(self, data: Union[bytes, str, Path]) -> int:
        """
        Decodes packages.xml (in either ABX or standard XML format) and registers
        all packages, effective UIDs, and storage mounts across all active user profiles.
        """
        if isinstance(data, Path):
            raw_bytes = data.read_bytes()
        elif isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        root = self.abx_decoder.decode(raw_bytes)
        user_profiles = self.catalog.get_user_profiles("ANDROID")
        if not user_profiles:
            # Default to User 0 if no explicit profiles were registered yet
            self.register_user_profile(user_id=0, profile_type="PRIMARY_OWNER", display_name="Owner")
            user_profiles = self.catalog.get_user_profiles("ANDROID")

        count = 0
        for pkg_el in root.iter("package"):
            pkg_name = pkg_el.attrib.get("name")
            if not pkg_name:
                continue

            code_path = pkg_el.attrib.get("codePath", f"/data/app/{pkg_name}/base.apk")
            installer = pkg_el.attrib.get("installer")
            initiating = pkg_el.attrib.get("initiatingPackageName")

            user_id_raw = pkg_el.attrib.get("userId") or pkg_el.attrib.get("sharedUserId")
            try:
                base_app_id = int(user_id_raw) if user_id_raw else 10000
            except ValueError:
                base_app_id = 10000

            version_code_raw = pkg_el.attrib.get("versionCode") or pkg_el.attrib.get("version")
            try:
                version_code = int(version_code_raw) if version_code_raw else None
            except ValueError:
                version_code = None

            # First install time conversion
            first_install_iso = None
            fit_raw = pkg_el.attrib.get("firstInstallTime") or pkg_el.attrib.get("it")
            if fit_raw:
                try:
                    fit_val = int(fit_raw, 16) if fit_raw.startswith("0x") else int(fit_raw)
                    if fit_val > 0:
                        dt = datetime.fromtimestamp(fit_val / 1000.0, tz=timezone.utc)
                        first_install_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    first_install_iso = None

            # For each active user profile on the phone, register the app instance and storage mounts
            for profile in user_profiles:
                u_id = profile["user_id"]
                effective_uid = self.calculate_linux_uid(u_id, base_app_id)

                inst_id = self.catalog.register_app_instance(
                    os_platform="ANDROID",
                    user_id=u_id,
                    app_identifier=pkg_name,
                    display_name=pkg_name.split(".")[-1].capitalize(),
                    install_status="INSTALLED_ACTIVE",
                    version_string=str(version_code) if version_code else None,
                    version_code=version_code,
                    base_app_id=base_app_id,
                    effective_linux_uid=effective_uid,
                    first_install_utc_iso=first_install_iso,
                    installer_source=installer,
                    initiating_package=initiating
                )

                # Register the 5 canonical storage mounts
                self.catalog.register_storage_mount(
                    app_instance_id=inst_id,
                    mount_category="ANDROID_CE_SANDBOX",
                    canonical_root_path=f"/data/user/{u_id}/{pkg_name}",
                    encryption_domain="ANDROID_CE"
                )
                self.catalog.register_storage_mount(
                    app_instance_id=inst_id,
                    mount_category="ANDROID_DE_SANDBOX",
                    canonical_root_path=f"/data/user_de/{u_id}/{pkg_name}",
                    encryption_domain="ANDROID_DE"
                )
                self.catalog.register_storage_mount(
                    app_instance_id=inst_id,
                    mount_category="ANDROID_EXT_DATA",
                    canonical_root_path=f"/data/media/{u_id}/Android/data/{pkg_name}",
                    encryption_domain="SHARED_MEDIA"
                )
                self.catalog.register_storage_mount(
                    app_instance_id=inst_id,
                    mount_category="ANDROID_EXT_MEDIA",
                    canonical_root_path=f"/data/media/{u_id}/Android/media/{pkg_name}",
                    encryption_domain="SHARED_MEDIA"
                )
                if code_path:
                    self.catalog.register_storage_mount(
                        app_instance_id=inst_id,
                        mount_category="ANDROID_APK_CODE",
                        canonical_root_path=code_path,
                        encryption_domain="SHARED_MEDIA"
                    )

                # Populate reverse Linux UID lookup table
                self.catalog.register_uid_ownership(
                    effective_linux_uid=effective_uid,
                    user_id=u_id,
                    base_app_id=base_app_id,
                    app_instance_id=inst_id,
                    app_identifier=pkg_name
                )
                count += 1

        return count
