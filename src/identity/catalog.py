"""
Identity & Sandbox Master Catalog Database.
Phase 1, Module 1.3, Section 6: SQLite catalog for multi-user profiles, application instances, and mount paths.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional, Union, List, Dict, Any


class IdentitySandboxCatalog:
    """Manages device user profiles, resolved applications, storage mounts, and UID reverse-lookup."""

    def __init__(self, catalog_db_path: Union[str, Path]):
        self.catalog_db_path = Path(catalog_db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.catalog_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Creates the 4 core relational identity tables."""
        self.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.catalog_db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA temp_store = MEMORY;")

        # Table 1: device_user_profiles
        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_user_profiles (
                profile_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                os_platform TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                profile_type TEXT NOT NULL,
                profile_display_name TEXT,
                created_utc_iso TEXT,
                last_login_utc_iso TEXT,
                UNIQUE(os_platform, user_id)
            );
        """)

        # Table 2: resolved_application_catalog
        cur.execute("""
            CREATE TABLE IF NOT EXISTS resolved_application_catalog (
                app_instance_id INTEGER PRIMARY KEY AUTOINCREMENT,
                os_platform TEXT NOT NULL,
                user_id INTEGER NOT NULL DEFAULT 0,
                app_identifier TEXT NOT NULL,
                display_name TEXT,
                install_status TEXT NOT NULL,
                version_string TEXT,
                version_code INTEGER,
                base_app_id INTEGER,
                effective_linux_uid INTEGER,
                first_install_utc_iso TEXT,
                last_update_utc_iso TEXT,
                installer_source TEXT,
                initiating_package TEXT,
                purchasing_account_id TEXT,
                signing_cert_sha256 TEXT,
                is_signature_verified INTEGER DEFAULT 1,
                is_forensic_downgraded INTEGER DEFAULT 0,
                ghost_evidence_sources TEXT,
                UNIQUE(os_platform, user_id, app_identifier)
            );
        """)

        # Table 3: app_storage_mounts
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_storage_mounts (
                mount_id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                mount_category TEXT NOT NULL,
                container_uuid_or_group TEXT,
                canonical_root_path TEXT NOT NULL,
                encryption_domain TEXT NOT NULL,
                is_present_in_vfs INTEGER NOT NULL DEFAULT 1,
                UNIQUE(app_instance_id, canonical_root_path)
            );
        """)

        # Table 4: uid_ownership_lookup
        cur.execute("""
            CREATE TABLE IF NOT EXISTS uid_ownership_lookup (
                effective_linux_uid INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                base_app_id INTEGER NOT NULL,
                app_instance_id INTEGER NOT NULL,
                app_identifier TEXT NOT NULL
            );
        """)

        conn.commit()
        conn.close()

    def register_user_profile(
        self,
        user_id: int,
        os_platform: str = "ANDROID",
        profile_type: str = "PRIMARY_OWNER",
        display_name: Optional[str] = None,
        created_utc_iso: Optional[str] = None,
        last_login_utc_iso: Optional[str] = None
    ) -> int:
        """Registers a user profile (User 0, Dual Messenger 95, Work Profile 10, etc.)."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO device_user_profiles (
                os_platform, user_id, profile_type, profile_display_name,
                created_utc_iso, last_login_utc_iso
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(os_platform, user_id) DO UPDATE SET
                profile_type = excluded.profile_type,
                profile_display_name = COALESCE(excluded.profile_display_name, profile_display_name);
        """, (os_platform, user_id, profile_type, display_name, created_utc_iso, last_login_utc_iso))
        row_id = cur.lastrowid
        conn.commit()
        conn.close()
        return row_id or 1

    def get_user_profiles(self, os_platform: str = "ANDROID") -> List[Dict[str, Any]]:
        """Returns all registered user profiles for a platform."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM device_user_profiles WHERE os_platform = ? ORDER BY user_id;", (os_platform,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def register_app_instance(
        self,
        os_platform: str,
        user_id: int,
        app_identifier: str,
        display_name: Optional[str] = None,
        install_status: str = "INSTALLED_ACTIVE",
        version_string: Optional[str] = None,
        version_code: Optional[int] = None,
        base_app_id: Optional[int] = None,
        effective_linux_uid: Optional[int] = None,
        first_install_utc_iso: Optional[str] = None,
        last_update_utc_iso: Optional[str] = None,
        installer_source: Optional[str] = None,
        initiating_package: Optional[str] = None,
        purchasing_account_id: Optional[str] = None,
        signing_cert_sha256: Optional[str] = None,
        is_signature_verified: int = 1,
        is_forensic_downgraded: int = 0,
        ghost_evidence_sources: Optional[str] = None
    ) -> int:
        """Registers or updates a specific app instance for a user profile."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO resolved_application_catalog (
                os_platform, user_id, app_identifier, display_name, install_status,
                version_string, version_code, base_app_id, effective_linux_uid,
                first_install_utc_iso, last_update_utc_iso, installer_source,
                initiating_package, purchasing_account_id, signing_cert_sha256,
                is_signature_verified, is_forensic_downgraded, ghost_evidence_sources
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(os_platform, user_id, app_identifier) DO UPDATE SET
                display_name = COALESCE(excluded.display_name, display_name),
                install_status = excluded.install_status,
                version_string = COALESCE(excluded.version_string, version_string),
                version_code = COALESCE(excluded.version_code, version_code),
                base_app_id = COALESCE(excluded.base_app_id, base_app_id),
                effective_linux_uid = COALESCE(excluded.effective_linux_uid, effective_linux_uid),
                first_install_utc_iso = COALESCE(excluded.first_install_utc_iso, first_install_utc_iso),
                last_update_utc_iso = COALESCE(excluded.last_update_utc_iso, last_update_utc_iso),
                installer_source = COALESCE(excluded.installer_source, installer_source),
                initiating_package = COALESCE(excluded.initiating_package, initiating_package),
                purchasing_account_id = COALESCE(excluded.purchasing_account_id, purchasing_account_id),
                signing_cert_sha256 = COALESCE(excluded.signing_cert_sha256, signing_cert_sha256),
                ghost_evidence_sources = COALESCE(excluded.ghost_evidence_sources, ghost_evidence_sources);
        """, (
            os_platform, user_id, app_identifier, display_name, install_status,
            version_string, version_code, base_app_id, effective_linux_uid,
            first_install_utc_iso, last_update_utc_iso, installer_source,
            initiating_package, purchasing_account_id, signing_cert_sha256,
            is_signature_verified, is_forensic_downgraded, ghost_evidence_sources
        ))
        cur.execute(
            "SELECT app_instance_id FROM resolved_application_catalog WHERE os_platform = ? AND user_id = ? AND app_identifier = ?;",
            (os_platform, user_id, app_identifier)
        )
        row = cur.fetchone()
        app_instance_id = row["app_instance_id"]
        conn.commit()
        conn.close()
        return app_instance_id

    def register_storage_mount(
        self,
        app_instance_id: int,
        mount_category: str,
        canonical_root_path: str,
        encryption_domain: str,
        container_uuid_or_group: Optional[str] = None,
        is_present_in_vfs: int = 1
    ) -> int:
        """Registers a storage mount path for an application instance."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO app_storage_mounts (
                app_instance_id, mount_category, container_uuid_or_group,
                canonical_root_path, encryption_domain, is_present_in_vfs
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_instance_id, canonical_root_path) DO UPDATE SET
                mount_category = excluded.mount_category,
                container_uuid_or_group = COALESCE(excluded.container_uuid_or_group, container_uuid_or_group),
                is_present_in_vfs = excluded.is_present_in_vfs;
        """, (
            app_instance_id, mount_category, container_uuid_or_group,
            canonical_root_path, encryption_domain, is_present_in_vfs
        ))
        cur.execute(
            "SELECT mount_id FROM app_storage_mounts WHERE app_instance_id = ? AND canonical_root_path = ?;",
            (app_instance_id, canonical_root_path)
        )
        mount_id = cur.fetchone()["mount_id"]
        conn.commit()
        conn.close()
        return mount_id

    def register_uid_ownership(
        self,
        effective_linux_uid: int,
        user_id: int,
        base_app_id: int,
        app_instance_id: int,
        app_identifier: str
    ) -> None:
        """Populates the reverse-lookup table from effective kernel UID to application."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO uid_ownership_lookup (
                effective_linux_uid, user_id, base_app_id, app_instance_id, app_identifier
            ) VALUES (?, ?, ?, ?, ?);
        """, (effective_linux_uid, user_id, base_app_id, app_instance_id, app_identifier))
        conn.commit()
        conn.close()

    def resolve_app_targets(self, app_identifiers: Union[List[str], str]) -> List[Dict[str, Any]]:
        """
        Exposed API for downstream parsers: retrieves all app instances and mounts across all user profiles.
        """
        if isinstance(app_identifiers, str):
            ids = [app_identifiers]
        else:
            ids = list(app_identifiers)

        if not ids:
            return []

        conn = self._get_connection()
        cur = conn.cursor()

        placeholders = ",".join("?" for _ in ids)
        query = f"""
            SELECT * FROM resolved_application_catalog
            WHERE app_identifier IN ({placeholders})
            ORDER BY user_id ASC, app_instance_id ASC;
        """
        cur.execute(query, ids)
        app_rows = [dict(r) for r in cur.fetchall()]

        for app in app_rows:
            inst_id = app["app_instance_id"]
            cur.execute("SELECT * FROM app_storage_mounts WHERE app_instance_id = ? ORDER BY mount_id ASC;", (inst_id,))
            app["storage_mounts"] = [dict(m) for m in cur.fetchall()]

        conn.close()
        return app_rows

    def resolve_file_owner(self, owner_uid: int) -> Optional[Dict[str, Any]]:
        """
        Exposed API: translates an inode owner_uid into application name and user profile.
        """
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT u.*, a.display_name, p.profile_display_name
            FROM uid_ownership_lookup u
            JOIN resolved_application_catalog a ON u.app_instance_id = a.app_instance_id
            LEFT JOIN device_user_profiles p ON u.user_id = p.user_id
            WHERE u.effective_linux_uid = ?;
        """, (owner_uid,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_ghost_apps(self) -> List[Dict[str, Any]]:
        """Returns all detected uninstalled applications with their residual evidence sources."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM resolved_application_catalog WHERE install_status = 'UNINSTALLED_GHOST_APP';")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
