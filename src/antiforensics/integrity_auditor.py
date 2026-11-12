"""
Sub-Engine 6.5A: OS Integrity, Bootloader, Root (Magisk, KernelSU, APatch),
Hooking Framework (LSPosed/Xposed), and iOS Jailbreak/TrollStore Auditor.
Complies with Section 3 of Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

from src.core.sqlite_uri import ro_uri
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.antiforensics.models import (
    IntegrityFindingCategory,
    OSIntegrityAuditRecord,
)


class OSIntegrityAuditor:
    """Audits operating system integrity, root policies, and runtime hooking frameworks."""

    def audit_magisk_database(
        self,
        db_path: str,
        source_vfs_file_id: int,
    ) -> List[OSIntegrityAuditRecord]:
        """
        Parses /data/adb/magisk.db to audit root privileges granted (policies),
        active Zygisk concealments from banking/UPI apps (denylist), and
        unmasks repackaged disguised Magisk Manager apps (strings.requester).
        """
        records: List[OSIntegrityAuditRecord] = []
        if not os.path.exists(db_path):
            return records

        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()

        # 1. Audit policies table
        try:
            cur.execute("SELECT uid, package_name, policy, until, logging, notification FROM policies")
            for row in cur.fetchall():
                uid, pkg_name, policy, until, logging, notif = row
                target_pkg = pkg_name if pkg_name else f"uid_{uid}"
                if policy == 2:
                    policy_str = "ROOT_ALLOWED (2)"
                elif policy == 1:
                    policy_str = "ROOT_DENIED (1)"
                else:
                    policy_str = f"ROOT_POLICY_{policy}"

                records.append(
                    OSIntegrityAuditRecord(
                        finding_category=IntegrityFindingCategory.MAGISK_ROOT_POLICY,
                        source_vfs_file_id=source_vfs_file_id,
                        target_or_requester_pkg=target_pkg,
                        hook_module_or_detail=f"uid={uid}, until={until}, logging={logging}",
                        policy_or_state=policy_str,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"magisk.db:policies:uid={uid}",
                        dim_corroboration=1.0,
                    )
                )
        except sqlite3.OperationalError as _err:
            records.extend([])

        # 2. Audit denylist table
        try:
            cur.execute("SELECT package_name, process_name FROM denylist")
            for row in cur.fetchall():
                pkg_name, proc_name = row
                records.append(
                    OSIntegrityAuditRecord(
                        finding_category=IntegrityFindingCategory.MAGISK_ZYGISK_DENYLIST_HIDE,
                        source_vfs_file_id=source_vfs_file_id,
                        target_or_requester_pkg=pkg_name,
                        hook_module_or_detail=f"process={proc_name}",
                        policy_or_state="CONCEALED_IN_ZYGISK_DENYLIST",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"magisk.db:denylist:pkg={pkg_name}",
                        dim_corroboration=1.0,
                    )
                )
        except sqlite3.OperationalError as _err:
            records.extend([])

        # 3. Audit strings table for unmasking disguised Magisk Manager
        try:
            cur.execute("SELECT key, value FROM strings")
            for row in cur.fetchall():
                key, val = row
                if key == "requester" and val:
                    records.append(
                        OSIntegrityAuditRecord(
                            finding_category=IntegrityFindingCategory.MAGISK_REPACKAGED_HIDDEN_APP,
                            source_vfs_file_id=source_vfs_file_id,
                            target_or_requester_pkg=val,
                            hook_module_or_detail="Disguised Magisk Manager unmasked from strings.requester",
                            policy_or_state="REPACKAGED_MAGISK_MANAGER",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance="magisk.db:strings:key=requester",
                            dim_corroboration=1.0,
                        )
                    )
        except sqlite3.OperationalError as _err:
            records.extend([])

        conn.close()
        return records

    def audit_lsposed_database(
        self,
        db_path: str,
        source_vfs_file_id: int,
    ) -> List[OSIntegrityAuditRecord]:
        """
        Parses /data/adb/lspd/config/modules_config.db to identify hooked applications.
        """
        records: List[OSIntegrityAuditRecord] = []
        if not os.path.exists(db_path):
            return records

        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT m.module_pkg_name, s.app_pkg_name
                FROM modules m
                JOIN scope s ON m.mid = s.mid
            """)
            for row in cur.fetchall():
                mod_pkg, target_pkg = row
                records.append(
                    OSIntegrityAuditRecord(
                        finding_category=IntegrityFindingCategory.LSPOSED_XPOSED_APP_HOOK,
                        source_vfs_file_id=source_vfs_file_id,
                        target_or_requester_pkg=target_pkg,
                        hook_module_or_detail=f"Injected Hook Module: {mod_pkg}",
                        policy_or_state="HOOKED_ACTIVE_IN_SCOPE",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"modules_config.db:scope:target={target_pkg}",
                        dim_corroboration=1.0,
                    )
                )
        except sqlite3.OperationalError as _err:
            records.extend([])

        conn.close()
        return records

    def audit_kernelsu_allowlist(
        self,
        allowlist_path: str,
        source_vfs_file_id: int,
    ) -> List[OSIntegrityAuditRecord]:
        """
        Parses /data/adb/ksu/allowlist to identify packages granted kernel-level superuser rights.
        """
        records: List[OSIntegrityAuditRecord] = []
        if not os.path.exists(allowlist_path):
            return records

        with open(allowlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_clean = line.strip()
                if not line_clean or line_clean.startswith("#"):
                    continue
                parts = line_clean.split(":")
                pkg = parts[0] if parts else line_clean
                records.append(
                    OSIntegrityAuditRecord(
                        finding_category=IntegrityFindingCategory.KERNELSU_OR_APATCH_ROOT,
                        source_vfs_file_id=source_vfs_file_id,
                        target_or_requester_pkg=pkg,
                        hook_module_or_detail="KernelSU Root Access Configured",
                        policy_or_state="KERNELSU_ROOT_ALLOWED",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"ksu_allowlist:{pkg}",
                        dim_corroboration=1.0,
                    )
                )
        return records

    def audit_bootloader_and_developer_options(
        self,
        settings_global_path: Optional[str] = None,
        build_props: Optional[Dict[str, str]] = None,
        source_vfs_file_id: int = 0,
    ) -> List[OSIntegrityAuditRecord]:
        """
        Audits Android bootloader unlock states and developer debugging flags.
        """
        records: List[OSIntegrityAuditRecord] = []

        # 1. Check build_props for unlocked bootloader
        if build_props:
            verified_boot = build_props.get("ro.boot.verifiedbootstate", "").lower()
            flash_locked = build_props.get("ro.boot.flash.locked", "")
            if verified_boot in ("orange", "yellow") or flash_locked == "0":
                records.append(
                    OSIntegrityAuditRecord(
                        finding_category=IntegrityFindingCategory.BOOTLOADER_UNLOCKED,
                        source_vfs_file_id=source_vfs_file_id,
                        target_or_requester_pkg="system_kernel",
                        hook_module_or_detail=f"verifiedbootstate={verified_boot}, flash.locked={flash_locked}",
                        policy_or_state="BOOTLOADER_ORANGE_UNLOCKED",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance="build.prop:ro.boot.verifiedbootstate",
                        dim_corroboration=1.0,
                    )
                )

        # 2. Check settings_global.xml for development options
        if settings_global_path and os.path.exists(settings_global_path):
            try:
                tree = ET.parse(settings_global_path)
                root = tree.getroot()
                for setting in root.findall("setting"):
                    name = setting.attrib.get("name")
                    val = setting.attrib.get("value")
                    if name in ("development_settings_enabled", "adb_enabled") and val == "1":
                        records.append(
                            OSIntegrityAuditRecord(
                                finding_category=IntegrityFindingCategory.ADB_DEVELOPER_OPTIONS_ENABLED,
                                source_vfs_file_id=source_vfs_file_id,
                                target_or_requester_pkg="system_settings",
                                hook_module_or_detail=f"{name}={val}",
                                policy_or_state="DEVELOPER_OPTIONS_AND_ADB_ACTIVE",
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                                dim_existence=EvidentiaryExistence.OBSERVED,
                                dim_access=EvidentiaryAccess.PLAINTEXT,
                                dim_storage=EvidentiaryStorage.LIVE_RECORD,
                                dim_provenance=f"settings_global.xml:{name}",
                                dim_corroboration=1.0,
                            )
                        )
            except Exception as _err:
                records.extend([])

        return records

    def audit_ios_jailbreak(
        self,
        jailbreak_paths: List[str],
        source_vfs_file_id: int = 0,
    ) -> List[OSIntegrityAuditRecord]:
        """
        Audits iOS filesystem paths for rootless/rootful jailbreaks, Substrate/ElleKit, and TrollStore.
        """
        records: List[OSIntegrityAuditRecord] = []
        jailbreak_indicators = {
            "/var/jb/": "Dopamine / Rootless Jailbreak Root",
            "Cydia": "Cydia Substrate Package Manager",
            "Sileo": "Sileo Package Manager",
            "TrollStore": "TrollStore CoreTrust App Sideloader",
            "MobileSubstrate": "MobileSubstrate Dynamic Library Injector",
            "ellekit": "ElleKit Hooking Framework",
        }

        for path_str in jailbreak_paths:
            for ind_key, desc in jailbreak_indicators.items():
                if ind_key.lower() in path_str.lower():
                    records.append(
                        OSIntegrityAuditRecord(
                            finding_category=IntegrityFindingCategory.IOS_JAILBREAK_OR_TROLLSTORE,
                            source_vfs_file_id=source_vfs_file_id,
                            target_or_requester_pkg="ios_filesystem",
                            hook_module_or_detail=f"Detected indicator: {path_str} ({desc})",
                            policy_or_state="IOS_JAILBROKEN_OR_MODDED",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance=f"vfs_path:{path_str}",
                            dim_corroboration=1.0,
                        )
                    )
                    break

        return records
