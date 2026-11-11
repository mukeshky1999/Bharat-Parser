"""
AntiForensicsEngine: Master Orchestrator and SQLite exporter for OS integrity,
clock tampering, location spoofing, and malware/remote access forensic ledgers.
Complies with Section 8 of Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.antiforensics.models import (
    OSIntegrityAuditRecord,
    ClockTamperGapRecord,
    LocationSpoofContradictionRecord,
    MalwareThreatRecord,
)
from src.antiforensics.integrity_auditor import OSIntegrityAuditor
from src.antiforensics.clock_gap_detector import ClockTamperGapDetector
from src.antiforensics.location_spoof_auditor import LocationSpoofAuditor
from src.antiforensics.malware_auditor import MalwareRemoteAccessAuditor


class AntiForensicsEngine:
    """Master orchestrator for Anti-Forensics, Tamper Detection, and Malware Analysis."""

    def __init__(self) -> None:
        self.integrity_auditor = OSIntegrityAuditor()
        self.clock_gap_detector = ClockTamperGapDetector()
        self.location_spoof_auditor = LocationSpoofAuditor()
        self.malware_auditor = MalwareRemoteAccessAuditor()

    def export_to_sqlite(
        self,
        integrity_findings: List[OSIntegrityAuditRecord],
        tamper_records: List[ClockTamperGapRecord],
        spoof_records: List[LocationSpoofContradictionRecord],
        malware_threats: List[MalwareThreatRecord],
        output_db_path: str,
    ) -> None:
        """
        Creates antiforensics_tamper_and_malware_engine.sqlite schema and persists all findings.
        """
        out_dir = Path(output_db_path).parent
        out_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Table 1: os_integrity_root_and_hook_audit
        cur.execute("""
            CREATE TABLE IF NOT EXISTS os_integrity_root_and_hook_audit (
                integrity_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_category TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                target_or_requester_pkg TEXT,
                hook_module_or_detail TEXT,
                policy_or_state TEXT NOT NULL,
                event_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Table 2: clock_tampering_and_deletion_gaps_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS clock_tampering_and_deletion_gaps_ledger (
                tamper_event_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                tamper_category TEXT NOT NULL,
                severity_level TEXT NOT NULL,
                affected_app_or_database TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                monotonic_anchor_detail TEXT NOT NULL,
                claimed_wallclock_utc_iso TEXT,
                true_bracketed_window_utc TEXT,
                courtroom_explanation_note TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Table 3: location_spoofing_and_sensor_contradictions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS location_spoofing_and_sensor_contradictions (
                spoof_flag_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_method TEXT NOT NULL,
                spoofer_package_or_tool TEXT,
                claimed_gps_lat_lon TEXT,
                contradicting_sensor_proof TEXT NOT NULL,
                event_utc_iso TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Table 4: malware_apk_c2_and_remote_access_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS malware_apk_c2_and_remote_access_ledger (
                threat_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_category TEXT NOT NULL,
                malicious_pkg_or_tool_name TEXT NOT NULL,
                installer_or_sideload_source TEXT,
                abused_permissions_list TEXT,
                extracted_c2_or_remote_id TEXT NOT NULL,
                session_start_or_install_utc TEXT,
                session_end_utc_iso TEXT,
                overlapped_financial_tx_uids TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Insert Integrity Findings
        for r in integrity_findings:
            cur.execute("""
                INSERT INTO os_integrity_root_and_hook_audit (
                    finding_category, source_vfs_file_id, target_or_requester_pkg,
                    hook_module_or_detail, policy_or_state, event_utc_iso,
                    recovery_classification, forensic_group, dim_existence,
                    dim_access, dim_storage, dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.finding_category.value if hasattr(r.finding_category, "value") else str(r.finding_category),
                r.source_vfs_file_id,
                r.target_or_requester_pkg,
                r.hook_module_or_detail,
                r.policy_or_state,
                r.event_utc_iso,
                r.recovery_classification.value if hasattr(r.recovery_classification, "value") else str(r.recovery_classification),
                r.forensic_group.value if hasattr(r.forensic_group, "value") else str(r.forensic_group),
                r.dim_existence.value if hasattr(r.dim_existence, "value") else str(r.dim_existence),
                r.dim_access.value if hasattr(r.dim_access, "value") else str(r.dim_access),
                r.dim_storage.value if hasattr(r.dim_storage, "value") else str(r.dim_storage),
                r.dim_provenance,
                r.dim_corroboration,
            ))

        # Insert Tamper Records
        for t in tamper_records:
            cur.execute("""
                INSERT INTO clock_tampering_and_deletion_gaps_ledger (
                    tamper_category, severity_level, affected_app_or_database,
                    source_vfs_file_id, monotonic_anchor_detail, claimed_wallclock_utc_iso,
                    true_bracketed_window_utc, courtroom_explanation_note,
                    recovery_classification, forensic_group, dim_existence,
                    dim_access, dim_storage, dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                t.tamper_category.value if hasattr(t.tamper_category, "value") else str(t.tamper_category),
                t.severity_level,
                t.affected_app_or_database,
                t.source_vfs_file_id,
                t.monotonic_anchor_detail,
                t.claimed_wallclock_utc_iso,
                t.true_bracketed_window_utc,
                t.courtroom_explanation_note,
                t.recovery_classification.value if hasattr(t.recovery_classification, "value") else str(t.recovery_classification),
                t.forensic_group.value if hasattr(t.forensic_group, "value") else str(t.forensic_group),
                t.dim_existence.value if hasattr(t.dim_existence, "value") else str(t.dim_existence),
                t.dim_access.value if hasattr(t.dim_access, "value") else str(t.dim_access),
                t.dim_storage.value if hasattr(t.dim_storage, "value") else str(t.dim_storage),
                t.dim_provenance,
                t.dim_corroboration,
            ))

        # Insert Spoof Records
        for s in spoof_records:
            cur.execute("""
                INSERT INTO location_spoofing_and_sensor_contradictions (
                    detection_method, spoofer_package_or_tool, claimed_gps_lat_lon,
                    contradicting_sensor_proof, event_utc_iso, recovery_classification,
                    forensic_group, dim_existence, dim_access, dim_storage,
                    dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                s.detection_method.value if hasattr(s.detection_method, "value") else str(s.detection_method),
                s.spoofer_package_or_tool,
                s.claimed_gps_lat_lon,
                s.contradicting_sensor_proof,
                s.event_utc_iso,
                s.recovery_classification.value if hasattr(s.recovery_classification, "value") else str(s.recovery_classification),
                s.forensic_group.value if hasattr(s.forensic_group, "value") else str(s.forensic_group),
                s.dim_existence.value if hasattr(s.dim_existence, "value") else str(s.dim_existence),
                s.dim_access.value if hasattr(s.dim_access, "value") else str(s.dim_access),
                s.dim_storage.value if hasattr(s.dim_storage, "value") else str(s.dim_storage),
                s.dim_provenance,
                s.dim_corroboration,
            ))

        # Insert Malware Threats
        for m in malware_threats:
            cur.execute("""
                INSERT INTO malware_apk_c2_and_remote_access_ledger (
                    threat_category, malicious_pkg_or_tool_name, installer_or_sideload_source,
                    abused_permissions_list, extracted_c2_or_remote_id,
                    session_start_or_install_utc, session_end_utc_iso,
                    overlapped_financial_tx_uids, recovery_classification,
                    forensic_group, dim_existence, dim_access, dim_storage,
                    dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                m.threat_category.value if hasattr(m.threat_category, "value") else str(m.threat_category),
                m.malicious_pkg_or_tool_name,
                m.installer_or_sideload_source,
                m.abused_permissions_list,
                m.extracted_c2_or_remote_id,
                m.session_start_or_install_utc,
                m.session_end_utc_iso,
                m.overlapped_financial_tx_uids,
                m.recovery_classification.value if hasattr(m.recovery_classification, "value") else str(m.recovery_classification),
                m.forensic_group.value if hasattr(m.forensic_group, "value") else str(m.forensic_group),
                m.dim_existence.value if hasattr(m.dim_existence, "value") else str(m.dim_existence),
                m.dim_access.value if hasattr(m.dim_access, "value") else str(m.dim_access),
                m.dim_storage.value if hasattr(m.dim_storage, "value") else str(m.dim_storage),
                m.dim_provenance,
                m.dim_corroboration,
            ))

        conn.commit()
        conn.close()
