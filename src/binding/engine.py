"""
Master Engine: SIM & Hardware Device-Binding Forensic Engine.
Coordinates Sub-Engines 3.2A, 3.2B, 3.2C, and 3.2D to reconstruct physical SIM card history,
outbound VMN binding SMS logs, embedded NPCI Common Library credentials, and remote ghost-binding trojan detection.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 3.2 Spec.
"""

from pathlib import Path
import sqlite3
from typing import List, Optional, Tuple, Union

from src.binding.cl_vault import NPCICommonLibraryParser
from src.binding.models import (
    DeviceSIMCardHistoryRecord,
    NPCICommonLibraryVaultRecord,
    UPIOutboundBindingSMSAudit,
)
from src.binding.sms_audit import OutboundBindingSMSDecoder
from src.binding.telephony import TelephonyProviderDecoder
from src.binding.trojan_detector import GhostSIMBindingTrojanDetector


class SIMBindingForensicEngine:
    """Master engine orchestrating SIM card ledgering, outbound SMS audit, and CL vault extraction."""

    def __init__(self) -> None:
        self.telephony_decoder = TelephonyProviderDecoder()
        self.sms_decoder = OutboundBindingSMSDecoder()
        self.cl_parser = NPCICommonLibraryParser()
        self.trojan_detector = GhostSIMBindingTrojanDetector()

    def analyze_sim_and_sms(
        self,
        telephony_db_path: Union[str, Path],
        sms_db_path: Union[str, Path],
        cl_records: Optional[List[NPCICommonLibraryVaultRecord]] = None,
        os_platform: str = "ANDROID",
    ) -> Tuple[List[DeviceSIMCardHistoryRecord], List[UPIOutboundBindingSMSAudit]]:
        """
        Executes unified analysis of telephony provider database and SMS database.
        Returns:
            Tuple of (sim_ledger_records, outbound_binding_sms_audit_records).
        """
        sim_records = self.telephony_decoder.decode_telephony_db(
            db_path=telephony_db_path,
            os_platform=os_platform,
        )

        sms_audits = self.sms_decoder.audit_outbound_sms(
            sms_db_path=sms_db_path,
            sim_ledger=sim_records,
            cl_records=cl_records,
        )

        return sim_records, sms_audits

    def parse_cl_preferences(
        self,
        file_path: Union[str, Path],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Optional[NPCICommonLibraryVaultRecord]:
        """Parses an individual NPCI Common Library preference XML file."""
        return self.cl_parser.parse_cl_preferences(
            file_path=file_path,
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
        )

    def scan_app_sandbox_for_cl_vaults(
        self,
        app_sandbox_dir: Union[str, Path],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> List[NPCICommonLibraryVaultRecord]:
        """Scans an extracted app sandbox directory for NPCI Common Library stores."""
        return self.cl_parser.scan_app_sandbox(
            app_sandbox_dir=app_sandbox_dir,
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
        )

    def export_to_ledger(
        self,
        sim_records: List[DeviceSIMCardHistoryRecord],
        sms_audits: List[UPIOutboundBindingSMSAudit],
        cl_records: List[NPCICommonLibraryVaultRecord],
        ledger_path: Union[str, Path],
    ) -> None:
        """
        Initializes npci_sim_binding_engine.sqlite schema and persists all records:
        1. device_sim_card_history_ledger
        2. upi_outbound_binding_sms_audit
        3. npci_common_library_vault_records
        """
        target = Path(ledger_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(target)
        cur = conn.cursor()

        try:
            # 1. device_sim_card_history_ledger
            cur.execute("""
                CREATE TABLE IF NOT EXISTS device_sim_card_history_ledger (
                    sim_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    os_platform TEXT NOT NULL,
                    android_sub_id INTEGER,
                    iccid_20_digit TEXT,
                    imsi_number TEXT,
                    msisdn_phone_number TEXT,
                    carrier_display_name TEXT,
                    mcc_mnc_code TEXT,
                    sim_form_factor TEXT NOT NULL,
                    seizure_slot_state TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    first_observed_utc_iso TEXT,
                    last_observed_utc_iso TEXT
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sim_iccid
                ON device_sim_card_history_ledger (iccid_20_digit);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sim_sub_id
                ON device_sim_card_history_ledger (android_sub_id);
            """)

            # 2. upi_outbound_binding_sms_audit
            cur.execute("""
                CREATE TABLE IF NOT EXISTS upi_outbound_binding_sms_audit (
                    binding_sms_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_vfs_file_id INTEGER NOT NULL,
                    sms_row_id INTEGER,
                    recovery_classification TEXT NOT NULL,
                    destination_vmn_number TEXT NOT NULL,
                    sms_payload_raw TEXT NOT NULL,
                    inferred_target_psp_or_bank TEXT,
                    android_sub_id INTEGER,
                    resolved_sim_iccid TEXT,
                    resolved_sim_msisdn TEXT,
                    creator_package_name TEXT,
                    delivery_status TEXT NOT NULL,
                    sent_utc_iso TEXT NOT NULL,
                    binding_attribution_verdict TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_vmn
                ON upi_outbound_binding_sms_audit (destination_vmn_number);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_sub_id
                ON upi_outbound_binding_sms_audit (android_sub_id);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_verdict
                ON upi_outbound_binding_sms_audit (binding_attribution_verdict);
            """)

            # 3. npci_common_library_vault_records
            cur.execute("""
                CREATE TABLE IF NOT EXISTS npci_common_library_vault_records (
                    cl_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    bound_sim_iccid_in_app TEXT,
                    bound_sim_sub_id_in_app INTEGER,
                    bound_mobile_msisdn TEXT,
                    bound_hardware_device_id TEXT,
                    cl_k0_token_present INTEGER DEFAULT 0,
                    matched_keystore_alias TEXT,
                    binding_registered_utc_iso TEXT
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_cl_app_id
                ON npci_common_library_vault_records (app_instance_id);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_cl_bound_iccid
                ON npci_common_library_vault_records (bound_sim_iccid_in_app);
            """)

            # Insert SIM records
            for s in sim_records:
                recovery_val = (
                    s.recovery_classification.value
                    if hasattr(s.recovery_classification, "value")
                    else str(s.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO device_sim_card_history_ledger (
                        os_platform,
                        android_sub_id,
                        iccid_20_digit,
                        imsi_number,
                        msisdn_phone_number,
                        carrier_display_name,
                        mcc_mnc_code,
                        sim_form_factor,
                        seizure_slot_state,
                        recovery_classification,
                        first_observed_utc_iso,
                        last_observed_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        s.os_platform,
                        s.android_sub_id,
                        s.iccid_20_digit,
                        s.imsi_number,
                        s.msisdn_phone_number,
                        s.carrier_display_name,
                        s.mcc_mnc_code,
                        s.sim_form_factor,
                        s.seizure_slot_state,
                        recovery_val,
                        s.first_observed_utc_iso,
                        s.last_observed_utc_iso,
                    ),
                )

            # Insert Outbound SMS audits
            for a in sms_audits:
                recovery_val = (
                    a.recovery_classification.value
                    if hasattr(a.recovery_classification, "value")
                    else str(a.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO upi_outbound_binding_sms_audit (
                        source_vfs_file_id,
                        sms_row_id,
                        recovery_classification,
                        destination_vmn_number,
                        sms_payload_raw,
                        inferred_target_psp_or_bank,
                        android_sub_id,
                        resolved_sim_iccid,
                        resolved_sim_msisdn,
                        creator_package_name,
                        delivery_status,
                        sent_utc_iso,
                        binding_attribution_verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        a.source_vfs_file_id,
                        a.sms_row_id,
                        recovery_val,
                        a.destination_vmn_number,
                        a.sms_payload_raw,
                        a.inferred_target_psp_or_bank,
                        a.android_sub_id,
                        a.resolved_sim_iccid,
                        a.resolved_sim_msisdn,
                        a.creator_package_name,
                        a.delivery_status,
                        a.sent_utc_iso,
                        a.binding_attribution_verdict,
                    ),
                )

            # Insert CL records
            for c in cl_records:
                cur.execute(
                    """
                    INSERT INTO npci_common_library_vault_records (
                        app_instance_id,
                        source_vfs_file_id,
                        bound_sim_iccid_in_app,
                        bound_sim_sub_id_in_app,
                        bound_mobile_msisdn,
                        bound_hardware_device_id,
                        cl_k0_token_present,
                        matched_keystore_alias,
                        binding_registered_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        c.app_instance_id,
                        c.source_vfs_file_id,
                        c.bound_sim_iccid_in_app,
                        c.bound_sim_sub_id_in_app,
                        c.bound_mobile_msisdn,
                        c.bound_hardware_device_id,
                        c.cl_k0_token_present,
                        c.matched_keystore_alias,
                        c.binding_registered_utc_iso,
                    ),
                )

            conn.commit()

        finally:
            conn.close()
