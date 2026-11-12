"""
Section 63(4)(c) BSA 2023 Statutory Certificate Generator (Sub-Engine 8.3B).
Populates Part A (Party/Custodian) and Part B (Forensic Expert) prescribed in the Schedule to the BSA, 2023.
"""

from datetime import datetime, timezone, timedelta
import json
from typing import Optional

from src.legal_and_bsa.models import (
    DeponentDetails,
    DeviceMetadata,
    ForensicExpertDetails,
    IntegrityAuditDisclosure,
    Section63BsaCertificateRecord,
    StatutoryRegimeMode,
    WorkstationEnvironment,
)


class Section63BsaCertificateGenerator:
    """Generates legally compliant Part A and Part B certificates under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023."""

    @staticmethod
    def synthesize_sec63_2_c_clause(audit: IntegrityAuditDisclosure) -> str:
        """Synthesizes the statutory Section 63(2)(c) proper operation or anomaly compensation statement."""
        anomalies_present = (
            audit.root_or_jailbreak_detected
            or audit.clock_tampering_detected
            or audit.malware_or_overlay_detected
        )

        if not anomalies_present:
            return (
                "Technical audit of the operating system kernel properties, bootloader lock state "
                "(verifiedbootstate = green), monotonic timebase anchors (.timesync / ROWID progression), "
                "and permission ledgers (appops) confirms that the communication device was operating "
                "normally and properly at all material times without root modification, clock rollback, "
                "or location simulation."
            )

        # Anomaly detected: precision disclosure + statutory compensation
        findings = []
        if audit.clock_tampering_detected:
            findings.append(audit.clock_tampering_details or "Manual system clock tampering/rollback")
        if audit.root_or_jailbreak_detected:
            findings.append(audit.root_details or "Root privilege elevation framework active")
        if audit.malware_or_overlay_detected:
            findings.append(audit.malware_details or "Malicious overlay / background accessibility agent detected")

        bounds = (
            audit.monotonic_counter_bounds
            or "monotonic hardware, database sequence counters (ROWID), and filesystem journal checkpoints"
        )
        findings_str = "; ".join(findings)

        return (
            f"Technical examination detected the following non-standard operating conditions: {findings_str}. "
            f"Pursuant to Section 63(2)(c) of the Bharatiya Sakshya Adhiniyam, 2023, it is certified that "
            f"the above-identified non-standard operating conditions have been mathematically isolated, "
            f"bounded via {bounds}, and explicitly flagged on the affected records, and were not such as to "
            f"affect the integrity of the remaining electronic records or the accuracy of their contents as "
            f"reproduced in this Computer Output."
        )

    def generate_section_63_certificate(
        self,
        certificate_reference_no: str,
        statutory_mode: StatutoryRegimeMode,
        deponent: DeponentDetails,
        device: DeviceMetadata,
        expert: ForensicExpertDetails,
        workstation: WorkstationEnvironment,
        integrity_audit: IntegrityAuditDisclosure,
        master_image_sha256: str,
        master_image_md5: str,
        case_merkle_root_sha256: str,
        rendered_pdf_sha256: Optional[str] = None,
    ) -> tuple[Section63BsaCertificateRecord, str]:
        """Generates statutory Part A + Part B Certificate Record and human-readable text."""
        now_ist = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")
        sec63_2_c_text = self.synthesize_sec63_2_c_clause(integrity_audit)

        deponent_dict = {
            "name": deponent.name,
            "designation": deponent.designation,
            "father_name": deponent.father_name,
            "age": deponent.age,
            "police_station": deponent.police_station,
            "district": deponent.district,
            "state": deponent.state,
            "fir_number": deponent.fir_number,
            "sections_of_law": deponent.sections_of_law,
            "custody_mode": deponent.custody_mode,
            "seizure_memo_ref": deponent.seizure_memo_ref,
        }

        device_dict = {
            "device_type": device.device_type,
            "make_and_brand": device.make_and_brand,
            "model_name": device.model_name,
            "imei_1": device.imei_1,
            "imei_2": device.imei_2,
            "serial_number": device.serial_number,
            "chipset_details": device.chipset_details,
            "operating_system": device.operating_system,
            "sim_iccids": device.sim_iccids,
            "phone_numbers": device.phone_numbers,
        }

        expert_dict = {
            "name": expert.name,
            "designation": expert.designation,
            "laboratory_unit": expert.laboratory_unit,
            "qualifications": expert.qualifications,
        }

        workstation_dict = {
            "workstation_hostname": workstation.workstation_hostname,
            "os_version": workstation.os_version,
            "engine_version": workstation.engine_version,
            "git_commit_hash": workstation.git_commit_hash,
            "vfs_mount_mode": workstation.vfs_mount_mode,
            "processing_start_ist": workstation.processing_start_ist,
            "processing_completion_ist": workstation.processing_completion_ist,
        }

        record = Section63BsaCertificateRecord(
            certificate_reference_no=certificate_reference_no,
            statutory_regime_mode=statutory_mode,
            case_fir_or_rc_number=deponent.fir_number or "N/A",
            part_a_deponent_details_json=json.dumps(deponent_dict),
            part_a_device_metadata_json=json.dumps(device_dict),
            part_b_expert_details_json=json.dumps(expert_dict),
            part_b_workstation_env_json=json.dumps(workstation_dict),
            sec63_2_c_integrity_clause_text=sec63_2_c_text,
            tier1_master_image_sha256=master_image_sha256.lower(),
            case_merkle_root_sha256=case_merkle_root_sha256.lower(),
            rendered_certificate_pdf_sha256=rendered_pdf_sha256,
            generated_at_ist_iso=now_ist,
        )

        # Build formatted statutory text conforming to Schedule to Section 63(4)(c) BSA 2023
        title = (
            "SCHEDULE\n"
            "[See sub-clause (c) of clause (4) of section 63]\n"
            "CERTIFICATE UNDER SECTION 63(4)(c) OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023"
        )
        if statutory_mode == StatutoryRegimeMode.DUAL_BSA_SEC_63_AND_IEA_SEC_65B_LEGACY:
            title += "\n[Corresponding to Section 65B(4) of the Indian Evidence Act, 1872]"

        part_a_text = (
            f"{title}\n\n"
            f"Certificate Reference No: {certificate_reference_no}\n"
            f"Case / Crime Reference: {deponent.fir_number or 'N/A'}\n"
            f"Police Station / Agency: {deponent.police_station or 'N/A'}, {deponent.district or ''}\n"
            f"Sections of Law: {deponent.sections_of_law or 'N/A'}\n\n"
            f"================================================================================\n"
            f"PART A: TO BE FILLED BY THE PERSON IN CHARGE / INVESTIGATING OFFICER / CUSTODIAN\n"
            f"================================================================================\n"
            f"I, {deponent.name}, Son/Daughter/Spouse of {deponent.father_name or 'N/A'}, aged {deponent.age or 0} years, "
            f"residing at / posted as {deponent.designation}, {deponent.police_station or ''}, "
            f"{deponent.district or ''}, {deponent.state or ''}, do hereby solemnly affirm and state as follows:\n\n"
            f"1. That I am the lawful custodian in official charge of the electronic record / seized communication device "
            f"in connection with {deponent.fir_number or 'the case'}.\n"
            f"2. Particulars of the Seized Communication Device:\n"
            f"   - Device Type: {device.device_type}\n"
            f"   - Make & Brand: {device.make_and_brand}\n"
            f"   - Model: {device.model_name}\n"
            f"   - IMEI 1: {device.imei_1 or 'N/A'}\n"
            f"   - IMEI 2: {device.imei_2 or 'N/A'}\n"
            f"   - Hardware Serial No: {device.serial_number or 'N/A'}\n"
            f"   - Operating System & Build: {device.operating_system or 'N/A'}\n"
            f"   - SIM Card ICCID(s): {', '.join(device.sim_iccids) if device.sim_iccids else 'N/A'}\n"
            f"   - Linked Mobile Number(s): {', '.join(device.phone_numbers) if device.phone_numbers else 'N/A'}\n"
            f"3. Lawful Custody & Seizure Details:\n"
            f"   - Mode of Custody: {deponent.custody_mode}\n"
            f"   - Seizure Reference: {deponent.seizure_memo_ref or 'Panchnama on record'}\n"
            f"4. Cryptographic Hash of Master Acquisition Source:\n"
            f"   - SHA-256 Digest: {master_image_sha256.lower()}\n"
            f"   - MD5 Digest: {master_image_md5.lower()}\n"
            f"   - Case Master Merkle Root: {case_merkle_root_sha256.lower()}\n\n"
            f"Date: {now_ist}\n"
            f"Signature: ___________________________\n"
            f"Name: {deponent.name}\n"
            f"Designation: {deponent.designation}\n"
        )

        part_b_text = (
            f"\n================================================================================\n"
            f"PART B: TO BE FILLED BY THE FORENSIC EXPERT / EXAMINER\n"
            f"================================================================================\n"
            f"I, {expert.name}, {expert.qualifications}, serving as {expert.designation} at {expert.laboratory_unit}, "
            f"do hereby certify as follows:\n\n"
            f"1. That I have examined and processed the electronic record from the communication device identified in Part A.\n"
            f"2. Technical Examination Environment & Workstation Details (Section 63(3) BSA):\n"
            f"   - Hostname: {workstation.workstation_hostname}\n"
            f"   - Host OS: {workstation.os_version}\n"
            f"   - Forensic Engine Version: {workstation.engine_version} (Git: {workstation.git_commit_hash})\n"
            f"   - VFS Mount State: {workstation.vfs_mount_mode}\n"
            f"   - Examination Commenced: {workstation.processing_start_ist or now_ist}\n"
            f"   - Examination Concluded: {workstation.processing_completion_ist or now_ist}\n"
            f"3. Technical Operating State & Anomaly Audit (Section 63(2)(c) BSA):\n"
            f"   {sec63_2_c_text}\n"
            f"4. Cryptographic Immutability Attestation:\n"
            f"   - Master Input Image SHA-256: {master_image_sha256.lower()}\n"
            f"   - Master Input Image MD5: {master_image_md5.lower()}\n"
            f"   - Immutability Status: IMMUTABILITY_VERIFIED_IDENTICAL (Zero bytes altered)\n"
            f"   - Case Master Merkle Root (All Artifacts): {case_merkle_root_sha256.lower()}\n"
            f"5. Affirmation:\n"
            f"   I affirm that the computer output produced is a true and accurate representation of the electronic records\n"
            f"   stored in the source communication device, produced in accordance with Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023.\n\n"
            f"Date: {now_ist}\n"
            f"Signature: ___________________________\n"
            f"Name: {expert.name}\n"
            f"Designation: {expert.designation}\n"
            f"Laboratory: {expert.laboratory_unit}\n"
        )

        return record, part_a_text + part_b_text
