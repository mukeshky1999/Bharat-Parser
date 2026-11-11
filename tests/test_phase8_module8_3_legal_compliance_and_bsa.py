"""
Acceptance Test Suite for Phase 8, Module 8.3:
Indian Legal Evidentiary Compliance Engine, Hierarchical Hash Manifest,
Merkle Chain-of-Custody Ledger & Section 63(4)(c) BSA 2023 Statutory Certificate Generator.

Test Scope (5 Acceptance Tests):
1. test_pre_post_ingest_source_immutability_and_hash_manifest:
   Verifies bit-for-bit pre-ingest vs post-ingest SHA-256 and MD5 immutability (IMMUTABILITY_VERIFIED_IDENTICAL),
   builds 3-Tier Hash Manifest (Tier 1, Tier 2A, Tier 2B, Tier 3), and computes deterministic Case Master Merkle Root.
2. test_section_63_2_c_bsa_anomaly_compensation_auto_drafting:
   Evaluates automated drafting of Section 63(2)(c) BSA proper operation clause;
   verifies that detected clock rollbacks and root modifications trigger precise anomaly isolation bounds
   and statutory non-affectation compensation statements.
3. test_merkle_chain_of_custody_append_and_tamper_detection:
   Enforces cryptographic chaining H_n = SHA256(H_{n-1} | n | timestamp | event | payload);
   detects single-byte database tamper and raises ChainOfCustodyTamperException halting export.
4. test_part_a_and_part_b_statutory_schedule_generation:
   Generates statutory Part A (Investigating Officer / Custodian) and Part B (Forensic Expert)
   prescribed in the Schedule to Section 63(4)(c) of Bharatiya Sakshya Adhiniyam, 2023.
5. test_legal_compliance_master_sqlite_export:
   Validates export of all 3 canonical tables and indexes into legal_compliance_and_section63_bsa.sqlite.
"""

import os
import sqlite3
import pytest

from src.legal_and_bsa.models import (
    HashTier,
    StatutoryRegimeMode,
    ImmutabilityStatus,
    EvidentiaryHashManifestItem,
    Section63BsaCertificateRecord,
    ChainOfCustodyEntry,
    DeponentDetails,
    DeviceMetadata,
    ForensicExpertDetails,
    WorkstationEnvironment,
    IntegrityAuditDisclosure,
)
from src.legal_and_bsa.hash_manifest import HierarchicalHashManifestManager
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from src.legal_and_bsa.chain_of_custody import (
    MerkleChainOfCustodyLedger,
    ChainOfCustodyTamperException,
)
from src.legal_and_bsa.engine import LegalComplianceAndBsaEngine


def test_pre_post_ingest_source_immutability_and_hash_manifest():
    """Acceptance Test 1: Pre/Post Ingest Immutability, 3-Tier Lineage, and Merkle Root."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_hash_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    manifest_mgr = HierarchicalHashManifestManager()

    # Create dummy primary master image
    master_image_path = os.path.join(sandbox, "Seized_Device_Extraction.tar")
    with open(master_image_path, "wb") as f:
        f.write(b"SIMULATED_PRIMARY_EXTRACTION_CONTAINER_BYTES_12345" + b"\x00" * 1024)

    # 1. Compute pre-ingest hash
    pre_sha256, pre_md5 = manifest_mgr.compute_file_hashes(master_image_path)
    assert len(pre_sha256) == 64
    assert len(pre_md5) == 32

    # Simulate read-only VFS consumption (no modification)
    post_sha256, post_md5 = manifest_mgr.compute_file_hashes(master_image_path)
    assert pre_sha256 == post_sha256
    assert pre_md5 == post_md5

    # 2. Register items across 3 tiers
    item_tier1 = manifest_mgr.register_manifest_item(
        hash_tier=HashTier.TIER_1_MASTER_ACQUISITION_SOURCE,
        canonical_path_or_exhibit_name="/evidence/Seized_Device_Extraction.tar",
        artifact_description="Primary Physical Tar Extraction of Seized Mobile Handset",
        file_path=master_image_path,
        parent_manifest_item_uid=None,
    )
    assert item_tier1.post_run_reverified_status == ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL

    # Tier 2A: Original encrypted DB inside VFS
    item_tier2a = manifest_mgr.register_synthetic_manifest_item(
        hash_tier=HashTier.TIER_2A_VFS_ORIGINAL_CONTAINER,
        canonical_path_or_exhibit_name="/data/user/0/com.whatsapp/databases/msgstore.db.crypt15",
        artifact_description="Encrypted WhatsApp Chat Database Store",
        byte_size=1048576,
        sha256_hex="1111111111111111111111111111111111111111111111111111111111111111",
        md5_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        parent_manifest_item_uid=item_tier1.manifest_item_uid,
    )

    # Tier 2B: Decrypted plaintext DB
    item_tier2b = manifest_mgr.register_synthetic_manifest_item(
        hash_tier=HashTier.TIER_2B_UNWRAPPED_OR_CARVED_DERIVATIVE,
        canonical_path_or_exhibit_name="/staging/whatsapp/msgstore.db",
        artifact_description="Decrypted WhatsApp SQLite Database Store",
        byte_size=1048576,
        sha256_hex="2222222222222222222222222222222222222222222222222222222222222222",
        md5_hex="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        parent_manifest_item_uid=item_tier2a.manifest_item_uid,
        crypto_unwrap_provenance_note="AES-256-GCM decrypted using /files/key",
    )

    # Tier 3: Exported Court Exhibit
    manifest_mgr.register_synthetic_manifest_item(
        hash_tier=HashTier.TIER_3_EXPORTED_COURT_EXHIBIT,
        canonical_path_or_exhibit_name="Exhibit_01_WhatsApp_Finance_Dossier.pdf",
        artifact_description="Courtroom Evidentiary PDF Dossier for WhatsApp Chat Records",
        byte_size=524288,
        sha256_hex="3333333333333333333333333333333333333333333333333333333333333333",
        md5_hex="cccccccccccccccccccccccccccccccc",
        parent_manifest_item_uid=item_tier2b.manifest_item_uid,
    )

    # 3. Compute Case Master Merkle Root
    merkle_root = manifest_mgr.compute_case_merkle_root()
    assert len(merkle_root) == 64

    # Changing any byte in manifest changes the Merkle root
    manifest_mgr.items[0].sha256_hex = "f" * 64
    tampered_root = manifest_mgr.compute_case_merkle_root()
    assert tampered_root != merkle_root


def test_section_63_2_c_bsa_anomaly_compensation_auto_drafting():
    """Acceptance Test 2: Section 63(2)(c) proper operation & precision anomaly compensation."""
    generator = Section63BsaCertificateGenerator()

    # Case 1: Pristine operating state (Zero integrity anomalies)
    clean_audit = IntegrityAuditDisclosure(
        root_or_jailbreak_detected=False,
        clock_tampering_detected=False,
        malware_or_overlay_detected=False,
    )
    clause_clean = generator.synthesize_sec63_2_c_clause(clean_audit)
    assert "operating normally and properly at all material times" in clause_clean
    assert "without root modification, clock rollback" in clause_clean

    # Case 2: System clock rollback of -48.5 hours and Magisk root detected
    anomaly_audit = IntegrityAuditDisclosure(
        root_or_jailbreak_detected=True,
        root_details="Magisk v27.0 root policy active with Zygisk hook",
        clock_tampering_detected=True,
        clock_tampering_details="Manual system clock rollback of -48.5 hours at ROWID 501 of mmssms.db",
        monotonic_counter_bounds="Bounded via ROWID 500..505 and mach_continuous_time monotonic ticks",
        malware_or_overlay_detected=False,
    )
    clause_anomaly = generator.synthesize_sec63_2_c_clause(anomaly_audit)

    # Must disclose exact anomalies and statutory Section 63(2)(c) non-affectation attestation
    assert "-48.5 hours" in clause_anomaly
    assert "Magisk v27.0" in clause_anomaly
    assert "ROWID 501" in clause_anomaly
    assert "Section 63(2)(c) of the Bharatiya Sakshya Adhiniyam, 2023" in clause_anomaly
    assert "were not such as to affect the integrity of the remaining electronic records" in clause_anomaly


def test_merkle_chain_of_custody_append_and_tamper_detection():
    """Acceptance Test 3: Append-only hash chain integrity & tamper rejection."""
    ledger = MerkleChainOfCustodyLedger()
    case_uuid = "CASE-2026-DEL-0412"
    master_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    ledger.initialize_chain(case_uuid=case_uuid, master_sha256=master_sha256)
    assert ledger.genesis_hash_hex is not None
    assert len(ledger.genesis_hash_hex) == 64

    # Append 5 sequential audit events
    events = [
        ("SYSTEM_PHASE_1_INGEST", "CASE_INITIALIZED", {"case_id": case_uuid}),
        ("EXAMINER_VERMA", "PRE_INGEST_HASH_LOCKED", {"sha256": master_sha256}),
        ("SYSTEM_PHASE_1_VFS", "VFS_MOUNTED_READ_ONLY", {"mode": "immutable"}),
        ("SYSTEM_PHASE_2_CRYPTO", "DERIVATIVE_UNWRAPPED", {"file": "msgstore.db"}),
        ("SYSTEM_MODULE_8_3", "CERTIFICATE_ISSUED", {"cert_ref": "BSA63-2026-001"}),
    ]

    for actor, action, payload in events:
        ledger.append_entry(actor=actor, event_action_type=action, payload_dict=payload)

    # Verify intact chain
    assert ledger.verify_chain_integrity() is True
    assert len(ledger.entries) == 5

    # Tamper with entry #3 payload in memory
    ledger.entries[2].canonical_payload_json = '{"mode": "TAMPERED_READ_WRITE"}'

    # Verification must fail and raise ChainOfCustodyTamperException
    with pytest.raises(ChainOfCustodyTamperException) as excinfo:
        ledger.verify_chain_integrity()
    assert "sequence 3" in str(excinfo.value).lower() or "seq 3" in str(excinfo.value).lower() or "3" in str(excinfo.value)


def test_part_a_and_part_b_statutory_schedule_generation():
    """Acceptance Test 4: Generation of Schedule to Section 63(4)(c) BSA 2023 (Part A & Part B)."""
    generator = Section63BsaCertificateGenerator()

    deponent = DeponentDetails(
        name="Rajesh Kumar Verma",
        designation="Inspector of Police",
        father_name="Late S. K. Verma",
        age=45,
        police_station="Cyber Crime Police Station",
        district="New Delhi",
        state="Delhi",
        fir_number="FIR No. 412/2026",
        sections_of_law="Sections 316(2), 318(4) BNS, 2023 r/w 66D IT Act",
        custody_mode="SEIZED_OFFICIAL_CUSTODY",
        seizure_memo_ref="Panchnama dated 01-11-2026",
    )

    device = DeviceMetadata(
        device_type="Smartphone",
        make_and_brand="Samsung Electronics",
        model_name="Galaxy S24 Ultra (SM-S928B)",
        imei_1="354829104928172",
        imei_2="354829104928180",
        serial_number="R58N20ABCDE",
        chipset_details="Snapdragon 8 Gen 3 for Galaxy",
        operating_system="Android 14 (OneUI 6.1, Kernel 6.1.43)",
        sim_iccids=["89918720192837461928"],
        phone_numbers=["+919876543210"],
    )

    expert = ForensicExpertDetails(
        name="Dr. Sunita Sharma",
        designation="Senior Scientific Officer (Cyber Forensics)",
        laboratory_unit="Central Forensic Science Laboratory (CFSL)",
        qualifications="M.Tech (Cyber Security), Ph.D. (Digital Forensics)",
    )

    workstation = WorkstationEnvironment(
        workstation_hostname="CFSL-CYBER-WS04",
        os_version="Windows 11 Enterprise (Build 26100)",
        engine_version="Forensic Data Parser v8.2.0-bsa",
        git_commit_hash="a1b2c3d4e5f67890",
        vfs_mount_mode="READ_ONLY_IMMUTABLE",
        processing_start_ist="2026-11-05 10:00:00 IST (+05:30)",
        processing_completion_ist="2026-11-05 11:30:00 IST (+05:30)",
    )

    audit = IntegrityAuditDisclosure(
        root_or_jailbreak_detected=False,
        clock_tampering_detected=False,
        malware_or_overlay_detected=False,
    )

    cert_record, rendered_text = generator.generate_section_63_certificate(
        certificate_reference_no="BSA63-2026-FIR0412-EX01",
        statutory_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
        deponent=deponent,
        device=device,
        expert=expert,
        workstation=workstation,
        integrity_audit=audit,
        master_image_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        master_image_md5="d41d8cd98f00b204e9800998ecf8427e",
        case_merkle_root_sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    )

    assert cert_record.certificate_reference_no == "BSA63-2026-FIR0412-EX01"
    assert "PART A" in rendered_text
    assert "PART B" in rendered_text
    assert "Rajesh Kumar Verma" in rendered_text
    assert "SM-S928B" in rendered_text
    assert "354829104928172" in rendered_text
    assert "Dr. Sunita Sharma" in rendered_text
    assert "READ_ONLY_IMMUTABLE" in rendered_text
    assert "Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023" in rendered_text


def test_legal_compliance_master_sqlite_export():
    """Acceptance Test 5: Export into legal_compliance_and_section63_bsa.sqlite."""
    output_db = os.path.join(".", ".workspace_tmp", "legal_compliance_and_section63_bsa.sqlite")
    if os.path.exists(output_db):
        os.remove(output_db)

    engine = LegalComplianceAndBsaEngine()

    manifest_items = [
        EvidentiaryHashManifestItem(
            manifest_item_uid=1,
            hash_tier=HashTier.TIER_1_MASTER_ACQUISITION_SOURCE,
            canonical_path_or_exhibit_name="/evidence/dump.tar",
            artifact_description="Primary acquisition archive",
            byte_size=1048576,
            sha256_hex="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5_hex="d41d8cd98f00b204e9800998ecf8427e",
            blake3_hex=None,
            parent_manifest_item_uid=None,
            crypto_unwrap_provenance_note=None,
            post_run_reverified_status=ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL,
            hashed_at_utc_iso="2026-11-05T10:00:00.000Z",
        )
    ]

    cert_records = [
        Section63BsaCertificateRecord(
            certificate_uid=1,
            certificate_reference_no="BSA63-2026-FIR0412-EX01",
            statutory_regime_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
            case_fir_or_rc_number="FIR No. 412/2026",
            part_a_deponent_details_json='{"name": "Rajesh Kumar Verma"}',
            part_a_device_metadata_json='{"model": "SM-S928B"}',
            part_b_expert_details_json='{"name": "Dr. Sunita Sharma"}',
            part_b_workstation_env_json='{"vfs_mount_mode": "READ_ONLY_IMMUTABLE"}',
            sec63_2_c_integrity_clause_text="Device operated normally at all material times.",
            tier1_master_image_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            case_merkle_root_sha256="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            rendered_certificate_pdf_sha256=None,
            generated_at_ist_iso="2026-11-05 11:30:00 IST (+05:30)",
        )
    ]

    audit_entries = [
        ChainOfCustodyEntry(
            seq_no=1,
            timestamp_utc_ns=1762348800000000000,
            timestamp_ist_iso="2026-11-05 10:00:00 IST (+05:30)",
            actor_or_subsystem="SYSTEM",
            event_action_type="CASE_INITIALIZED",
            canonical_payload_json='{"case": "412"}',
            previous_entry_hash_hex="0" * 64,
            current_entry_hash_hex="a" * 64,
        )
    ]

    engine.export_master_database(
        output_db_path=output_db,
        manifest_items=manifest_items,
        certificates=cert_records,
        audit_entries=audit_entries,
    )

    assert os.path.exists(output_db)
    conn = sqlite3.connect(output_db)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM evidentiary_hash_manifest_ledger;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM section63_bsa_certificates_registry;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM chain_of_custody_merkle_ledger;")
    assert cur.fetchone()[0] == 1

    conn.close()
