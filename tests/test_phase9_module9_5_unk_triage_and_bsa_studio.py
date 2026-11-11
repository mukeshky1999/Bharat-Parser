"""
Acceptance Test Suite for Phase 9, Module 9.5:
Interactive Zero-Omission (UNK) Triage Workbench, Cryptographic Key-Broker Unlocker Console
& The WYSIWYG Section 63(4)(c) BSA 2023 Courtroom Report Studio.

Test Scope (5 Acceptance Tests):
1. test_4kb_sliding_window_entropy_skyline_and_zero_code_schema_promotion:
   Verifies 4 KB sliding-window block entropy H(b_k) (separating 4 KB plaintext header from 60 KB ciphertext),
   256-bin chi-squared byte histogram, and zero-code SQLite table promotion into super-timeline & entity graph.
2. test_key_broker_incremental_dag_hot_patch_under_3_seconds:
   Evaluates candidate password harvesting, unlocking locked vault with passphrase 'Vikram@786',
   and executing targeted 5-step incremental DAG hot-patching in < 3.0 seconds without full re-ingest.
3. test_1930_ncrp_freeze_deconfliction_and_victim_safeguard_lock:
   Validates 3-tier freeze de-confliction: locking Complainant/Victim account with [VICTIM / COMPLAINANT - DO NOT FREEZE],
   excluding known utility billers (IRCTC/BESCOM), and exporting 14-column 1930 NCRP CSV.
4. test_section_63_bsa_preflight_gate_and_merkle_tamper_block:
   Evaluates mandatory 6-point pre-flight compliance gate: blocking export if deponent fields are blank,
   if master SHA-256 hashes mismatch, or if Merkle audit chain is tampered with.
5. test_wysiwyg_dual_preview_master_court_vs_sec230_bnss_defense_copy:
   Validates side-by-side dual preview of unredacted Master Court copy and Section 230 BNSS Defense Disclosure copy
   with statutory POCSO placeholder cards (P. Gopalkrishnan safeguard) and Sec 72 BNS victim redactions.
"""

import os
import sqlite3
import time
import pytest

from src.unk_triage_and_bsa_studio.models import (
    SemanticColumnRole,
    BlockEntropyResult,
    ChiSquareHistogramResult,
    PromotedSchemaRecord,
    CandidateSecretRecord,
    IncrementalHotPatchResult,
    FreezeCandidateAccount,
    PreFlightCheckResult,
    BsaDossierDualPreview,
)
from src.unk_triage_and_bsa_studio.entropy_profiler import (
    SlidingWindowEntropyProfiler,
)
from src.unk_triage_and_bsa_studio.schema_mapper import (
    ZeroCodeSchemaMapper,
)
from src.unk_triage_and_bsa_studio.key_broker_hotpatcher import (
    KeyBrokerHotPatcher,
)
from src.unk_triage_and_bsa_studio.freeze_deconfliction import (
    NodalFreezeDeconflictionCenter,
)
from src.unk_triage_and_bsa_studio.bsa_report_studio import (
    BsaReportStudioEngine,
)
from src.unk_triage_and_bsa_studio.engine import (
    UnkTriageAndBsaStudioMasterEngine,
)


def test_4kb_sliding_window_entropy_skyline_and_zero_code_schema_promotion():
    """Acceptance Test 1: 4 KB sliding-window entropy skyline H(b_k) and zero-code table promotion."""
    profiler = SlidingWindowEntropyProfiler(block_size_bytes=4096)
    mapper = ZeroCodeSchemaMapper()

    # 1. Construct a synthetic 65,536-byte (16 x 4096) hybrid container:
    # Block 0 (4 KB): Plaintext ASCII JSON header (H ~ 4.5 bits/byte)
    # Blocks 1..15 (60 KB): High-entropy pseudo-random ciphertext (H ~ 7.99 bits/byte)
    plaintext_chunk = (b'{"table":"hisab_ledger","columns":["jama_ts","party_no","amount"],"status":"active"}\n' * 50)[:4096]
    # High-entropy bytes: cycling byte pattern with high diversity
    ciphertext_chunk = bytes([((i * 101 + 37) % 256) for i in range(15 * 4096)])
    hybrid_file_bytes = plaintext_chunk + ciphertext_chunk

    entropy_profile: BlockEntropyResult = profiler.compute_block_entropy_skyline(hybrid_file_bytes)

    assert len(entropy_profile.block_entropies) == 16
    # Block 0 has low/moderate plaintext entropy
    assert entropy_profile.block_entropies[0] < 5.5
    # Blocks 1 through 15 have high ciphertext entropy (> 7.9)
    assert all(h > 7.9 for h in entropy_profile.block_entropies[1:])

    # Verify 4-class byte composition on Block 0 (dominant printable ASCII)
    b0_comp = entropy_profile.block_compositions[0]
    assert b0_comp.printable_ascii_pct > 80.0

    # Verify 256-bin Chi-Square histogram
    hist_result: ChiSquareHistogramResult = profiler.compute_256bin_chi_squared(ciphertext_chunk)
    assert len(hist_result.observed_counts) == 256
    assert hist_result.ideal_uniform_reference == (15 * 4096) / 256.0

    # 2. Interactive Zero-Code Schema Promotion for Table `hisab_ledger`
    sandbox = os.path.join(".", ".workspace_tmp", "test_triage_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "unk_triage_and_keybroker.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    mapper.initialize_triage_db(db_path)

    raw_table_rows = [
        {"jama_ts": 1762348800000 + i * 1000, "party_no": f"+9198765432{i:02d}", "amount": 50000.0 + i * 100}
        for i in range(60)
    ]

    column_mappings = {
        "jama_ts": SemanticColumnRole.TIMESTAMP_EPOCH_MS,
        "party_no": SemanticColumnRole.ACTOR_SOURCE_IDENTIFIER,
        "amount": SemanticColumnRole.FINANCIAL_OR_CRYPTO_AMOUNT,
    }

    promotion_record: PromotedSchemaRecord = mapper.promote_table_to_case(
        db_path=db_path,
        vfs_file_id=501,
        table_name="hisab_ledger",
        column_roles=column_mappings,
        raw_rows=raw_table_rows,
        examiner_name="Inspector R. K. Verma",
    )

    assert promotion_record.promoted_rows_count == 60
    assert promotion_record.table_name == "hisab_ledger"
    assert promotion_record.mapping_uid > 0

    # Verify persistence in unk_promoted_custom_schemas_ledger
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM unk_promoted_custom_schemas_ledger;")
    assert cur.fetchone()[0] == 1
    conn.close()


def test_key_broker_incremental_dag_hot_patch_under_3_seconds():
    """Acceptance Test 2: Password harvester, vault unlock, and 5-step DAG hot-patching in < 3.0s."""
    hotpatcher = KeyBrokerHotPatcher()

    # 1. Candidate Password Harvester collects device candidate passphrases
    device_secrets = hotpatcher.harvest_candidate_secrets(
        notes_strings=["Meeting at 5pm", "WiFi password is pass123", "Secret code Vikram@786"],
        autofill_passwords=["HdfcNet@2025", "Vikram@786"],
        account_names=["VIKRAM SINGH"],
        account_dobs=["15/08/1995"],
    )

    secret_values = [s.secret_value for s in device_secrets]
    assert "Vikram@786" in secret_values
    # Includes Indian bank PDF permutation: First 4 name + DDMM -> "VIKR1508"
    assert any("VIKR1508" in s for s in secret_values)

    # 2. Test unlock & execute 5-step Incremental DAG Hot-Patch in < 3.0 seconds
    t0 = time.perf_counter()
    patch_result: IncrementalHotPatchResult = hotpatcher.execute_incremental_hotpatch(
        vfs_file_id=892,
        secret="Vikram@786",
        container_type="SQLCIPHER_V4_DATABASE",
        simulated_unlocked_records=[
            {"type": "FINANCIAL_TRANSACTION", "amount": 180000.0, "utr": "630914829104"},
            {"type": "CHAT_MESSAGE", "sender": "+919876543210", "text": "Hawala confirmed"},
        ],
    )
    duration_sec = time.perf_counter() - t0

    assert duration_sec < 3.0  # Must complete in under 3.0 seconds!
    assert patch_result.is_unlocked is True
    assert patch_result.unwrapped_records_count == 2
    assert patch_result.derivative_vfs_id > 0
    assert patch_result.merkle_audit_entry_created is True
    assert "CONTAINER_UNWRAPPED_AND_HOT_PATCHED" in patch_result.merkle_event_type


def test_1930_ncrp_freeze_deconfliction_and_victim_safeguard_lock():
    """Acceptance Test 3: Freeze De-Confliction Center, Victim Account Safeguard Lock, and 14-Col NCRP CSV."""
    deconfliction = NodalFreezeDeconflictionCenter()

    candidates = [
        # Complainant / Victim Account (Must be automatically locked)
        {
            "account_no": "50100111222333",
            "ifsc": "HDFC0000001",
            "vpa": "victim@hdfc",
            "is_complainant_victim": True,
            "volume_inr": 180000.0,
        },
        # Public Utility Biller (Must be excluded by default)
        {
            "account_no": "999888777666",
            "ifsc": "SBIN0001000",
            "vpa": "irctc@upi",
            "is_complainant_victim": False,
            "volume_inr": 4500.0,
        },
        # Layer-1 Mule Account (Target for freeze)
        {
            "account_no": "30984718291",
            "ifsc": "SBIN0004821",
            "vpa": "vikram99@okaxis",
            "is_complainant_victim": False,
            "volume_inr": 180000.0,
        },
    ]

    evaluated_candidates: list[FreezeCandidateAccount] = deconfliction.evaluate_freeze_candidates(candidates)

    # Candidate 1: Victim Account
    c_victim = next(c for c in evaluated_candidates if c.account_no == "50100111222333")
    assert c_victim.is_freeze_locked is True
    assert c_victim.freeze_checkbox_disabled is True
    assert "VICTIM / COMPLAINANT" in c_victim.role_badge

    # Candidate 2: Utility Biller
    c_utility = next(c for c in evaluated_candidates if c.vpa == "irctc@upi")
    assert c_utility.is_utility_excluded is True
    assert "UTILITY / GOVT BILLER" in c_utility.role_badge

    # Candidate 3: Mule Account
    c_mule = next(c for c in evaluated_candidates if c.account_no == "30984718291")
    assert c_mule.is_freeze_locked is False
    assert c_mule.freeze_checkbox_disabled is False
    assert "MULE TARGET" in c_mule.role_badge

    # Generate 14-column 1930 NCRP Bank Lien CSV
    ncrp_csv = deconfliction.generate_1930_ncrp_csv(
        evaluated_candidates,
        complainant_account="50100111222333",
        acknowledgement_no="NCRP-2026-UP-482109",
    )

    # Victim account must only appear in Source/Payer column, NEVER in Target Beneficiary column!
    assert "Beneficiary_Account_to_Freeze" in ncrp_csv
    assert "30984718291" in ncrp_csv  # Mule account included in freeze list
    lines = ncrp_csv.strip().split("\n")
    # Header + 1 mule row = 2 lines (victim and utility are excluded from freeze rows)
    assert len(lines) == 2


def test_section_63_bsa_preflight_gate_and_merkle_tamper_block():
    """Acceptance Test 4: Section 63(4)(c) BSA pre-flight statutory gate and Merkle tamper detection."""
    studio = BsaReportStudioEngine()

    # 1. Incomplete submission: Missing Deponent designation in Part A
    incomplete_data = {
        "part_a_deponent_name": "R. K. Verma",
        "part_a_deponent_designation": "",  # Blank! Fails Check 1
        "part_b_expert_name": "Dr. S. Sharma",
        "part_b_expert_qualification": "M.Sc. Digital Forensics",
        "master_pre_ingest_sha256": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
        "master_post_ingest_sha256": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
        "merkle_chain_broken_links_count": 0,
        "pocso_unredacted_items_count": 0,
    }

    check_incomplete: PreFlightCheckResult = studio.run_preflight_statutory_gate(incomplete_data)
    assert check_incomplete.is_passed is False
    assert "Part A deponent designation is mandatory" in check_incomplete.failure_reasons[0]

    # 2. Tampered submission: Master pre-ingest vs post-ingest hash mismatch
    tampered_hash_data = dict(incomplete_data)
    tampered_hash_data["part_a_deponent_designation"] = "Inspector of Police, Cyber Crime PS"
    tampered_hash_data["master_post_ingest_sha256"] = "DIFFERENT_CORRUPT_HASH_1234567890"

    check_tampered: PreFlightCheckResult = studio.run_preflight_statutory_gate(tampered_hash_data)
    assert check_tampered.is_passed is False
    assert any("Master image hash mismatch" in r for r in check_tampered.failure_reasons)

    # 3. Tampered submission: Merkle chain has 1 broken link
    tampered_merkle_data = dict(tampered_hash_data)
    tampered_merkle_data["master_post_ingest_sha256"] = tampered_merkle_data["master_pre_ingest_sha256"]
    tampered_merkle_data["merkle_chain_broken_links_count"] = 1

    check_merkle: PreFlightCheckResult = studio.run_preflight_statutory_gate(tampered_merkle_data)
    assert check_merkle.is_passed is False
    assert any("Merkle audit chain integrity failed" in r for r in check_merkle.failure_reasons)

    # 4. Valid complete submission passes all 6 checks
    valid_data = dict(tampered_merkle_data)
    valid_data["merkle_chain_broken_links_count"] = 0

    check_valid: PreFlightCheckResult = studio.run_preflight_statutory_gate(valid_data)
    assert check_valid.is_passed is True
    assert len(check_valid.failure_reasons) == 0
    assert check_valid.checks_passed_count == 6


def test_wysiwyg_dual_preview_master_court_vs_sec230_bnss_defense_copy():
    """Acceptance Test 5: WYSIWYG dual preview (Master Court vs Section 230 BNSS Defense Disclosure)."""
    studio = BsaReportStudioEngine()

    exhibits = [
        {
            "exhibit_id": "EXHIBIT_01",
            "file_path": "/DCIM/Camera/IMG_0042.JPG",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "is_pocso_or_intimate_media": True,
            "victim_name": "Priya Sharma",
            "caption": "Recovered photo from camera roll",
        },
        {
            "exhibit_id": "EXHIBIT_02",
            "file_path": "/data/user/0/com.phonepe.app/databases/phonepe.db",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "md5": "ef2d127de37b942baad06145e54b0c61",
            "is_pocso_or_intimate_media": False,
            "victim_name": None,
            "caption": "Transaction ledger database",
        },
    ]

    dual_preview: BsaDossierDualPreview = studio.generate_dual_preview_dossier(
        exhibits=exhibits,
        include_dual_statutory_caption=True,
    )

    # 1. Dual statutory caption present
    assert "Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023" in dual_preview.statutory_header_caption
    assert "Section 65B(4) of the Indian Evidence Act, 1872" in dual_preview.statutory_header_caption

    # 2. Left Pane (Master Court Copy) contains unredacted victim details and media
    assert "Priya Sharma" in dual_preview.master_court_html
    assert "UNREDACTED VISUAL EXHIBIT RENDERED" in dual_preview.master_court_html

    # 3. Right Pane (Section 230 BNSS Defense Disclosure Copy) contains statutory withholding safeguards
    assert "Priya Sharma" not in dual_preview.defense_disclosure_html
    assert "VICTIM_PROTECTED_SEC72_BNS" in dual_preview.defense_disclosure_html
    assert "STATUTORY JUDICIAL-INSPECTION PLACEHOLDER" in dual_preview.defense_disclosure_html
    assert "P. Gopalkrishnan v. State of Kerala" in dual_preview.defense_disclosure_html
