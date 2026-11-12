"""UNK triage workbench and key-broker console:
1. sliding-window entropy and chi-square profiling, and examiner-driven promotion of an unknown table;
2. incremental DAG hot-patch after an examiner supplies a key.
"""

import os
import sqlite3
import time
import pytest

from src.unk_triage.models import (
    SemanticColumnRole,
    BlockEntropyResult,
    ChiSquareHistogramResult,
    PromotedSchemaRecord,
    CandidateSecretRecord,
    IncrementalHotPatchResult,
)
from src.unk_triage.entropy_profiler import SlidingWindowEntropyProfiler
from src.unk_triage.schema_mapper import ZeroCodeSchemaMapper
from src.unk_triage.key_broker_hotpatcher import KeyBrokerHotPatcher
from src.unk_triage.engine import UnkTriageMasterEngine


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
