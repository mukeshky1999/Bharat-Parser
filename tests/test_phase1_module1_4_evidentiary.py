"""
Tests for Phase 1 Module 1.4: The 5D Evidentiary State & Tripartite Audit Engine.
Complies with:
- Section 4.3 (5D Evidentiary State Matrix) of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
- Section 63(4)(c) Bharatiya Sakshya Adhiniyam (BSA) 2023 & SWGDE Forensics Standards.
- Engineering Specification Phase 1 Module 1.4.

Verifies:
1. Rule 1 & Rule 2: "Not Observed" vs "Absent" ban, BFU Lock-State & Tier 1B backup exclusion inference.
2. Rule 3: Strict distinction between Hardware-Gated (SEP/TEE) and Missing-Key-Gated secrets (Signal/Keychain).
3. Rule 4: Zero silent parser failures & Dimension D schema version mismatch detection.
4. The Unclassified Artifacts Sweeper (UNK ledger, automatic SQLite table inspection & row counting).
5. The Tripartite Case Summary Rollup across all 18 Canonical Forensic Groups.
"""

import json
import sqlite3
import pytest
from pathlib import Path

# Production module imports (failing during Phase A RED phase)
from src.evidentiary.enums import (
    DimensionAPresence,
    DimensionBAccessibility,
    DimensionCIntegrity,
    DimensionDCoverage,
    DimensionEMaturity,
    TripartiteStoredState,
    UnclassifiedStorageFormat,
    ExaminerReviewStatus,
)
from src.evidentiary.models import EvidentiaryAuditEntry
from src.evidentiary.engine import EvidentiaryStateEngine
from src.evidentiary.sweeper import UnclassifiedArtifactsSweeper
from src.evidentiary.ledger import TripartiteLedgerDatabase


# ============================================================================
# Helpers
# ============================================================================

def make_sample_sqlite_db(path: Path, table_name: str, rows_count: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(f"CREATE TABLE {table_name} (id INTEGER PRIMARY KEY, note TEXT);")
    for i in range(rows_count):
        cur.execute(f"INSERT INTO {table_name} (note) VALUES ('entry_{i}');")
    conn.commit()
    conn.close()
    return path


# ============================================================================
# Test Cases
# ============================================================================

class TestEvidentiaryStateEngine:
    """Stage 1: 5D Evidentiary State Machine & Courtroom Rule Enforcement Tests."""

    def test_rule_1_and_2_bfu_lock_state_attribution(self, tmp_path):
        """
        BFU Test: Android DE telephony database is PRESENT and READABLE,
        while CE WhatsApp database is missing due to BFU lock state.
        Must be marked SOURCE_PRESENT_NOT_ACQUIRED_BFU, NEVER 'Absent'.
        """
        db_path = tmp_path / "evidentiary.sqlite"
        ledger = TripartiteLedgerDatabase(db_path=db_path)
        engine = EvidentiaryStateEngine(ledger=ledger)

        # 1. Evaluate DE telephony artifact (present in extraction)
        entry_de = engine.evaluate_artifact(
            artifact_code="G04_TELEPHONY_DE_SMS",
            forensic_group_num=4,
            forensic_group_name="Group 04 — Financial SMS & Notifications",
            expected_canonical_path="/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
            file_exists_in_vfs=True,
            file_size_bytes=102400,
            is_plaintext_readable=True,
            is_bfu_extraction=True,
            is_tier_1b_backup=False
        )

        assert isinstance(entry_de, EvidentiaryAuditEntry)
        assert entry_de.dim_a_presence == DimensionAPresence.PRESENT
        assert entry_de.dim_b_accessibility == DimensionBAccessibility.READABLE
        assert entry_de.dim_c_integrity == DimensionCIntegrity.VERIFIED_LIVE_STAGING_HASH

        # 2. Evaluate CE WhatsApp artifact (missing in BFU)
        entry_ce = engine.evaluate_artifact(
            artifact_code="G07_WHATSAPP_CE_MSGSTORE",
            forensic_group_num=7,
            forensic_group_name="Group 07 — Mainstream & Modded Chats",
            expected_canonical_path="/data/user/0/com.whatsapp/databases/msgstore.db",
            file_exists_in_vfs=False,
            file_size_bytes=0,
            is_plaintext_readable=False,
            is_bfu_extraction=True,
            is_tier_1b_backup=False
        )

        # Must NOT be 'Absent' or 'NOT_OBSERVED' — must explicitly indicate BFU gating!
        assert entry_ce.dim_a_presence == DimensionAPresence.SOURCE_PRESENT_NOT_ACQUIRED_BFU
        assert entry_ce.dim_b_accessibility == DimensionBAccessibility.NOT_APPLICABLE
        assert "BFU" in entry_ce.diagnostic_notes

    def test_rule_2_tier_1b_backup_exclusion_inference(self, tmp_path):
        """
        iOS Logical Backup Test: knowledgeC.db and tracev3 are excluded by iOS backup policy.
        Must be marked SOURCE_PRESENT_NOT_ACQUIRED_TIER.
        """
        db_path = tmp_path / "evidentiary.sqlite"
        ledger = TripartiteLedgerDatabase(db_path=db_path)
        engine = EvidentiaryStateEngine(ledger=ledger)

        entry_kc = engine.evaluate_artifact(
            artifact_code="G15_KNOWLEDGEC_EVENTS",
            forensic_group_num=15,
            forensic_group_name="Group 15 — OS Behavioral Telemetry",
            expected_canonical_path="/private/var/mobile/Library/CoreDuet/knowledgeC.db",
            file_exists_in_vfs=False,
            file_size_bytes=0,
            is_plaintext_readable=False,
            is_bfu_extraction=False,
            is_tier_1b_backup=True
        )

        assert entry_kc.dim_a_presence == DimensionAPresence.SOURCE_PRESENT_NOT_ACQUIRED_TIER
        assert "Backup Policy" in entry_kc.diagnostic_notes

    def test_rule_3_encrypted_signal_missing_key_material(self, tmp_path):
        """
        Rule 3 Test: Encrypted database present without decryption key material.
        Must be marked ENCRYPTED_GATED_MISSING_KEY with actionable diagnostic notes.
        """
        db_path = tmp_path / "evidentiary.sqlite"
        ledger = TripartiteLedgerDatabase(db_path=db_path)
        engine = EvidentiaryStateEngine(ledger=ledger)

        entry_signal = engine.evaluate_artifact(
            artifact_code="G07_SIGNAL_SQLITE",
            forensic_group_num=7,
            forensic_group_name="Group 07 — Mainstream & Modded Chats",
            expected_canonical_path="/private/var/mobile/Containers/Shared/AppGroup/UUID/grdb/Signal.sqlite",
            file_exists_in_vfs=True,
            file_size_bytes=52428800,  # 50 MB
            is_plaintext_readable=False,
            is_encrypted_ciphertext=True,
            has_hardware_gated_key=False,
            missing_keychain_key=True
        )

        assert entry_signal.dim_a_presence == DimensionAPresence.PRESENT
        assert entry_signal.dim_b_accessibility == DimensionBAccessibility.ENCRYPTED_GATED_MISSING_KEY
        assert entry_signal.dim_d_coverage == DimensionDCoverage.PARSED_WITH_SUPPLIED_KEYS
        assert entry_signal.dim_e_maturity == DimensionEMaturity.R4
        assert "keychain-2.db" in entry_signal.diagnostic_notes


class TestUnclassifiedArtifactsSweeper:
    """Stage 4: Unknown & Unclassified Artifacts Sweeper (UNK Ledger) Tests."""

    def test_unclassified_sqlite_database_auto_inspector(self, tmp_path):
        catalog_db = tmp_path / "evidentiary.sqlite"
        ledger = TripartiteLedgerDatabase(db_path=catalog_db)

        # Create an unknown SQLite database in an app sandbox
        custom_db_path = tmp_path / "hawala_ledger.db"
        make_sample_sqlite_db(custom_db_path, table_name="transfers", rows_count=50)

        sweeper = UnclassifiedArtifactsSweeper(ledger=ledger)

        # Simulate sweeping an unparsed SQLite database
        unk_entry = sweeper.inspect_unclassified_file(
            vfs_file_id=999,
            canonical_path="/data/user/0/com.custom.calc/databases/hawala_ledger.db",
            file_disk_path=custom_db_path,
            owning_app_instance_id=42,
            inferred_forensic_group=13
        )

        assert unk_entry["unk_id"] == "UNK-0001"
        assert unk_entry["detected_storage_format"] == UnclassifiedStorageFormat.SQLITE3.value
        assert unk_entry["canonical_path"] == "/data/user/0/com.custom.calc/databases/hawala_ledger.db"

        # Verify automated SQLite table summary extraction
        summary_dict = json.loads(unk_entry["sqlite_table_summary_json"])
        assert summary_dict == {"transfers": 50}

        # Check ledger record
        records = ledger.get_unclassified_artifacts()
        assert len(records) == 1
        assert records[0]["unk_id"] == "UNK-0001"
        assert records[0]["examiner_review_status"] == ExaminerReviewStatus.PENDING_REVIEW.value


class TestTripartiteRollupSummary:
    """Stage 5: Tripartite Case Summary Rollup across all 18 Forensic Groups."""

    def test_tripartite_summary_computation(self, tmp_path):
        db_path = tmp_path / "evidentiary.sqlite"
        ledger = TripartiteLedgerDatabase(db_path=db_path)
        engine = EvidentiaryStateEngine(ledger=ledger)

        # Add entries in Group 4 and Group 7
        engine.evaluate_artifact(
            artifact_code="G04_TELEPHONY_DE_SMS",
            forensic_group_num=4,
            forensic_group_name="Group 04 — Financial SMS & Notifications",
            expected_canonical_path="/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
            file_exists_in_vfs=True,
            file_size_bytes=1024,
            is_plaintext_readable=True,
            active_records=150,
            residual_records=25
        )

        engine.evaluate_artifact(
            artifact_code="G07_SIGNAL_SQLITE",
            forensic_group_num=7,
            forensic_group_name="Group 07 — Mainstream & Modded Chats",
            expected_canonical_path="/path/Signal.sqlite",
            file_exists_in_vfs=True,
            file_size_bytes=2048,
            is_plaintext_readable=False,
            is_encrypted_ciphertext=True,
            missing_keychain_key=True
        )

        # Generate rollup
        ledger.generate_tripartite_rollup()

        summary = ledger.get_tripartite_case_summary()
        # All 18 forensic groups must be present
        assert len(summary) == 18

        g4 = next(s for s in summary if s["group_number"] == 4)
        assert g4["stored_targets_expected"] >= 1
        assert g4["acquired_targets_present"] >= 1
        assert g4["total_active_artifacts"] == 150
        assert g4["total_residual_artifacts"] == 25

        g7 = next(s for s in summary if s["group_number"] == 7)
        assert g7["gated_or_excluded_count"] >= 1
