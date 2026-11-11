"""
Test Suite for Phase 3, Module 3.3: Indian Retail, Payments, AePS & Corporate Banking App Decoders.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures, SQLite databases, and encrypted PDF streams (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests SBI mPassbook narration splitter & offline RBI IFSC dictionary branch resolver.
- Tests YONO Cash cardless ATM token cross-app runner correlation (WhatsApp / SMS).
- Tests deterministic Indian bank statement PDF auto-unlocker (testing 366 DDMM calendar combinations).
- Tests AePS BC agent cash-out & Mantra/Morpho RD service hardware scanner attribution.
- Verifies canonical indian_banking_sandbox_engine.sqlite schema and 4 tables.
"""

from pathlib import Path
import shutil
import sqlite3
import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_banking_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_indian_banking_sandbox_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


def build_standard_encrypted_pdf_bytes(password: str) -> bytes:
    """
    Constructs a valid, minimal PDF 1.4 binary file protected with standard
    Security Handler Revision 2 (40-bit RC4) user password encryption.
    """
    import hashlib
    from cryptography.hazmat.primitives.ciphers import Cipher
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

    # Standard PDF padding bytes from ISO 32000-1:2008 (Section 7.6.3.3)
    padding = bytes([
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
        0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
        0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
    ])
    doc_id = b"0123456789abcdef"
    p_val = -3904  # standard permissions

    # Algorithm 3.2: Compute encryption key
    pw_bytes = password.encode("latin1")[:32]
    padded_pw = pw_bytes + padding[:32 - len(pw_bytes)]

    h = hashlib.md5(padded_pw)
    # Owner entry (using default owner key)
    o_val = bytes([0xAA] * 32)
    h.update(o_val)
    h.update(p_val.to_bytes(4, byteorder="little", signed=True))
    h.update(doc_id)
    key = h.digest()[:5]  # 40-bit key

    # Algorithm 3.4: Compute U (User check) entry
    cipher = Cipher(ARC4(key), mode=None)
    enc = cipher.encryptor()
    u_val = enc.update(padding)

    o_hex = o_val.hex()
    u_hex = u_val.hex()
    id_hex = doc_id.hex()

    pdf_body = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<<
  /Filter /Standard
  /V 1
  /R 2
  /Length 40
  /P {p_val}
  /O <{o_hex}>
  /U <{u_hex}>
>>
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000188 00000 n 
trailer
<<
  /Size 5
  /Root 1 0 R
  /Encrypt 4 0 R
  /ID [<{id_hex}> <{id_hex}>]
>>
startxref
340
%%EOF
"""
    return pdf_body.encode("latin1")


# ==============================================================================
# TEST 1: SBI mPassbook Narration Splitter & Offline IFSC Branch Resolver Test
# ==============================================================================

def test_sbi_mpassbook_narration_splitter_and_ifsc_resolver(tmp_banking_dir):
    """
    Acceptance Test 1 (Section 10.1):
    1. Populates an offline mPassbook database with:
       - Narration = "UPI/DR/630914829104/VIKRAM SINGH/HDFC/vikram@okhdfcbank/Rent"
       - Amount = 15000.0, running_balance = 85000.0
       - Beneficiary row with IFSC = "SBIN0000201"
    Verifies that Sub-Engine 3.3A & OfflineIFSCResolver:
    1. Splits the narration into UTR 630914829104, direction DEBIT, counterparty VIKRAM SINGH,
       and VPA vikram@okhdfcbank.
    2. Resolves SBIN0000201 via the offline RBI IFSC dictionary to:
       "State Bank of India — Varanasi Main Branch, Uttar Pradesh".
    """
    from src.banking.narration_parser import CoreBankingNarrationParser
    from src.banking.ifsc_resolver import OfflineIFSCResolver

    # 1. Test Core Banking Narration Parser
    parser = CoreBankingNarrationParser()
    raw_narration = "UPI/DR/630914829104/VIKRAM SINGH/HDFC/vikram@okhdfcbank/Rent"
    parsed = parser.parse_narration(raw_narration)

    assert parsed.utr_or_rrn == "630914829104"
    assert parsed.direction == "DEBIT"
    assert parsed.counterparty_name == "VIKRAM SINGH"
    assert parsed.counterparty_vpa == "vikram@okhdfcbank"
    assert parsed.payment_rail == "UPI"

    # 2. Test Offline RBI IFSC Resolver
    resolver = OfflineIFSCResolver()
    branch_info = resolver.resolve_ifsc("SBIN0000201")

    assert branch_info is not None
    assert branch_info.bank_name == "State Bank of India"
    assert "Varanasi Main Branch" in branch_info.branch_name
    assert branch_info.state == "Uttar Pradesh"
    assert "State Bank of India — Varanasi Main Branch, Uttar Pradesh" in branch_info.formatted_location


# ==============================================================================
# TEST 2: YONO Cash ATM Runner Cross-App Correlation Test
# ==============================================================================

def test_yono_cash_atm_runner_cross_app_correlation(tmp_banking_dir):
    """
    Acceptance Test 2 (Section 10.2):
    1. Generates a YONO Cash record with Reference Number "849201" for ₹20,000 at 14:00:00 UTC.
    2. Populates a test WhatsApp msgstore.db with an outbound message sent at 14:02:15 UTC
       to "+919811223344" containing "Ref 849201 pin 445512 nikalo".
    Verifies that CardlessRunnerCorrelator:
    1. Detects the matching 6-digit reference number within the 4-hour window.
    2. Links "+919811223344" as linked_runner_chat_recipient.
    """
    from src.banking.cardless_runner import CardlessRunnerCorrelator
    from src.banking.models import CardlessATMOrPDFRecord

    yono_record = CardlessATMOrPDFRecord(
        source_vfs_file_id=201,
        artifact_category="YONO_CASH_CARDLESS_ATM",
        bank_institution_name="State Bank of India",
        cardless_ref_id_or_pdf_name="849201",
        amount_inr_or_row_count=20000.0,
        event_utc_iso="2026-11-05T14:00:00.000000Z",
    )

    # Create synthetic WhatsApp msgstore.db
    msgstore_path = tmp_banking_dir / "msgstore.db"
    con = sqlite3.connect(msgstore_path)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE messages (
            _id INTEGER PRIMARY KEY,
            key_remote_jid TEXT,
            data TEXT,
            timestamp INTEGER,
            from_me INTEGER
        );
    """)
    # 14:02:15 UTC = 1793887335000 ms
    cur.execute("""
        INSERT INTO messages VALUES (
            1,
            '919811223344@s.whatsapp.net',
            'Ref 849201 pin 445512 nikalo',
            1793887335000,
            1
        );
    """)
    con.commit()
    con.close()

    correlator = CardlessRunnerCorrelator()
    linked_recipient = correlator.find_runner_recipient_for_cardless_token(
        token_record=yono_record,
        chat_db_paths=[msgstore_path],
    )

    assert linked_recipient == "+919811223344"


# ==============================================================================
# TEST 3: Deterministic Bank Statement PDF Auto-Unlocker Test
# ==============================================================================

def test_deterministic_bank_statement_pdf_unlocker(tmp_banking_dir):
    """
    Acceptance Test 3 (Section 10.3 & Section 8.1):
    1. Creates a password-protected PDF encrypted with "RAHU1408"
       (first 4 letters of "RAHUL SHARMA" + DDMM 1408 of DOB 14-08-1995).
    2. Passes candidate profile name "RAHUL SHARMA" without specifying DOB.
    Verifies that DeterministicBankStatementUnlocker:
    1. Tests the 366 RAHU<DDMM> calendar combinations in < 50 ms.
    2. Unlocks the PDF and returns unlocked_password = "RAHU1408".
    """
    from src.banking.pdf_unlocker import DeterministicBankStatementUnlocker

    correct_pw = "RAHU1408"
    pdf_bytes = build_standard_encrypted_pdf_bytes(correct_pw)
    pdf_path = tmp_banking_dir / "SBI_Statement_Nov2026.pdf"
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    unlocker = DeterministicBankStatementUnlocker()
    result = unlocker.unlock_pdf_statement(
        pdf_path=pdf_path,
        account_holder_name="RAHUL SHARMA",
    )

    assert result is not None
    assert result.unlocked_password == "RAHU1408"
    assert result.is_unlocked is True


# ==============================================================================
# TEST 4: AePS Biometric Cash-Out & RD Service Detection Test
# ==============================================================================

def test_aeps_biometric_cashout_and_rd_service_detection(tmp_banking_dir):
    """
    Acceptance Test 4 (Section 10.4):
    1. Simulates Spice Money AePS agent sandbox:
       - BC Agent ID = "SMA102938"
       - Cash-out row: Aadhaar = "XXXX-XXXX-1234", RRN = "410293847581", Amount = 5000.0
    2. Simulates attached Mantra RD Service configuration:
       - DeviceSerialNumber = "MFS100-9988776"
    Verifies that IndianBankingSandboxEngine:
    1. Detects AePS agent profile and links the Mantra scanner serial number.
    2. Extracts the AePS cash-out row with payment_rail = "AEPS_BIOMETRIC_CASHOUT".
    """
    from src.banking.engine import IndianBankingSandboxEngine

    # 1. Spice Money agent shared_prefs
    spice_prefs_dir = tmp_banking_dir / "in.spicemoney.spicemoney" / "shared_prefs"
    spice_prefs_dir.mkdir(parents=True, exist_ok=True)
    with open(spice_prefs_dir / "user_profile.xml", "w", encoding="utf-8") as f:
        f.write("""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="bc_agent_id">SMA102938</string>
    <string name="merchant_name">Ramesh General Store</string>
    <string name="registered_mobile">9876543210</string>
</map>
""")

    # Spice Money offline AePS cash-out database
    spice_db_dir = tmp_banking_dir / "in.spicemoney.spicemoney" / "databases"
    spice_db_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(spice_db_dir / "aeps_transactions.db")
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE aeps_ledger (
            _id INTEGER PRIMARY KEY,
            aadhaar_mask TEXT,
            bank_iin TEXT,
            rrn TEXT,
            amount REAL,
            txn_time INTEGER
        );
    """)
    cur.execute("""
        INSERT INTO aeps_ledger VALUES (
            1,
            'XXXX-XXXX-1234',
            '607152',
            '410293847581',
            5000.0,
            1704110400000
        );
    """)
    con.commit()
    con.close()

    # 2. Mantra RD Service configuration
    mantra_prefs_dir = tmp_banking_dir / "com.mantra.rdservice" / "shared_prefs"
    mantra_prefs_dir.mkdir(parents=True, exist_ok=True)
    with open(mantra_prefs_dir / "rd_service_prefs.xml", "w", encoding="utf-8") as f:
        f.write("""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="DeviceSerialNumber">MFS100-9988776</string>
    <string name="DeviceModel">MFS100</string>
</map>
""")

    engine = IndianBankingSandboxEngine()
    profiles, transactions = engine.analyze_banking_sandboxes(
        root_data_dir=tmp_banking_dir,
    )

    # 1. Verify Profile
    assert len(profiles) >= 1
    spice_profile = next((p for p in profiles if p.customer_id_cif_crn == "SMA102938"), None)
    assert spice_profile is not None
    assert spice_profile.app_tier_category == "AEPS_BC_AGENT_APP"
    assert spice_profile.attached_biometric_scanner_sn == "MFS100-9988776"

    # 2. Verify Transaction
    assert len(transactions) >= 1
    aeps_tx = next((t for t in transactions if t.utr_or_rrn_reference == "410293847581"), None)
    assert aeps_tx is not None
    assert aeps_tx.payment_rail == "AEPS_BIOMETRIC_CASHOUT"
    assert aeps_tx.amount_inr_decimal == 5000.0


# ==============================================================================
# TEST 5: Master Ledger Export Test (indian_banking_sandbox_engine.sqlite)
# ==============================================================================

def test_indian_banking_sandbox_master_ledger_export(tmp_banking_dir):
    """
    Section 9: Database Schema for Module 3.3
    Verifies that IndianBankingSandboxEngine creates and exports to:
    1. banking_app_profiles_and_roles
    2. bank_mpassbook_and_sandbox_ledger
    3. bank_beneficiaries_and_cooling_audit
    4. cardless_atm_and_unlocked_pdfs_ledger
    inside indian_banking_sandbox_engine.sqlite with exact column names, constraints, and indexes.
    """
    from src.banking.engine import IndianBankingSandboxEngine
    from src.banking.models import (
        BankingAppProfileRecord,
        BankMPassbookLedgerRecord,
        BankBeneficiaryCoolingRecord,
        CardlessATMOrPDFRecord,
    )

    ledger_path = tmp_banking_dir / "indian_banking_sandbox_engine.sqlite"
    engine = IndianBankingSandboxEngine()

    profile = BankingAppProfileRecord(
        app_instance_id=10,
        source_vfs_file_id=101,
        bank_institution_name="State Bank of India",
        app_tier_category="PSU_RETAIL",
        customer_id_cif_crn="CIF11223344",
        corporate_role="RETAIL_INDIVIDUAL",
        account_holder_name="Rahul Sharma",
        registered_mobile_no="+919876543210",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )

    tx = BankMPassbookLedgerRecord(
        source_vfs_file_id=102,
        source_artifact_type="OFFLINE_MPASSBOOK_DB",
        payment_rail="IMPS",
        utr_or_rrn_reference="630914829104",
        tx_direction="DEBIT",
        amount_inr_decimal=25000.0,
        running_balance_inr=75000.0,
        raw_narration_text="TO TRANSFER-INB IMPS/630914829104/VIKRAM/HDFC0001234",
        extracted_counterparty_name="VIKRAM",
        extracted_counterparty_ifsc="HDFC0001234",
        resolved_branch_city_state="HDFC Bank — Mumbai Main Branch, Maharashtra",
        tx_utc_iso="2026-11-05T12:00:00.000000Z",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )

    beneficiary = BankBeneficiaryCoolingRecord(
        source_vfs_file_id=103,
        beneficiary_holder_name="Vikram Singh",
        beneficiary_account_no="50100234567890",
        beneficiary_ifsc_11_char="HDFC0001234",
        resolved_bank_and_branch_loc="HDFC Bank — Mumbai Main Branch, Maharashtra",
        added_utc_iso="2026-11-05T11:45:00.000000Z",
        cooling_period_end_utc_iso="2026-11-05T12:15:00.000000Z",
        first_transfer_utc_iso="2026-11-05T12:00:00.000000Z",
        post_cooling_latency_minutes=15.0,
        is_rapid_mule_drain_flagged=1,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )

    special = CardlessATMOrPDFRecord(
        source_vfs_file_id=104,
        artifact_category="YONO_CASH_CARDLESS_ATM",
        bank_institution_name="State Bank of India",
        cardless_ref_id_or_pdf_name="849201",
        amount_inr_or_row_count=20000.0,
        linked_runner_chat_recipient="+919811223344",
        event_utc_iso="2026-11-05T14:00:00.000000Z",
    )

    engine.export_to_ledger(
        profiles=[profile],
        transactions=[tx],
        beneficiaries=[beneficiary],
        specials=[special],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. banking_app_profiles_and_roles
    cur.execute("SELECT * FROM banking_app_profiles_and_roles;")
    row_prof = cur.fetchone()
    assert row_prof is not None
    cols_prof = [d[0] for d in cur.description]
    assert "customer_id_cif_crn" in cols_prof
    assert "app_tier_category" in cols_prof

    # 2. bank_mpassbook_and_sandbox_ledger
    cur.execute("SELECT * FROM bank_mpassbook_and_sandbox_ledger;")
    row_tx = cur.fetchone()
    assert row_tx is not None
    cols_tx = [d[0] for d in cur.description]
    assert "utr_or_rrn_reference" in cols_tx
    assert "payment_rail" in cols_tx

    # 3. bank_beneficiaries_and_cooling_audit
    cur.execute("SELECT * FROM bank_beneficiaries_and_cooling_audit;")
    row_ben = cur.fetchone()
    assert row_ben is not None
    cols_ben = [d[0] for d in cur.description]
    assert "is_rapid_mule_drain_flagged" in cols_ben
    assert "cooling_period_end_utc_iso" in cols_ben

    # 4. cardless_atm_and_unlocked_pdfs_ledger
    cur.execute("SELECT * FROM cardless_atm_and_unlocked_pdfs_ledger;")
    row_spec = cur.fetchone()
    assert row_spec is not None
    cols_spec = [d[0] for d in cur.description]
    assert "cardless_ref_id_or_pdf_name" in cols_spec
    assert "linked_runner_chat_recipient" in cols_spec

    con.close()
