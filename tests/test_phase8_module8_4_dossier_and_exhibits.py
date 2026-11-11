"""
Acceptance Test Suite for Phase 8, Module 8.4:
Crime-Typology Dossier Builder, Nodal Agency (1930 NCRP / FIU-IND / CEX) Freeze Exporter,
Section 94 BNSS Requisition Drafter & Courtroom Exhibit Packager.

Test Scope (5 Acceptance Tests):
1. test_golden_hour_ncrp_and_cex_crypto_freeze_packets:
   Validates export of ncrp_1930_bank_freeze_packet.csv with 14 mandatory I4C columns,
   and fiu_ind_and_cex_crypto_freeze_packet.csv covering CEX UIDs and Tether TRC-20 addresses.
2. test_autodrafted_section_94_bnss_requisitions_grouping:
   Evaluates automated grouping of discovered bank accounts, TSPs, CEXs, and hyperlocal apps
   into statutory Section 94 BNSS, 2023 legal notices with target identifiers and checklists.
3. test_section_230_bnss_defense_copy_pocso_and_intimate_media_redaction_gate:
   Enforces P. Gopalkrishnan v. State of Kerala (2019) compliance: replaces CSAM/POCSO and intimate media
   with Statutory Judicial-Inspection Placeholder Cards containing SHA-256/MD5 hashes;
   verifies Section 72 BNS victim identity anonymization ([VICTIM_PROTECTED_ID_01]).
4. test_crime_typology_dossier_compilation_and_courtroom_pdf:
   Compiles Cyber-Fraud Mule & USDT Laundering Dossier with 7 chapters, inline forensic provenance footers,
   and bound Section 63(4)(c) BSA 2023 certification.
5. test_dossier_and_exhibits_master_sqlite_export:
   Validates export of all 3 canonical tables and indexes into dossier_freeze_and_exhibit_packager.sqlite.
"""

import os
import sqlite3
import pytest

from src.dossier_and_exhibits.models import (
    DossierProfileType,
    ExportAudienceScope,
    NodalAgencyTarget,
    RecipientNodalCategory,
    RedactionTag,
    MuleTransactionEntry,
    CryptoFreezeEntry,
    CrimeDossierRecord,
    NodalFreezePacketRecord,
    Section94BnssRequisitionRecord,
    SensitiveMediaItem,
)
from src.dossier_and_exhibits.nodal_freeze_and_requisitions import (
    NodalFreezeExporter,
    Section94BnssRequisitionDrafter,
)
from src.dossier_and_exhibits.dossier_builder import CrimeTypologyDossierBuilder
from src.dossier_and_exhibits.exhibit_packager import ExhibitAndDefensePackager
from src.dossier_and_exhibits.engine import DossierAndExhibitPackagerEngine


def test_golden_hour_ncrp_and_cex_crypto_freeze_packets():
    """Acceptance Test 1: Golden-hour I4C NCRP 1930 (14 columns) and CEX/Tether freeze sheets."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_freeze_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    exporter = NodalFreezeExporter()

    # 1. Bank and UPI transactions (3 UPI outflows + 1 cheque unmasked account)
    tx_entries = [
        MuleTransactionEntry(
            s_no=1,
            transaction_layer="Layer 1 Direct",
            payment_rail="UPI",
            utr_or_rrn_12_digit="630911111111",
            transaction_timestamp_ist="05-11-2026 14:10:00 IST",
            transaction_amount_inr=50000.00,
            payer_account_or_vpa="victim@okhdfcbank",
            beneficiary_bank_name="State Bank of India",
            beneficiary_account_number="30984718291",
            beneficiary_ifsc_11_char="SBIN0004821",
            beneficiary_upi_vpa="mule1@ybl",
            beneficiary_verified_cbs_name="VIKRAM SINGH",
            linked_mobile_number_e164="+919876543210",
            forensic_source_artifact_and_sha256="phonepe.db [SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]",
        ),
        MuleTransactionEntry(
            s_no=2,
            transaction_layer="Layer 1 Direct",
            payment_rail="UPI",
            utr_or_rrn_12_digit="630922222222",
            transaction_timestamp_ist="05-11-2026 14:15:00 IST",
            transaction_amount_inr=95000.00,
            payer_account_or_vpa="victim@okhdfcbank",
            beneficiary_bank_name="State Bank of India",
            beneficiary_account_number="30984718291",
            beneficiary_ifsc_11_char="SBIN0004821",
            beneficiary_upi_vpa="mule1@ybl",
            beneficiary_verified_cbs_name="VIKRAM SINGH",
            linked_mobile_number_e164="+919876543210",
            forensic_source_artifact_and_sha256="paisa.db [SHA-256: a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0]",
        ),
        MuleTransactionEntry(
            s_no=3,
            transaction_layer="Layer 2 Pass-Through",
            payment_rail="IMPS",
            utr_or_rrn_12_digit="630933333333",
            transaction_timestamp_ist="05-11-2026 14:25:00 IST",
            transaction_amount_inr=140000.00,
            payer_account_or_vpa="30984718291",
            beneficiary_bank_name="HDFC Bank",
            beneficiary_account_number="50100492817281",
            beneficiary_ifsc_11_char="HDFC0001024",
            beneficiary_upi_vpa="layer2mule@okaxis",
            beneficiary_verified_cbs_name="MOHD ASLAM",
            linked_mobile_number_e164="+919811223344",
            forensic_source_artifact_and_sha256="cheque_ocr.jpg [SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069]",
        ),
    ]

    csv_path, sha256_bank, bank_packet = exporter.export_ncrp_1930_bank_freeze_packet(
        transactions=tx_entries, output_dir=sandbox
    )

    assert os.path.exists(csv_path)
    assert bank_packet.total_accounts_or_wallets_count == 2
    assert bank_packet.total_utrs_or_txids_count == 3
    assert bank_packet.total_disputed_fiat_inr == 285000.00
    assert len(sha256_bank) == 64

    # Verify CSV has all 14 mandatory columns in header
    with open(csv_path, "r", encoding="utf-8") as f:
        header = f.readline().strip().split(",")
    assert len(header) == 14
    assert "UTR_or_RRN_12_Digit" in header
    assert "Beneficiary_IFSC_11_Char" in header
    assert "Forensic_Source_Artifact_and_SHA256" in header

    # 2. Crypto entries (Binance CEX UID + TronLink USDT-TRC20 address)
    crypto_entries = [
        CryptoFreezeEntry(
            category="CEX_ACCOUNT",
            exchange_or_network="Binance (LERP)",
            target_identifier="482910482",
            kyc_name_or_control="VIKRAM SINGH (PAN: ABCPS1234K)",
            fiat_or_token_balance="15,400.00 USDT",
            associated_txids_or_orders=["P2P-ORD-20261105-998811"],
            requested_action="Immediate Account Freeze & Production of KYC, Counterparty UIDs & Login IPs under Sec 94 BNSS",
        ),
        CryptoFreezeEntry(
            category="ONCHAIN_WALLET",
            exchange_or_network="TRON TRC-20",
            target_identifier="TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
            kyc_name_or_control="Suspect Active TronLink Pro Wallet",
            fiat_or_token_balance="25,000.00 USDT",
            associated_txids_or_orders=["3a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef"],
            requested_action="Tether Contract Blacklist / Law Enforcement Freeze Request",
        ),
    ]

    crypto_csv, sha256_crypto, crypto_packet = exporter.export_fiu_and_cex_crypto_freeze_packet(
        entries=crypto_entries, output_dir=sandbox
    )
    assert os.path.exists(crypto_csv)
    assert crypto_packet.total_accounts_or_wallets_count == 2
    assert crypto_packet.total_utrs_or_txids_count == 2
    assert "USDT" in crypto_packet.total_disputed_crypto_summary


def test_autodrafted_section_94_bnss_requisitions_grouping():
    """Acceptance Test 2: Auto-grouping of discovered leads into Section 94 BNSS notices."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_requisition_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    drafter = Section94BnssRequisitionDrafter()

    discovered_leads = [
        # State Bank of India leads
        {
            "category": "BANK_NODAL_OFFICER",
            "organization": "State Bank of India",
            "ifsc": "SBIN0004821",
            "account_number": "30984718291",
            "utr": "630911111111",
        },
        {
            "category": "BANK_NODAL_OFFICER",
            "organization": "State Bank of India",
            "ifsc": "SBIN0001024",
            "account_number": "30984718299",
            "utr": "630922222222",
        },
        # Reliance Jio leads
        {
            "category": "TELECOM_TSP_NODAL",
            "organization": "Reliance Jio Infocomm Ltd.",
            "msisdn": "+919876543210",
            "imei": "354829104928172",
            "cell_tower_id": "405-86-1042-eNodeB 1048577",
        },
        # Blinkit leads
        {
            "category": "HYPERLOCAL_DELIVERY_OR_RIDE_NODAL",
            "organization": "Blinkit / Eternal Ltd.",
            "order_id": "ORD998877",
            "linked_phone": "+919876543210",
        },
        # Binance LERP leads
        {
            "category": "CRYPTO_CEX_OR_SWAP_COMPLIANCE",
            "organization": "Binance Compliance (LERP)",
            "uid": "482910482",
            "order_id": "P2P-ORD-20261105-998811",
        },
    ]

    case_info = {
        "fir_number": "FIR No. 412/2026",
        "police_station": "Cyber Crime Police Station",
        "district": "New Delhi",
        "io_name": "Inspector Rajesh Kumar Verma",
        "sections_of_law": "Sections 316(2), 318(4) BNS, 2023 r/w 66D IT Act",
    }

    requisitions = drafter.generate_section_94_requisitions(
        discovered_leads=discovered_leads, case_info=case_info, output_dir=sandbox
    )

    # Must produce exactly 4 distinct grouped notices: SBI, Jio, Blinkit, Binance
    assert len(requisitions) == 4

    sbi_req = next(r for r in requisitions if r.recipient_organization_name == "State Bank of India")
    assert sbi_req.recipient_nodal_category == RecipientNodalCategory.BANK_NODAL_OFFICER
    assert "30984718291" in sbi_req.target_identifiers_json
    assert "30984718299" in sbi_req.target_identifiers_json
    assert "Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023" in sbi_req.statutory_provision
    assert os.path.exists(sbi_req.rendered_notice_doc_path)

    jio_req = next(r for r in requisitions if "Jio" in r.recipient_organization_name)
    assert jio_req.recipient_nodal_category == RecipientNodalCategory.TELECOM_TSP_NODAL
    assert "+919876543210" in jio_req.target_identifiers_json


def test_section_230_bnss_defense_copy_pocso_and_intimate_media_redaction_gate():
    """Acceptance Test 3: P. Gopalkrishnan (2019) CSAM/intimate-media lock and Section 72 BNS masking."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_defense_bundle_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    packager = ExhibitAndDefensePackager()

    sensitive_items = [
        SensitiveMediaItem(
            canonical_path="/data/media/0/DCIM/Camera/evidence_normal.jpg",
            file_name="evidence_normal.jpg",
            sha256_hex="1111111111111111111111111111111111111111111111111111111111111111",
            md5_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            redaction_tag=None,
            timestamps_utc="2026-11-05T12:00:00Z",
            raw_bytes=b"SAFE_DOCUMENT_SCREENSHOT_BYTES",
        ),
        SensitiveMediaItem(
            canonical_path="/data/media/0/DCIM/Camera/intimate_assault_photo.jpg",
            file_name="intimate_assault_photo.jpg",
            sha256_hex="2222222222222222222222222222222222222222222222222222222222222222",
            md5_hex="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            redaction_tag=RedactionTag.CSAM_POCSO,
            timestamps_utc="2026-11-05T12:05:00Z",
            raw_bytes=b"CONTRABAND_BYTES_NEVER_EXPORT_TO_DEFENSE",
        ),
    ]

    bundle_result = packager.package_section_230_defense_bundle(
        case_id="CASE-412",
        items=sensitive_items,
        output_dir=sandbox,
        anonymize_victim_identity=True,
        victim_name="Pooja Sharma",
    )

    # 1. Verification of CSAM / Intimate Media Gate
    assert bundle_result.pocso_withheld_count == 1
    # Raw contraband bytes must NOT exist in the defense bundle directory
    withheld_path = os.path.join(sandbox, "exhibits", "intimate_assault_photo.jpg")
    assert not os.path.exists(withheld_path)

    # Placeholder card must exist and cite Hon'ble Supreme Court judgment in P. Gopalkrishnan v. State of Kerala
    placeholder_file = os.path.join(sandbox, "exhibits", "intimate_assault_photo_WITHHELD_NOTICE.txt")
    assert os.path.exists(placeholder_file)
    with open(placeholder_file, "r", encoding="utf-8") as f:
        card_text = f.read()
    assert "POCSO Act, 2012" in card_text
    assert "P. Gopalkrishnan v. State of Kerala (2019)" in card_text
    assert "2222222222222222222222222222222222222222222222222222222222222222" in card_text

    # Safe document screenshot must be copied
    safe_path = os.path.join(sandbox, "exhibits", "evidence_normal.jpg")
    assert os.path.exists(safe_path)

    # 2. Verification of Section 72 BNS Victim Anonymization
    html_viewer = os.path.join(sandbox, "Open_Case_Dossier.html")
    assert os.path.exists(html_viewer)
    with open(html_viewer, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "Pooja Sharma" not in html_content
    assert "[VICTIM_PROTECTED_ID_01]" in html_content


def test_crime_typology_dossier_compilation_and_courtroom_pdf():
    """Acceptance Test 4: Compile Cyber-Fraud Mule & USDT Laundering Dossier with 7 chapters."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_dossier_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    builder = CrimeTypologyDossierBuilder()

    dossier_data = {
        "case_title": "State vs. Vikram Singh & Others (Mule Syndicate)",
        "fir_number": "FIR No. 412/2026",
        "police_station": "Cyber Crime PS, New Delhi",
        "device_imei": "354829104928172",
        "mule_accounts": [
            {"bank": "SBI", "ac": "30984718291", "vpa": "mule1@ybl", "utr": "630911111111"}
        ],
        "crypto_wallets": [
            {"network": "TRON TRC-20", "address": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", "balance": "25000 USDT"}
        ],
        "handler_chats": [
            {
                "platform": "Telegram",
                "chat": "Mule Coordinator -> Vikram: send UTR screenshot for 50k",
                "vfs_id": 142,
                "source": "cache4.db-wal",
                "offset": "0x0041A2B0",
                "state": "HISTORICAL_COMMITTED_RECORD",
            }
        ],
        "linked_sec63_cert_uid": 101,
    }

    dossier_record, doc_path = builder.compile_dossier(
        profile_type=DossierProfileType.PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING,
        dossier_data=dossier_data,
        output_dir=sandbox,
    )

    assert dossier_record.dossier_profile_type == DossierProfileType.PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING
    assert os.path.exists(doc_path)
    assert len(dossier_record.exported_pdf_path_and_sha256) > 64

    # Verify provenance footer is present in the rendered document
    with open(doc_path, "r", encoding="utf-8") as f:
        doc_text = f.read()
    assert "[VFS ID: #142 | Source: cache4.db-wal | Offset: 0x0041A2B0 | State: HISTORICAL_COMMITTED_RECORD]" in doc_text
    assert "Chapter 1: Executive Summary & Device Owner Attribution" in doc_text
    assert "Chapter 4: End-to-End Rupee-to-Crypto (USDT/XMR) Laundering Chains" in doc_text


def test_dossier_and_exhibits_master_sqlite_export():
    """Acceptance Test 5: Verify export into dossier_freeze_and_exhibit_packager.sqlite."""
    output_db = os.path.join(".", ".workspace_tmp", "dossier_freeze_and_exhibit_packager.sqlite")
    if os.path.exists(output_db):
        os.remove(output_db)

    engine = DossierAndExhibitPackagerEngine()

    dossiers = [
        CrimeDossierRecord(
            dossier_uid=1,
            dossier_profile_type=DossierProfileType.PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING,
            dossier_title="Cyber Fraud Mule Dossier",
            export_audience_scope=ExportAudienceScope.IO_AND_COURT_UNREDACTED_MASTER,
            included_entity_uids_json="[1, 2]",
            included_story_uids_json="[101]",
            pocso_or_intimate_media_withheld_count=0,
            linked_sec63_certificate_uid=1,
            exported_pdf_path_and_sha256="dossier.pdf:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            exported_html5_bundle_sha256=None,
            compiled_at_ist_iso="2026-11-05 14:00:00 IST (+05:30)",
        )
    ]

    freeze_packets = [
        NodalFreezePacketRecord(
            freeze_packet_uid=1,
            target_agency_or_portal=NodalAgencyTarget.I4C_NCRP_1930_CFCFRMS_BANK_LIEN,
            total_accounts_or_wallets_count=2,
            total_utrs_or_txids_count=3,
            total_disputed_fiat_inr=285000.0,
            total_disputed_crypto_summary=None,
            exported_csv_xlsx_path="ncrp_packet.csv",
            exported_file_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            generated_at_ist_iso="2026-11-05 14:05:00 IST (+05:30)",
        )
    ]

    requisitions = [
        Section94BnssRequisitionRecord(
            requisition_uid=1,
            statutory_provision="Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 [erstwhile Sec 91 CrPC]",
            recipient_nodal_category=RecipientNodalCategory.BANK_NODAL_OFFICER,
            recipient_organization_name="State Bank of India",
            target_identifiers_json='["30984718291"]',
            requested_records_checklist="AOF, KYC, Statement",
            rendered_notice_doc_path="notice_sbi.txt",
        )
    ]

    engine.export_master_database(
        output_db_path=output_db,
        dossiers=dossiers,
        freeze_packets=freeze_packets,
        requisitions=requisitions,
    )

    assert os.path.exists(output_db)
    conn = sqlite3.connect(output_db)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM compiled_crime_dossiers_registry;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM nodal_freeze_and_lien_exports_ledger;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM section94_bnss_requisitions_queue;")
    assert cur.fetchone()[0] == 1

    conn.close()
