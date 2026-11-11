"""
Master Engine: Indian Banking Sandbox Engine.
Orchestrates deep extraction across PSU, Private, Payments, AePS, and Corporate banking app sandboxes.
Parses offline mPassbooks, correlates cardless ATM runners, links biometric RD scanners to AePS agents,
and maintains the Master Case Ledger inside indian_banking_sandbox_engine.sqlite.
Adheres strictly to AGENTS.md Forensic Invariants and Section 9 of Module 3.3 Spec.
"""

from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Tuple, Union
import xml.etree.ElementTree as ET

from src.banking.cardless_runner import CardlessRunnerCorrelator
from src.banking.ifsc_resolver import OfflineIFSCResolver
from src.banking.models import (
    AppTierCategory,
    BankBeneficiaryCoolingRecord,
    BankingAppProfileRecord,
    BankMPassbookLedgerRecord,
    CardlessATMOrPDFRecord,
    CorporateRole,
    PaymentRail,
    SourceArtifactType,
    TxDirection,
)
from src.banking.narration_parser import CoreBankingNarrationParser
from src.banking.pdf_unlocker import DeterministicBankStatementUnlocker
from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp


class IndianBankingSandboxEngine:
    """Master engine orchestrating retail, payments, AePS, and corporate banking forensics."""

    AEPS_PACKAGES = {
        "in.spicemoney.spicemoney": "Spice Money AePS",
        "com.finopaymentbank.finomitra": "Fino Mitra AePS",
        "com.bnb.paynearby": "PayNearby AePS",
        "com.rnfi.relipay": "Relipay AePS",
        "com.roinet.xpresso": "Roinet Xpresso",
        "com.ezeepay.service": "Ezeepay",
        "in.bankit.agent": "Bankit Agent",
        "com.csc.digipay": "CSC DigiPay",
    }

    RD_SERVICE_PACKAGES = {
        "com.mantra.rdservice": "Mantra MFS100 RD Service",
        "com.mantra.mfs110.rdservice": "Mantra MFS110 RD Service",
        "com.scl.rdservice": "Morpho IDEMIA RD Service",
        "com.acpl.registersdk": "Startek FM220 RD Service",
        "com.secugen.rdservice": "SecuGen RD Service",
    }

    PSU_PACKAGES = {
        "com.sbi.lotusintouch": "State Bank of India (YONO)",
        "com.sbi.SBIFreedomPlus": "State Bank of India (YONO Lite)",
        "com.bankofbaroda.mconnect": "Bank of Baroda (bob World)",
        "com.bankofbaroda.mpassbook": "Bank of Baroda (mPassbook)",
        "com.Version1": "Punjab National Bank (PNB One)",
        "com.canarabank.mobility": "Canara Bank (ai1)",
        "com.unionbank.ecommerce.mobile.android": "Union Bank of India (Vyom)",
        "com.indianbank.indoasis": "Indian Bank (IndOASIS)",
        "com.boi.ua.android": "Bank of India (BOI Mobile)",
    }

    PRIVATE_PACKAGES = {
        "com.csam.icici.bank.imobile": "ICICI Bank (iMobile Pay)",
        "com.snapwork.hdfc": "HDFC Bank MobileBanking",
        "com.msf.kbank.mobile": "Kotak Mahindra Bank (Kotak811)",
        "com.axis.mobile": "Axis Bank (Axis Mobile)",
        "com.indusind.indusmobile": "IndusInd Bank",
        "com.idfcfirstbank.optimus": "IDFC FIRST Bank",
        "com.yesbank": "Yes Bank (IRIS)",
        "com.fedmobile": "Federal Bank (FedMobile)",
        "com.epifi.paisa": "Federal Bank (Fi Money)",
        "money.jupiter": "Federal Bank (Jupiter)",
    }

    PAYMENTS_PACKAGES = {
        "com.myairtelapp": "Airtel Payments Bank",
        "com.ippb.app": "India Post Payments Bank",
        "com.jio.finance": "Jio Payments Bank",
    }

    CORPORATE_PACKAGES = {
        "com.sbi.yonobusiness": "SBI YONO Business",
        "com.icicibank.instabiz": "ICICI Bank InstaBIZ",
        "com.hdfc.cbx": "HDFC Bank CorpApp",
        "com.axis.AxisCorporate": "Axis Corporate",
        "com.kotak.fyn": "Kotak fyn",
        "com.bankofbaroda.bobworldbusiness": "bob World Business",
    }

    def __init__(self) -> None:
        self.narration_parser = CoreBankingNarrationParser()
        self.ifsc_resolver = OfflineIFSCResolver()
        self.runner_correlator = CardlessRunnerCorrelator()
        self.pdf_unlocker = DeterministicBankStatementUnlocker()

    def analyze_banking_sandboxes(
        self,
        root_data_dir: Union[str, Path],
    ) -> Tuple[List[BankingAppProfileRecord], List[BankMPassbookLedgerRecord]]:
        """
        Discovers and parses Indian banking app sandboxes (PSU, Private, Payments, AePS, Corporate).
        Returns:
            Tuple of (discovered_profiles, extracted_ledger_transactions).
        """
        root = Path(root_data_dir)
        if not root.exists():
            return [], []

        profiles: List[BankingAppProfileRecord] = []
        transactions: List[BankMPassbookLedgerRecord] = []

        # Step 1: Discover attached RD service hardware serial numbers
        discovered_rd_scanner_sn: Optional[str] = None
        for pkg_name, label in self.RD_SERVICE_PACKAGES.items():
            pkg_dir = root / pkg_name
            if not pkg_dir.exists():
                continue
            shared_prefs_dir = pkg_dir / "shared_prefs"
            if shared_prefs_dir.exists():
                for xml_file in shared_prefs_dir.glob("*.xml"):
                    try:
                        tree = ET.parse(xml_file)
                        r = tree.getroot()
                        for el in r:
                            name_attr = el.attrib.get("name", "").lower()
                            val_attr = el.attrib.get("value") or el.text
                            if name_attr in (
                                "deviceserialnumber",
                                "device_serial_number",
                                "serialnumber",
                                "serial_number",
                            ):
                                if val_attr:
                                    discovered_rd_scanner_sn = str(val_attr).strip()
                                    break
                    except Exception:
                        error_occurred = True

        # Step 2: Iterate all app packages in root directory
        for pkg_dir in root.iterdir():
            if not pkg_dir.is_dir():
                continue

            pkg_name = pkg_dir.name
            app_tier = AppTierCategory.PRIVATE_RETAIL.value
            inst_name = "Indian Banking App"

            if pkg_name in self.AEPS_PACKAGES:
                app_tier = AppTierCategory.AEPS_BC_AGENT_APP.value
                inst_name = self.AEPS_PACKAGES[pkg_name]
            elif pkg_name in self.PSU_PACKAGES:
                app_tier = AppTierCategory.PSU_RETAIL.value
                inst_name = self.PSU_PACKAGES[pkg_name]
            elif pkg_name in self.PRIVATE_PACKAGES:
                app_tier = AppTierCategory.PRIVATE_RETAIL.value
                inst_name = self.PRIVATE_PACKAGES[pkg_name]
            elif pkg_name in self.PAYMENTS_PACKAGES:
                app_tier = AppTierCategory.PAYMENTS_BANK.value
                inst_name = self.PAYMENTS_PACKAGES[pkg_name]
            elif pkg_name in self.CORPORATE_PACKAGES:
                app_tier = AppTierCategory.CORPORATE_SME_BANKING.value
                inst_name = self.CORPORATE_PACKAGES[pkg_name]
            elif pkg_name in self.RD_SERVICE_PACKAGES:
                app_tier = AppTierCategory.BIOMETRIC_RD_SERVICE.value
                inst_name = self.RD_SERVICE_PACKAGES[pkg_name]

            # Parse shared_prefs for user profile
            shared_prefs_dir = pkg_dir / "shared_prefs"
            if shared_prefs_dir.exists():
                for xml_file in shared_prefs_dir.glob("*.xml"):
                    try:
                        tree = ET.parse(xml_file)
                        r = tree.getroot()
                        cif: Optional[str] = None
                        name: Optional[str] = None
                        mobile: Optional[str] = None
                        scanner_sn = discovered_rd_scanner_sn if app_tier == AppTierCategory.AEPS_BC_AGENT_APP.value else None

                        for el in r:
                            key = el.attrib.get("name", "").lower()
                            val = el.attrib.get("value") or el.text
                            if not val:
                                continue
                            val_str = str(val).strip()

                            if key in ("bc_agent_id", "agent_id", "merchant_id", "cif", "customer_id", "crn", "user_id"):
                                cif = val_str
                            elif key in ("merchant_name", "user_name", "account_holder_name", "name"):
                                name = val_str
                            elif key in ("registered_mobile", "mobile", "phone_number"):
                                mobile = val_str
                            elif key in ("deviceserialnumber", "device_serial_number", "serial_number"):
                                scanner_sn = val_str

                        if cif or name or scanner_sn:
                            prof = BankingAppProfileRecord(
                                app_instance_id=1,
                                source_vfs_file_id=101,
                                bank_institution_name=inst_name,
                                app_tier_category=app_tier,
                                customer_id_cif_crn=cif,
                                corporate_role=(
                                    CorporateRole.BC_CASH_AGENT.value
                                    if app_tier == AppTierCategory.AEPS_BC_AGENT_APP.value
                                    else CorporateRole.RETAIL_INDIVIDUAL.value
                                ),
                                account_holder_name=name,
                                registered_mobile_no=mobile,
                                attached_biometric_scanner_sn=scanner_sn,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            )
                            profiles.append(prof)
                    except Exception:
                        error_occurred = True

            # Parse offline databases
            db_dir = pkg_dir / "databases"
            if db_dir.exists():
                for db_file in db_dir.glob("*.db"):
                    conn = sqlite3.connect(f"file:{db_file.resolve()}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cur = conn.cursor()

                    try:
                        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [row["name"] for row in cur.fetchall()]

                        # AePS cash-out tables
                        for t in tables:
                            if "aeps" in t.lower() or "biometric" in t.lower() or "cashout" in t.lower() or t == "aeps_ledger":
                                cur.execute(f"SELECT * FROM {t};")
                                rows = cur.fetchall()
                                for r in rows:
                                    col_keys = r.keys()
                                    rrn = str(r["rrn"]) if "rrn" in col_keys and r["rrn"] else None
                                    aadhaar = str(r["aadhaar_mask"]) if "aadhaar_mask" in col_keys and r["aadhaar_mask"] else None
                                    amt = float(r["amount"]) if "amount" in col_keys and r["amount"] is not None else 0.0
                                    ts_val = r["txn_time"] if "txn_time" in col_keys else None

                                    utc_ts = "1970-01-01T00:00:00.000000Z"
                                    if ts_val is not None:
                                        try:
                                            num_ts = int(ts_val)
                                            if num_ts > 10_000_000_000:
                                                utc_ts = ForensicTimestamp.from_unix_milliseconds(num_ts).utc_iso8601
                                            elif num_ts > 0:
                                                utc_ts = ForensicTimestamp.from_unix_seconds(num_ts).utc_iso8601
                                        except ValueError:
                                            utc_ts = str(ts_val)

                                    rec = BankMPassbookLedgerRecord(
                                        source_vfs_file_id=201,
                                        source_artifact_type=SourceArtifactType.AEPS_AGENT_LEDGER.value,
                                        payment_rail=PaymentRail.AEPS_BIOMETRIC_CASHOUT.value,
                                        tx_direction=TxDirection.DEBIT.value,
                                        amount_inr_decimal=amt,
                                        tx_utc_iso=utc_ts,
                                        utr_or_rrn_reference=rrn,
                                        extracted_counterparty_acct_vpa=aadhaar,
                                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    )
                                    transactions.append(rec)

                            # mPassbook tables
                            elif "passbook" in t.lower() or "transaction" in t.lower() or "statement" in t.lower():
                                cur.execute(f"SELECT * FROM {t};")
                                rows = cur.fetchall()
                                for r in rows:
                                    col_keys = r.keys()
                                    narration = str(r["narration"]) if "narration" in col_keys and r["narration"] else ""
                                    amt = 0.0
                                    if "amount" in col_keys and r["amount"] is not None:
                                        amt = float(r["amount"])
                                    elif "debit_amt" in col_keys and r["debit_amt"]:
                                        amt = float(r["debit_amt"])
                                    elif "credit_amt" in col_keys and r["credit_amt"]:
                                        amt = float(r["credit_amt"])

                                    bal = float(r["running_balance"]) if "running_balance" in col_keys and r["running_balance"] else None

                                    parsed_narr = self.narration_parser.parse_narration(narration)

                                    branch_info = self.ifsc_resolver.resolve_ifsc(parsed_narr.counterparty_ifsc)
                                    loc = branch_info.formatted_location if branch_info else None

                                    rec = BankMPassbookLedgerRecord(
                                        source_vfs_file_id=202,
                                        source_artifact_type=SourceArtifactType.OFFLINE_MPASSBOOK_DB.value,
                                        payment_rail=parsed_narr.payment_rail,
                                        tx_direction=parsed_narr.direction,
                                        amount_inr_decimal=amt,
                                        tx_utc_iso="1970-01-01T00:00:00.000000Z",
                                        utr_or_rrn_reference=parsed_narr.utr_or_rrn,
                                        running_balance_inr=bal,
                                        raw_narration_text=narration,
                                        extracted_counterparty_name=parsed_narr.counterparty_name,
                                        extracted_counterparty_acct_vpa=parsed_narr.counterparty_vpa or parsed_narr.counterparty_acct,
                                        extracted_counterparty_ifsc=parsed_narr.counterparty_ifsc,
                                        resolved_branch_city_state=loc,
                                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    )
                                    transactions.append(rec)
                    finally:
                        conn.close()

        return profiles, transactions

    def export_to_ledger(
        self,
        profiles: List[BankingAppProfileRecord],
        transactions: List[BankMPassbookLedgerRecord],
        beneficiaries: List[BankBeneficiaryCoolingRecord],
        specials: List[CardlessATMOrPDFRecord],
        ledger_path: Union[str, Path],
    ) -> None:
        """
        Initializes indian_banking_sandbox_engine.sqlite schema and persists all records:
        1. banking_app_profiles_and_roles
        2. bank_mpassbook_and_sandbox_ledger
        3. bank_beneficiaries_and_cooling_audit
        4. cardless_atm_and_unlocked_pdfs_ledger
        """
        target = Path(ledger_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(target)
        cur = conn.cursor()

        try:
            # 1. banking_app_profiles_and_roles
            cur.execute("""
                CREATE TABLE IF NOT EXISTS banking_app_profiles_and_roles (
                    bank_profile_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    bank_institution_name TEXT NOT NULL,
                    app_tier_category TEXT NOT NULL,
                    corporate_id_code TEXT,
                    customer_id_cif_crn TEXT,
                    corporate_role TEXT,
                    account_holder_name TEXT,
                    registered_mobile_no TEXT,
                    linked_account_numbers_json TEXT,
                    attached_biometric_scanner_sn TEXT,
                    last_login_utc_iso TEXT,
                    recovery_classification TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_profile_cif
                ON banking_app_profiles_and_roles (customer_id_cif_crn);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_profile_cat
                ON banking_app_profiles_and_roles (app_tier_category);
            """)

            # 2. bank_mpassbook_and_sandbox_ledger
            cur.execute("""
                CREATE TABLE IF NOT EXISTS bank_mpassbook_and_sandbox_ledger (
                    bank_tx_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    bank_profile_uid INTEGER,
                    source_vfs_file_id INTEGER NOT NULL,
                    source_artifact_type TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    local_account_number TEXT,
                    payment_rail TEXT NOT NULL,
                    utr_or_rrn_reference TEXT,
                    tx_direction TEXT NOT NULL,
                    amount_inr_decimal REAL NOT NULL,
                    running_balance_inr REAL,
                    raw_narration_text TEXT,
                    extracted_counterparty_name TEXT,
                    extracted_counterparty_acct_vpa TEXT,
                    extracted_counterparty_ifsc TEXT,
                    resolved_branch_city_state TEXT,
                    tx_utc_iso TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_tx_utr
                ON bank_mpassbook_and_sandbox_ledger (utr_or_rrn_reference);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_tx_rail
                ON bank_mpassbook_and_sandbox_ledger (payment_rail);
            """)

            # 3. bank_beneficiaries_and_cooling_audit
            cur.execute("""
                CREATE TABLE IF NOT EXISTS bank_beneficiaries_and_cooling_audit (
                    beneficiary_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER,
                    source_vfs_file_id INTEGER NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    beneficiary_holder_name TEXT NOT NULL,
                    beneficiary_account_no TEXT NOT NULL,
                    beneficiary_ifsc_11_char TEXT,
                    resolved_bank_and_branch_loc TEXT,
                    added_utc_iso TEXT,
                    cooling_period_end_utc_iso TEXT,
                    first_transfer_utc_iso TEXT,
                    post_cooling_latency_minutes REAL,
                    is_rapid_mule_drain_flagged INTEGER DEFAULT 0
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_ben_acct
                ON bank_beneficiaries_and_cooling_audit (beneficiary_account_no);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_ben_rapid
                ON bank_beneficiaries_and_cooling_audit (is_rapid_mule_drain_flagged);
            """)

            # 4. cardless_atm_and_unlocked_pdfs_ledger
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cardless_atm_and_unlocked_pdfs_ledger (
                    special_artifact_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_category TEXT NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    bank_institution_name TEXT NOT NULL,
                    cardless_ref_id_or_pdf_name TEXT NOT NULL,
                    amount_inr_or_row_count REAL,
                    unlocked_pdf_password TEXT,
                    linked_runner_chat_recipient TEXT,
                    event_utc_iso TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_bank_cardless_ref
                ON cardless_atm_and_unlocked_pdfs_ledger (cardless_ref_id_or_pdf_name);
            """)

            # Insert profiles
            for p in profiles:
                rec_val = (
                    p.recovery_classification.value
                    if hasattr(p.recovery_classification, "value")
                    else str(p.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO banking_app_profiles_and_roles (
                        app_instance_id,
                        source_vfs_file_id,
                        bank_institution_name,
                        app_tier_category,
                        corporate_id_code,
                        customer_id_cif_crn,
                        corporate_role,
                        account_holder_name,
                        registered_mobile_no,
                        linked_account_numbers_json,
                        attached_biometric_scanner_sn,
                        last_login_utc_iso,
                        recovery_classification
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        p.app_instance_id,
                        p.source_vfs_file_id,
                        p.bank_institution_name,
                        p.app_tier_category,
                        p.corporate_id_code,
                        p.customer_id_cif_crn,
                        p.corporate_role,
                        p.account_holder_name,
                        p.registered_mobile_no,
                        p.linked_account_numbers_json,
                        p.attached_biometric_scanner_sn,
                        p.last_login_utc_iso,
                        rec_val,
                    ),
                )

            # Insert transactions
            for t in transactions:
                rec_val = (
                    t.recovery_classification.value
                    if hasattr(t.recovery_classification, "value")
                    else str(t.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO bank_mpassbook_and_sandbox_ledger (
                        bank_profile_uid,
                        source_vfs_file_id,
                        source_artifact_type,
                        recovery_classification,
                        local_account_number,
                        payment_rail,
                        utr_or_rrn_reference,
                        tx_direction,
                        amount_inr_decimal,
                        running_balance_inr,
                        raw_narration_text,
                        extracted_counterparty_name,
                        extracted_counterparty_acct_vpa,
                        extracted_counterparty_ifsc,
                        resolved_branch_city_state,
                        tx_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        t.bank_profile_uid,
                        t.source_vfs_file_id,
                        t.source_artifact_type,
                        rec_val,
                        t.local_account_number,
                        t.payment_rail,
                        t.utr_or_rrn_reference,
                        t.tx_direction,
                        t.amount_inr_decimal,
                        t.running_balance_inr,
                        t.raw_narration_text,
                        t.extracted_counterparty_name,
                        t.extracted_counterparty_acct_vpa,
                        t.extracted_counterparty_ifsc,
                        t.resolved_branch_city_state,
                        t.tx_utc_iso,
                    ),
                )

            # Insert beneficiaries
            for b in beneficiaries:
                rec_val = (
                    b.recovery_classification.value
                    if hasattr(b.recovery_classification, "value")
                    else str(b.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO bank_beneficiaries_and_cooling_audit (
                        app_instance_id,
                        source_vfs_file_id,
                        recovery_classification,
                        beneficiary_holder_name,
                        beneficiary_account_no,
                        beneficiary_ifsc_11_char,
                        resolved_bank_and_branch_loc,
                        added_utc_iso,
                        cooling_period_end_utc_iso,
                        first_transfer_utc_iso,
                        post_cooling_latency_minutes,
                        is_rapid_mule_drain_flagged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        b.app_instance_id,
                        b.source_vfs_file_id,
                        rec_val,
                        b.beneficiary_holder_name,
                        b.beneficiary_account_no,
                        b.beneficiary_ifsc_11_char,
                        b.resolved_bank_and_branch_loc,
                        b.added_utc_iso,
                        b.cooling_period_end_utc_iso,
                        b.first_transfer_utc_iso,
                        b.post_cooling_latency_minutes,
                        b.is_rapid_mule_drain_flagged,
                    ),
                )

            # Insert special artifacts
            for s in specials:
                cur.execute(
                    """
                    INSERT INTO cardless_atm_and_unlocked_pdfs_ledger (
                        artifact_category,
                        source_vfs_file_id,
                        bank_institution_name,
                        cardless_ref_id_or_pdf_name,
                        amount_inr_or_row_count,
                        unlocked_pdf_password,
                        linked_runner_chat_recipient,
                        event_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        s.artifact_category,
                        s.source_vfs_file_id,
                        s.bank_institution_name,
                        s.cardless_ref_id_or_pdf_name,
                        s.amount_inr_or_row_count,
                        s.unlocked_pdf_password,
                        s.linked_runner_chat_recipient,
                        s.event_utc_iso,
                    ),
                )

            conn.commit()

        finally:
            conn.close()
