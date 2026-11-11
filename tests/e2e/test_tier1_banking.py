"""
Tier 1 Feature Coverage: Indian Banking & Financial Ecosystem
Tests Core Banking System (CBS) narration parsing, offline IFSC directory resolution,
deterministic bank statement password generation, AePS agent & RD service classification,
and cardless ATM cashout correlation.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.banking.cardless_runner import CardlessRunnerCorrelator
from src.banking.engine import IndianBankingSandboxEngine
from src.banking.ifsc_resolver import OfflineIFSCResolver
from src.banking.narration_parser import CoreBankingNarrationParser
from src.banking.pdf_unlocker import DeterministicBankStatementUnlocker


class TestTier1Banking(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_banking_")
        self.narration_parser = CoreBankingNarrationParser()
        self.ifsc_resolver = OfflineIFSCResolver()
        self.pdf_unlocker = DeterministicBankStatementUnlocker()
        self.cardless_correlator = CardlessRunnerCorrelator()

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_cbs_narration_parser_modes_and_splitting(self):
        """
        T1.4.1: Validates Core Banking System (CBS) narration parsing for UPI, IMPS, and NEFT.
        Authoritative source: Indian Core Banking System (CBS) transaction narration standards (Finacle/BaNCS).
        """
        # 1. UPI Credit Narration
        upi_narration = "UPI/CR/630911223344/MOHAMMAD IMRAN/SBIN/suspect@ybl/Payment"
        res_upi = self.narration_parser.parse_narration(upi_narration)
        self.assertIsNotNone(res_upi)
        self.assertEqual(res_upi.payment_rail, "UPI")
        self.assertEqual(res_upi.direction, "CREDIT")
        self.assertEqual(res_upi.utr_or_rrn, "630911223344")
        self.assertEqual(res_upi.counterparty_name, "MOHAMMAD IMRAN")
        self.assertEqual(res_upi.counterparty_vpa, "suspect@ybl")

        # 2. IMPS Debit Narration
        imps_narration = "TO TRANSFER-INB IMPS/630914829104/VIKRAM/HDFC0001234"
        res_imps = self.narration_parser.parse_narration(imps_narration)
        self.assertIsNotNone(res_imps)
        self.assertEqual(res_imps.payment_rail, "IMPS")
        self.assertEqual(res_imps.direction, "DEBIT")
        self.assertEqual(res_imps.utr_or_rrn, "630914829104")
        self.assertEqual(res_imps.counterparty_name, "VIKRAM")

        # 3. IMPS Credit Narration
        imps_cr_narration = "BY TRANSFER-IMPS/410293847581/RAMESH KUMAR/SBIN/9876543210"
        res_imps_cr = self.narration_parser.parse_narration(imps_cr_narration)
        self.assertIsNotNone(res_imps_cr)
        self.assertEqual(res_imps_cr.payment_rail, "IMPS")
        self.assertEqual(res_imps_cr.direction, "CREDIT")
        self.assertEqual(res_imps_cr.utr_or_rrn, "410293847581")
        self.assertEqual(res_imps_cr.counterparty_name, "RAMESH KUMAR")

        # 4. NEFT Narration
        neft_narration = "NEFT-CR-N09283910283-AMIT SHARMA-SETTLEMENT"
        res_neft = self.narration_parser.parse_narration(neft_narration)
        self.assertIsNotNone(res_neft)
        self.assertEqual(res_neft.payment_rail, "NEFT")
        self.assertEqual(res_neft.direction, "CREDIT")

    def test_offline_ifsc_directory_resolver(self):
        """
        T1.4.2: Validates offline resolution of 40+ Indian bank IFSC codes to legal institutions.
        Authoritative source: Reserve Bank of India National Clearing Cell Directory.
        """
        # Test SBI
        sbi_info = self.ifsc_resolver.resolve_ifsc("SBIN0000691")
        self.assertIsNotNone(sbi_info)
        self.assertEqual(sbi_info.bank_name, "State Bank of India")

        # Test HDFC
        hdfc_info = self.ifsc_resolver.resolve_ifsc("HDFC0000128")
        self.assertIsNotNone(hdfc_info)
        self.assertEqual(hdfc_info.bank_name, "HDFC Bank")

        # Test ICICI
        icici_info = self.ifsc_resolver.resolve_ifsc("ICIC0000001")
        self.assertIsNotNone(icici_info)
        self.assertEqual(icici_info.bank_name, "ICICI Bank")

        # Test validity checks
        self.assertTrue(self.ifsc_resolver.is_valid_ifsc("SBIN0000691"))
        self.assertTrue(self.ifsc_resolver.is_valid_ifsc("UTIB0000005"))
        self.assertFalse(self.ifsc_resolver.is_valid_ifsc("INVALID_CODE"))
        self.assertFalse(self.ifsc_resolver.is_valid_ifsc("12345678901"))

    def test_deterministic_pdf_bank_statement_unlocker(self):
        """
        T1.4.3: Validates deterministic generation of Indian bank statement password masks.
        Authoritative source: Indian Banking password conventions (PAN, DOB, Name+DOB, Mobile).
        """
        candidates = self.pdf_unlocker.generate_candidate_passwords(
            account_holder_name="VIKRAM SHARMA",
            dob_ddmmyyyy="15081995",
            registered_mobile="9876543210",
            pan_number="ABCDE1234F",
            account_number="0000001234567890",
        )

        self.assertGreaterEqual(len(candidates), 6)
        # Verify presence of standard Indian bank password patterns
        self.assertIn("VIKR1508", candidates)       # SBI / HDFC standard (4 chars name + DDMM)
        self.assertIn("ABCDE1234F", candidates)     # PAN standard
        self.assertIn("abcde1234f", candidates)     # Lowercase PAN
        self.assertIn("0000001234567890", candidates) # Full account number

    def test_cardless_atm_runner_phone_normalization(self):
        """
        T1.4.4: Validates phone number normalization for cardless ATM cashout token tracking.
        Authoritative source: Indian Telephony E.164 and National Formatting.
        """
        norm_phone = self.cardless_correlator.normalize_phone_number("+91 98765 43210")
        self.assertEqual(norm_phone, "+919876543210")

        norm_plain = self.cardless_correlator.normalize_phone_number("9876543210")
        self.assertEqual(norm_plain, "+919876543210")

    def test_aeps_and_rd_service_packages_classification(self):
        """
        T1.4.5: Validates classification of Aadhaar Enabled Payment System (AePS) apps
        and Biometric Registered Device (RD) telemetry packages.
        Authoritative source: UIDAI Aadhaar Authentication & NPCI AePS Guidelines.
        """
        engine = IndianBankingSandboxEngine()
        aeps_pkgs = engine.AEPS_PACKAGES
        rd_pkgs = engine.RD_SERVICE_PACKAGES

        # Verify presence of major Indian AePS agent applications
        self.assertIn("in.spicemoney.spicemoney", aeps_pkgs)
        self.assertIn("com.bnb.paynearby", aeps_pkgs)
        self.assertIn("in.bankit.agent", aeps_pkgs)

        # Verify presence of certified UIDAI RD service driver packages
        self.assertIn("com.mantra.rdservice", rd_pkgs)
        self.assertIn("com.scl.rdservice", rd_pkgs)  # Morpho Safran
        self.assertIn("com.acpl.registersdk", rd_pkgs)  # Startek FM220


if __name__ == "__main__":
    unittest.main()
