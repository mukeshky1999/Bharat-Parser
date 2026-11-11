"""
Tier 1 Feature Coverage: Crypto Exchanges & Web3 Wallets
Tests BIP-39 2048-word seed hunting, TRC-20 TRON conversions,
blockchain network address classification, custodial exchange registry,
and P2P escrow transaction decoding.
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
from src.cex.binance import (
    CEXP2PEscrowOrderRecord,
    CEXP2POrderStatus,
    CEXP2PTradeDirection,
)
from src.seedhunter.seed_hunter import (
    RecoveredSeedRecord,
    SecretType,
    scan_text_for_crypto_secrets,
    validate_bip39_mnemonic,
)
from src.web3.tronlink import (
    base58check_to_hex41,
    format_bigint_decimal,
    hex41_to_base58check,
)
from parsers.custodial_wallet_parser import (
    WALLET_SIGNATURES,
    compute_risk_badge,
    detect_chain_from_address,
)


class TestTier1Crypto(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_crypto_")

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_bip39_2048_word_mnemonic_validation(self):
        """
        T1.7.1: Validates BIP-39 mnemonic verification using official 2048-word dictionary and SHA-256 checksums.
        Authoritative source: Bitcoin Improvement Proposal BIP-0039 Specification.
        """
        # Official valid 12-word BIP-39 phrase with valid checksum
        valid_phrase = "army van defense carry jealous true garbage claim echo media make crunch"
        is_valid, entropy, word_idx = validate_bip39_mnemonic(valid_phrase)
        self.assertTrue(is_valid)
        self.assertEqual(len(entropy), 16)  # 128-bit entropy for 12 words

        # Corrupted phrase with checksum error (swapped last word)
        invalid_phrase = "army van defense carry jealous true garbage claim echo media make army"
        is_bad, _, _ = validate_bip39_mnemonic(invalid_phrase)
        self.assertFalse(is_bad)

        # Non-dictionary gibberish
        gibberish = "random words that do not belong to bip thirty nine dictionary at all"
        is_gibberish, _, _ = validate_bip39_mnemonic(gibberish)
        self.assertFalse(is_gibberish)

    def test_bip39_freeform_text_scanner(self):
        """
        T1.7.2: Validates scanning of unallocated memory/text lines for crypto mnemonic secrets.
        Authoritative source: BIP-39 Secret Hunter Engine.
        """
        phrase = "army van defense carry jealous true garbage claim echo media make crunch"
        recovered = scan_text_for_crypto_secrets(
            phrase,
            source_detail="suspect_notes.txt",
            source_vfs_file_id=501,
        )
        self.assertEqual(len(recovered), 1)

        rec = recovered[0]
        self.assertEqual(rec.secret_type, SecretType.BIP39_MNEMONIC_12_TO_24_WORDS)
        self.assertEqual(rec.plaintext_mnemonic_or_privkey, phrase)
        self.assertEqual(rec.source_vfs_file_id, 501)

    def test_tronlink_trc20_base58_hex41_conversion(self):
        """
        T1.7.3: Validates Tron Base58Check to Hex 41 conversion and TRC-20 6-decimal math.
        Authoritative source: TRON Developer Protocol Documentation.
        """
        # TRON USDT Smart Contract Address
        usdt_b58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        hex41 = base58check_to_hex41(usdt_b58)
        self.assertTrue(hex41.startswith("41"))
        self.assertEqual(len(hex41), 42)

        # Roundtrip verification
        roundtrip_b58 = hex41_to_base58check(hex41)
        self.assertEqual(roundtrip_b58, usdt_b58)

        # TRC-20 6-decimal USDT conversion (500,000,000 raw units = 500.000000 USDT)
        raw_val, usdt_formatted = format_bigint_decimal(500000000, 6)
        self.assertEqual(usdt_formatted, "500.000000")

    def test_crypto_chain_detection_from_address(self):
        """
        T1.7.4: Validates multi-chain address heuristics (EVM, Bitcoin, Tron).
        Authoritative source: EIP-55 (Ethereum), BIP-173 (Bech32), and Tron Base58 specs.
        """
        # EVM address (0x prefix, 40 hex chars)
        self.assertEqual(detect_chain_from_address("0x71C849186259437b752455c3d0961b78240409A6"), "EVM")

        # Bitcoin SegWit Bech32 (bc1q prefix)
        self.assertEqual(detect_chain_from_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "BTC")

        # Tron address (T prefix, 34 chars)
        self.assertEqual(detect_chain_from_address("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"), "TRX")

        # Invalid address returns None
        self.assertIsNone(detect_chain_from_address("NOT_A_CRYPTO_ADDRESS"))

    def test_custodial_wallet_registry_and_signatures(self):
        """
        T1.7.5: Validates custodial crypto exchange registry and risk badge calculation.
        Authoritative source: FIU-IND AML/CFT Domestic Registration Directory.
        """
        # Verify international & domestic FIU-IND entities in signatures
        self.assertIn("Coinbase", WALLET_SIGNATURES)
        self.assertIn("MEXC", WALLET_SIGNATURES)
        self.assertIn("Giottus", WALLET_SIGNATURES)  # FIU-IND domestic
        self.assertIn("Mudrex", WALLET_SIGNATURES)   # FIU-IND domestic

        # Test risk badge computation for structuring (near ₹50,000 threshold)
        badge_structuring = compute_risk_badge(48000.0, None, "FIAT_ONRAMP")
        self.assertIn("Structuring", badge_structuring)

        # Test risk badge computation for large single transactions (>= ₹5 Lakh)
        badge_high = compute_risk_badge(600000.0, None, "TRANSFER")
        self.assertIn("≥ ₹5L", badge_high)

    def test_binance_p2p_escrow_record_creation(self):
        """
        T1.7.6: Validates Binance P2P escrow transaction model with INR banking rail.
        Authoritative source: Binance P2P Merchant Escrow Specification.
        """
        order = CEXP2PEscrowOrderRecord(
            p2p_order_uid="P2P_UID_101",
            cex_account_uid="ACC_BINANCE_01",
            exchange_name="Binance",
            source_vfs_file_id=601,
            recovery_classification="ALLOCATED_DB",
            p2p_order_number="BNB_ORDER_9918273645",
            trade_direction=CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT,
            order_status=CEXP2POrderStatus.COMPLETED_RELEASED,
            crypto_asset="USDT",
            crypto_quantity_decimal=1200.50,
            fiat_currency="INR",
            fiat_total_amount=105644.00,
            unit_exchange_rate=88.00,
            counterparty_cex_uid_nick="FastCryptoTrader",
            counterparty_verified_kyc_name="SURESH CHANDRA",
            fiat_payment_rail="UPI / IMPS",
            counterparty_vpa_or_bank_ifsc="suresh@okhdfcbank",
            extracted_utr_or_giftcard_code="630911223344",
            is_third_party_payer_mismatch=False,
            order_created_utc_iso="2024-05-04T10:00:00Z",
            order_completed_utc_iso="2024-05-04T10:15:00Z",
            evidentiary_state=None,
        )

        self.assertEqual(order.exchange_name, "Binance")
        self.assertEqual(order.crypto_quantity_decimal, 1200.50)
        self.assertEqual(order.fiat_total_amount, 105644.00)
        self.assertEqual(order.extracted_utr_or_giftcard_code, "630911223344")
        self.assertEqual(order.counterparty_verified_kyc_name, "SURESH CHANDRA")


if __name__ == "__main__":
    unittest.main()
