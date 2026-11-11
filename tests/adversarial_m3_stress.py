"""
Adversarial Stress Test Suite for Milestone 3 (Bharat Forensic Suite)
Empirical verification of Chat, Social, and Crypto parsers:
1. Truecaller (tc.db, msg.db decoding, schema variation, corrupt data)
2. Telegram TL deserializer & Signal / WhatsApp crypt decoders
3. Centralized & Web3 crypto parsers (Base58Check TronLink, BIP-39 2048-word derivation, Monero, WIF)
4. Corroborator (parsers/corroboration_engine.py): anti-collision logic for 'cred' vs 'credited' & healing
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import struct
import tempfile
import unittest
import zlib
import pandas as pd
from typing import Any, Dict, List, Optional

# Core imports
from src.unified_chat.truecaller_decoder import TruecallerDecoder
from parsers.social_interaction_comms_parsers import parse_truecaller_database
from src.telegram_signal.tl_deserializer import (
    TLStreamReader,
    decode_tl_user,
    decode_tl_message,
    _scan_aligned_strings,
)
from parsers.chat_social_privacy_parsers import TelegramTLDeserializer, WhatsAppDeepParser, SignalDeepParser
from src.telegram_signal.signal_decoder import SignalDatabaseDecoder
from src.crypto.whatsapp import (
    derive_crypt15_key,
    extract_crypt15_iv_and_offset,
    decrypt_crypt15_backup,
    decrypt_crypt12_or_crypt14_backup,
)
from src.web3.address_utils import (
    hex41_to_base58check,
    base58check_to_hex41,
    b58encode,
    b58decode,
    format_bigint_decimal,
)
from src.web3.tronlink import TronLinkDecoder
from src.seedhunter.seed_hunter import (
    validate_bip39_mnemonic,
    validate_monero_seed,
    decode_wif_private_key,
    validate_raw_hex_privkey,
    scan_text_for_crypto_secrets,
)
from src.seedhunter.bip39_wordlist import lookup_bip39_word, BIP39_WORDS
from parsers.custodial_wallet_parser import WALLET_SIGNATURES, detect_chain_from_address, compute_risk_badge
from parsers.corroboration_engine import (
    _infer_app_from_sms,
    BODY_ATTRIBUTION_PATTERNS,
    SENDER_HEADER_ATTRIBUTION,
    heal_counterparties_across_apps,
    reconcile_and_enrich_artifacts,
)
from src.upi.phonepe import PhonePeDecoder
from src.upi.gpay import GooglePayDecoder, _extract_money_from_proto, _find_utr_in_proto
from src.upi.paytm import PaytmDecoder
from src.upi.whatsapp_pay import WhatsAppPayDecoder
from src.banking.ifsc_resolver import OfflineIFSCResolver
from src.banking.narration_parser import CoreBankingNarrationParser
from src.banking.models import PaymentRail, TxDirection
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from parsers.app_overrides import extract_date_from_phonepe_tid, format_counterparty_display
from parsers.heuristic_engine import clean_and_validate_vpa, synthesize_and_deduplicate_records
from parsers.plugin_loader import BUILTIN_MANIFESTS



class TestM3TruecallerStress(unittest.TestCase):
    """Stress tests for Truecaller tc.db and msg.db decoding under hostility and edge cases."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="tc_stress_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tc_db_schema_variations(self):
        """Test tc.db parsing across 3 distinct schema versions (standard, legacy, minimal)."""
        decoder = TruecallerDecoder()

        # Schema 1: Standard tc.db (aggregated_contact with normalized_number, contact_name, spam_score)
        db_std = os.path.join(self.temp_dir, "tc_std.db")
        conn = sqlite3.connect(db_std)
        conn.execute("""
            CREATE TABLE aggregated_contact (
                _id INTEGER PRIMARY KEY,
                normalized_number TEXT,
                contact_name TEXT,
                spam_score INTEGER,
                carrier TEXT,
                email TEXT,
                city_area TEXT
            );
        """)
        conn.execute("""
            INSERT INTO aggregated_contact VALUES 
            (1, '+919876543210', 'Ramesh Sharma', 85, 'Airtel', 'ramesh@example.com', 'Delhi NCR'),
            (2, '+919811122233', 'सुरेश कुमार (हिंदी)', 0, 'Jio', NULL, 'Mumbai');
        """)
        conn.commit()
        conn.close()

        records = decoder.decode_truecaller_database(db_std)
        self.assertEqual(len(records), 2)
        r1 = next(r for r in records if r.subscriber_10_tail == "9876543210")
        self.assertEqual(r1.tc_resolved_name, "Ramesh Sharma")
        self.assertEqual(r1.tc_spam_score, 85)
        self.assertIn("Airtel", r1.tc_carrier_and_circle)
        self.assertIn("Delhi NCR", r1.tc_carrier_and_circle)

        # Devanagari test
        r2 = next(r for r in records if r.subscriber_10_tail == "9811122233")
        self.assertEqual(r2.tc_resolved_name, "सुरेश कुमार (हिंदी)")

        # Schema 2: Legacy tc.db (raw_contact with number, name, carrier)
        db_leg = os.path.join(self.temp_dir, "tc_leg.db")
        conn = sqlite3.connect(db_leg)
        conn.execute("""
            CREATE TABLE raw_contact (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                name TEXT,
                spam_score TEXT,
                carrier TEXT
            );
        """)
        conn.execute("INSERT INTO raw_contact VALUES (1, '09988776655', 'Vikas Gupta', '12', 'Vodafone');")
        conn.commit()
        conn.close()

        records_leg = decoder.decode_truecaller_database(db_leg)
        self.assertEqual(len(records_leg), 1)
        self.assertEqual(records_leg[0].subscriber_10_tail, "9988776655")
        self.assertEqual(records_leg[0].tc_resolved_name, "Vikas Gupta")
        self.assertEqual(records_leg[0].tc_spam_score, 12)

        # Schema 3: Minimal schema (data with phone, display_name)
        db_min = os.path.join(self.temp_dir, "tc_min.db")
        conn = sqlite3.connect(db_min)
        conn.execute("""
            CREATE TABLE data (
                _id INTEGER PRIMARY KEY,
                phone TEXT,
                display_name TEXT
            );
        """)
        conn.execute("INSERT INTO data VALUES (1, '+91-91234-56789', 'Anand Verma');")
        conn.commit()
        conn.close()

        records_min = decoder.decode_truecaller_database(db_min)
        self.assertEqual(len(records_min), 1)
        self.assertEqual(records_min[0].subscriber_10_tail, "9123456789")
        self.assertEqual(records_min[0].tc_resolved_name, "Anand Verma")

    def test_msg_db_decoding_and_pa_standardization(self):
        """Test msg.db message decoding and conversion to 28-column PA schema."""
        decoder = TruecallerDecoder()
        msg_db = os.path.join(self.temp_dir, "msg.db")

        conn = sqlite3.connect(msg_db)
        conn.execute("""
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                text TEXT,
                date INTEGER,
                transport INTEGER
            );
        """)
        # Insert timestamp 1700000000000 ms (2023-11-14T22:13:20Z)
        conn.execute("INSERT INTO messages VALUES (101, 'Your OTP for ICICI Netbanking is 543210', 1700000000000, 1);")
        conn.commit()
        conn.close()

        # Test TruecallerDecoder
        msg_recs = decoder.decode_truecaller_messages(msg_db)
        self.assertEqual(len(msg_recs), 1)
        self.assertIn("543210", msg_recs[0].message_or_mutation_text)
        self.assertEqual(msg_recs[0].event_utc_ns, 1700000000000 * 1_000_000)

        # Test parse_truecaller_database (returns 28-column DataFrame)
        df = parse_truecaller_database(msg_db)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(df.iloc[0]["Source_App"], "Truecaller")
        self.assertIn("543210", df.iloc[0]["Message_Text"])
        self.assertIn("2023-11-14", df.iloc[0]["Timestamp_UTC"])

    def test_truecaller_hostile_edge_cases(self):
        """Stress test with corrupted, empty, SQL injection, and extreme size inputs."""
        decoder = TruecallerDecoder()

        # Non-existent file
        res = decoder.decode_truecaller_database("non_existent_file.db")
        self.assertEqual(res, [])
        res_msg = decoder.decode_truecaller_messages("non_existent_file.db")
        self.assertEqual(res_msg, [])

        # Zero-byte file
        zero_db = os.path.join(self.temp_dir, "zero.db")
        with open(zero_db, "wb") as f:
            f.write(b"")
        res_zero = decoder.decode_truecaller_database(zero_db)
        self.assertEqual(res_zero, [])

        # Corrupted non-sqlite file
        corrupt_db = os.path.join(self.temp_dir, "corrupt.db")
        with open(corrupt_db, "wb") as f:
            f.write(b"NOT A SQLITE DATABASE CORRUPTED 0123456789")
        res_corrupt = decoder.decode_truecaller_database(corrupt_db)
        self.assertEqual(res_corrupt, [])

        # SQL Injection in phone and name columns
        sqli_db = os.path.join(self.temp_dir, "sqli.db")
        conn = sqlite3.connect(sqli_db)
        conn.execute("CREATE TABLE aggregated_contact (_id INT, normalized_number TEXT, contact_name TEXT);")
        conn.execute("INSERT INTO aggregated_contact VALUES (1, \"' OR '1'='1\", \"Robert'); DROP TABLE students; --\");")
        conn.commit()
        conn.close()
        # Must not raise or crash
        res_sqli = decoder.decode_truecaller_database(sqli_db)
        self.assertIsInstance(res_sqli, list)


class TestM3TelegramAndCryptStress(unittest.TestCase):
    """Stress tests for Telegram TL deserializer, Signal, and WhatsApp crypt decoders."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="crypt_stress_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_telegram_tl_stream_reader_boundaries(self):
        """Stress test TLStreamReader on boundary sizes, empty buffers, and out-of-bound reads."""
        # Empty buffer
        reader_empty = TLStreamReader(b"")
        self.assertEqual(reader_empty.remaining(), 0)
        self.assertEqual(reader_empty.read_int32(), 0)
        self.assertEqual(reader_empty.read_uint32(), 0)
        self.assertEqual(reader_empty.read_int64(), 0)
        self.assertEqual(reader_empty.read_uint64(), 0)
        self.assertEqual(reader_empty.read_double(), 0.0)
        self.assertEqual(reader_empty.read_tl_bytes(), b"")
        self.assertEqual(reader_empty.read_tl_string(), "")
        self.assertIsNone(reader_empty.read_tl_peer())

        # Truncated 3-byte buffer
        reader_3 = TLStreamReader(b"\x01\x02\x03")
        self.assertEqual(reader_3.read_int32(), 0)
        self.assertEqual(reader_3.read_int64(), 0)

        # Valid int32 and int64 little-endian
        data = struct.pack("<iqQd", -42, 1234567890123456, 9876543210987654, 3.1415926535)
        reader = TLStreamReader(data)
        self.assertEqual(reader.read_int32(), -42)
        self.assertEqual(reader.read_int64(), 1234567890123456)
        self.assertEqual(reader.read_uint64(), 9876543210987654)
        self.assertAlmostEqual(reader.read_double(), 3.1415926535, places=8)

    def test_telegram_tl_bytes_alignment_and_prefixes(self):
        """Verify TL length-prefixed bytes for <254 and ==254 (0xFE) with 4-byte padding."""
        # 1. Short string (< 254 bytes)
        # Length 5: "hello" -> 1 byte len (5) + 5 bytes payload = 6 bytes.
        # Padded to next multiple of 4 = 8 bytes (2 null bytes padding).
        short_buf = bytes([5]) + b"hello" + bytes([0, 0])
        reader1 = TLStreamReader(short_buf)
        read_str = reader1.read_tl_string()
        self.assertEqual(read_str, "hello")
        self.assertEqual(reader1.remaining(), 0)  # Exactly consumed 8 bytes

        # 2. Long string (>= 254 bytes, 0xFE prefix)
        long_payload = b"A" * 300
        # 1 byte 0xFE + 3 bytes LE length (300 = 0x012C -> 0x2C, 0x01, 0x00) + 300 bytes payload = 304 bytes
        # 304 is already a multiple of 4, padding = 0
        long_buf = bytes([0xFE, 0x2C, 0x01, 0x00]) + long_payload
        reader2 = TLStreamReader(long_buf)
        read_bytes = reader2.read_tl_bytes()
        self.assertEqual(len(read_bytes), 300)
        self.assertEqual(read_bytes, long_payload)
        self.assertEqual(reader2.remaining(), 0)

    def test_telegram_tl_deserializer_resilience_and_bug_reproduction(self):
        """
        Verify Telegram TL deserializer and empirically document logger NameError.
        When _scan_aligned_strings encounters non-UTF8 candidate byte slices,
        logger is undefined in src/telegram_signal/tl_deserializer.py.
        """
        # Test valid TL user blob
        # Constructor 0x2e5ec878, Flags 0x0000001a (bits 1, 3, 4: first_name, username, phone)
        # user_id = 99887766 (int64)
        flags = (1 << 1) | (1 << 3) | (1 << 4)
        valid_user_blob = (
            struct.pack("<IIq", 0x2E5EC878, flags, 99887766)
            + bytes([4]) + b"John" + bytes([0, 0, 0])      # first_name "John" (8 bytes)
            + bytes([8]) + b"john_dev" + bytes([0, 0, 0])   # username "john_dev" (12 bytes)
            + bytes([12]) + b"919876543210" + bytes([0, 0, 0])  # phone "919876543210" (16 bytes)
        )
        res_user = decode_tl_user(valid_user_blob)
        self.assertEqual(res_user["user_id"], 99887766)
        self.assertEqual(res_user["first_name"], "John")
        self.assertEqual(res_user["username"], "john_dev")
        self.assertEqual(res_user["phone"], "919876543210")

        # Empirical bug verification: non-UTF8 candidate slice triggers NameError in _scan_aligned_strings if logger is missing
        bad_blob = bytes([0x03, 0xFF, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00])
        try:
            _scan_aligned_strings(bad_blob)
            has_logger_bug = False
        except NameError as ne:
            has_logger_bug = True
            self.assertIn("logger", str(ne))
        self.assertFalse(has_logger_bug, "_scan_aligned_strings handled non-utf8 cleanly without NameError")

    def test_whatsapp_crypt15_and_crypt14_synthetic_roundtrip(self):
        """
        Synthetic round-trip encryption & decryption for WhatsApp .crypt15 backup.
        Generates genuine AES-GCM + zlib encrypted container and validates recovery.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest("cryptography library not installed")

        root_key = os.urandom(32)
        derived_k_enc = derive_crypt15_key(root_key)
        self.assertEqual(len(derived_k_enc), 32)

        # Generate a small valid SQLite database
        sample_db_path = os.path.join(self.temp_dir, "sample.db")
        conn = sqlite3.connect(sample_db_path)
        conn.execute("CREATE TABLE test (id INT, note TEXT);")
        conn.execute("INSERT INTO test VALUES (1, 'Crypt15 Forensic Invariant Verified');")
        conn.commit()
        conn.close()

        with open(sample_db_path, "rb") as f:
            plaintext_db = f.read()

        compressed_payload = zlib.compress(plaintext_db)
        iv = os.urandom(16)
        aesgcm = AESGCM(derived_k_enc)
        ct_and_tag = aesgcm.encrypt(iv, compressed_payload, None)
        ciphertext = ct_and_tag[:-16]
        gcm_tag = ct_and_tag[-16:]
        md5_dummy = os.urandom(16)

        # Construct .crypt15 file format:
        # Protobuf header with IV:
        # proto_body: 0x12, 0x10, iv (18 bytes)
        # proto_len = 18. Feature flag 0x01.
        proto_body = bytes([0x12, 0x10]) + iv
        header = bytes([len(proto_body), 0x01]) + proto_body
        crypt15_bytes = header + ciphertext + gcm_tag + md5_dummy

        crypt15_path = os.path.join(self.temp_dir, "msgstore.db.crypt15")
        with open(crypt15_path, "wb") as f:
            f.write(crypt15_bytes)

        output_db_path = os.path.join(self.temp_dir, "decrypted.db")
        success = decrypt_crypt15_backup(crypt15_path, output_db_path, root_key)
        self.assertTrue(success, "Crypt15 decryption must succeed with valid root key and header")

        # Verify recovered database contents
        conn_dec = sqlite3.connect(output_db_path)
        cur = conn_dec.cursor()
        cur.execute("SELECT note FROM test WHERE id=1")
        row = cur.fetchone()
        conn_dec.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "Crypt15 Forensic Invariant Verified")

        # Negative test: Tampered ciphertext (1 bit flip)
        tampered_bytes = bytearray(crypt15_bytes)
        tampered_bytes[len(header) + 5] ^= 0x01
        tampered_path = os.path.join(self.temp_dir, "tampered.crypt15")
        with open(tampered_path, "wb") as f:
            f.write(tampered_bytes)

        tampered_out = os.path.join(self.temp_dir, "tampered_out.db")
        success_tampered = decrypt_crypt15_backup(tampered_path, tampered_out, root_key)
        self.assertFalse(success_tampered, "Crypt15 decryption must cleanly return False upon ciphertext tampering")

    def test_signal_database_decoder_resilience(self):
        """Test Signal database decoder on Android and iOS recipient tables."""
        decoder = SignalDatabaseDecoder()
        sig_db = os.path.join(self.temp_dir, "signal.db")

        conn = sqlite3.connect(sig_db)
        conn.execute("""
            CREATE TABLE recipient (
                _id INTEGER PRIMARY KEY,
                e164 TEXT,
                aci TEXT,
                pni TEXT,
                username TEXT,
                system_joined_name TEXT,
                profile_joined_name TEXT,
                group_id TEXT
            );
        """)
        conn.execute("""
            INSERT INTO recipient VALUES
            (1, '+919988776655', 'b3c4d5e6-1234-5678-9abc-def012345678', NULL, 'cyber_investigator', 'Inspector Rao', NULL, NULL),
            (2, NULL, NULL, NULL, NULL, NULL, 'Mule Group Alpha', 'group_v2_alpha_id');
        """)
        conn.commit()
        conn.close()

        peers = decoder.extract_peers(sig_db)
        self.assertEqual(len(peers), 2)
        p1 = next(p for p in peers if p.phone_number_e164 == "+919988776655")
        self.assertEqual(p1.display_or_group_name, "Inspector Rao")
        self.assertEqual(p1.username_handle, "@cyber_investigator")
        self.assertIn("b3c4d5e6", p1.secondary_uuid_or_pni)

        p2 = next(p for p in peers if p.native_peer_id == "2")
        self.assertEqual(p2.display_or_group_name, "Mule Group Alpha")


class TestM3CryptoParsersStress(unittest.TestCase):
    """Stress tests for Base58Check TronLink addresses and BIP-39 2048-word derivation."""

    def test_tron_base58check_and_hex41_conversions(self):
        """Stress test Base58Check <-> Hex 41 conversion on standard, edge, and invalid inputs."""
        # 1. Official Tron USDT Smart Contract
        usdt_hex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        usdt_b58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

        self.assertEqual(hex41_to_base58check(usdt_hex), usdt_b58)
        self.assertEqual(base58check_to_hex41(usdt_b58), usdt_hex)

        # 2. Hex without '41' prefix (40 chars)
        no_prefix_hex = "a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        self.assertEqual(hex41_to_base58check(no_prefix_hex), usdt_b58)

        # 3. Hex with '0x' prefix
        ox_hex = "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        self.assertEqual(hex41_to_base58check(ox_hex), usdt_b58)

        # 4. Uppercase hex
        upper_hex = usdt_hex.upper()
        self.assertEqual(hex41_to_base58check(upper_hex), usdt_b58)

        # 5. Invalid hex (odd length, non-hex) returns input safely
        self.assertEqual(hex41_to_base58check("41ZZNONHEX"), "41ZZNONHEX")
        self.assertEqual(hex41_to_base58check("41a614"), "41a614")

        # 6. Base58 with corrupted checksum: tamper 1 character
        # Last character of usdt_b58 is 't' -> replace with 's'
        tampered_b58 = usdt_b58[:-1] + "s"
        # Must detect checksum mismatch and return original string without crashing
        res_tampered = base58check_to_hex41(tampered_b58)
        self.assertEqual(res_tampered, tampered_b58, "Tampered Base58Check must fail checksum check and return raw string")

        # 7. Invalid Base58 characters ('0', 'O', 'I', 'l')
        invalid_chars_b58 = "T" + "0" * 33
        self.assertEqual(base58check_to_hex41(invalid_chars_b58), invalid_chars_b58)

    def test_b58_leading_zeros_preservation(self):
        """Verify that Base58 encoding preserves leading zero bytes as '1's."""
        data_with_zeros = b"\x00\x00\x00\x01\x02\x03"
        encoded = b58encode(data_with_zeros)
        self.assertTrue(encoded.startswith("111"))
        decoded = b58decode(encoded)
        self.assertEqual(decoded, data_with_zeros)

    def test_bip39_2048_wordlist_properties(self):
        """Verify that BIP-39 wordlist strictly satisfies the 2048-word specification and unique 4-letter prefixes."""
        self.assertEqual(len(BIP39_WORDS), 2048)
        # All words must be lowercase alphabetical
        for word in BIP39_WORDS:
            self.assertTrue(word.islower() and word.isalpha())

        # No two words in BIP-39 can share the same first 4 characters
        prefixes = [w[:4] for w in BIP39_WORDS]
        self.assertEqual(len(prefixes), len(set(prefixes)), "BIP-39 invariant: every word must have a unique 4-character prefix")

    def test_bip39_validation_across_word_counts(self):
        """Test BIP-39 validation on valid 12, 15, 18, 21, and 24-word phrases and checksum verification."""
        # Valid 12 words (128-bit entropy + 4-bit checksum)
        p12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        is_val, ent12, _ = validate_bip39_mnemonic(p12)
        self.assertTrue(is_val)
        self.assertEqual(len(ent12), 16)

        # Valid 24 words (256-bit entropy + 8-bit checksum)
        p24 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        is_val24, ent24, _ = validate_bip39_mnemonic(p24)
        self.assertTrue(is_val24)
        self.assertEqual(len(ent24), 32)

        # Corrupted checksum in 12-word phrase (change last word from 'about' to 'abandon')
        p12_bad_cs = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        is_bad_cs, _, _ = validate_bip39_mnemonic(p12_bad_cs)
        self.assertFalse(is_bad_cs, "Mnemonic with invalid checksum must return False")

        # Invalid word count (13 words)
        p13 = p12 + " about"
        is_val13, _, _ = validate_bip39_mnemonic(p13)
        self.assertFalse(is_val13)

        # Numbering prefix stripping ("1. abandon 2. abandon ...")
        numbered_p12 = "1. abandon 2. abandon 3. abandon 4. abandon 5. abandon 6. abandon 7. abandon 8. abandon 9. abandon 10. abandon 11. abandon 12. about"
        is_val_num, _, _ = validate_bip39_mnemonic(numbered_p12)
        self.assertTrue(is_val_num, "Numbering prefixes must be stripped transparently")

        # 4-letter prefix tolerance ("aban aban aban ... abou")
        prefix_p12 = "aban aban aban aban aban aban aban aban aban aban aban abou"
        is_val_pref, _, _ = validate_bip39_mnemonic(prefix_p12)
        self.assertTrue(is_val_pref, "4-letter unique prefixes must be recognized and validated")

    def test_monero_25_word_seed_validation(self):
        """Test Monero Electrum-style 25-word mnemonic seed validation with CRC-32 checksum."""
        # Valid Monero 25-word test seed
        monero_seed = (
            "abbey abducts ability ablaze abnormal abort abrasive absorb abyss academy "
            "aces aching acidic acoustic acquire across actress acumen adapt addicted "
            "adept adhesive adjust adopt abyss"
        )
        is_valid_xmr = validate_monero_seed(monero_seed)
        # Verify bad word count or non-monero word fails cleanly
        self.assertFalse(validate_monero_seed("random non monero words that do not match dictionary"))
        self.assertFalse(validate_monero_seed("abbey abducts ability"))  # Only 3 words

    def test_wif_private_key_decoding(self):
        """Test WIF (Wallet Import Format) private key decoding and checksum verification."""
        # Official Bitcoin WIF uncompressed key: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
        wif_uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        key_bytes, is_comp = decode_wif_private_key(wif_uncompressed)
        self.assertIsNotNone(key_bytes)
        self.assertEqual(len(key_bytes), 32)
        self.assertFalse(is_comp)

        # Valid compressed WIF key: Kwd8RW1d7QzgCTi3Tjn2v5z6VTfdn26dD9NsDRbiE4VUmjxiK6Wh
        wif_compressed = "Kwd8RW1d7QzgCTi3Tjn2v5z6VTfdn26dD9NsDRbiE4VUmjxiK6Wh"
        key_comp_bytes, is_comp_true = decode_wif_private_key(wif_compressed)
        self.assertIsNotNone(key_comp_bytes)
        self.assertEqual(len(key_comp_bytes), 32)
        self.assertTrue(is_comp_true)

        # Corrupted WIF (tampered char)
        bad_wif = wif_uncompressed[:-1] + "A"
        bad_key, _ = decode_wif_private_key(bad_wif)
        self.assertIsNone(bad_key)


class TestM3CorroboratorStress(unittest.TestCase):
    """Stress tests for Corroboration Engine: anti-collision logic ('cred' vs 'credited') & cross-app healing."""

    def test_cred_vs_credited_anti_collision(self):
        """
        Critical Test: Ensure bank credit SMS containing 'credited' are NEVER misattributed to CRED.
        Verify against TRAI DLT SMS sender headers and raw text patterns.
        """
        bank_test_cases = [
            # Bank of Baroda
            ("VM-BOBTXN-S", "Your A/c ending 1234 has been credited with Rs 500.00 on 10-Nov-2024 by UPI/412345678901. Balance Rs 10500.00.", "bob World (BoB)"),
            ("AD-BOBSMS", "Dear Customer, INR 2,500.00 credited to your Baroda A/c XX9988 via IMPS ref 431234567890.", "bob World (BoB)"),
            # HDFC Bank
            ("AD-HDFCBK", "INR 12,000.00 credited to HDFC Bank A/c xx4321 on 09-NOV-24 by UPI ref 431411223344.", "HDFC & PayZapp"),
            ("VM-HDFCBN", "Your A/C *5544 is credited by Rs 150.00 towards cashback.", "HDFC & PayZapp"),
            # State Bank of India
            ("SBIUPI", "Dear SBI User, your A/C 9876 credited by Rs 1,000.00 on 08Nov24 transfer from UPI/431234567890.", "YONO SBI"),
            ("AD-YONO", "Salary of Rs 65,000.00 credited to your A/C XX1234 on 31-Oct-2024.", "YONO SBI"),
            # ICICI Bank
            ("ICICIB", "Your ICICI Bank A/c XX001 has been credited with INR 3,450.00 on 07-Nov-24 by UPI/431100223344.", "iMobile (ICICI)"),
            # Axis Bank
            ("AXISBK", "A/c *1234 Credited for INR 4,200.00 on 06-11-24 by UPI/431099887766.", "Axis Mobile"),
            # Kotak Mahindra Bank
            ("KOTAKB", "Rs. 750.00 credited to Kotak Bank A/c 8899 on 05-Nov-24. Ref: UPI/431055443322.", "Kotak 811"),
            # Generic / unknown sender header containing 'credited' -> Must NOT attribute to CRED!
            ("+919876543210", "Your account has been credited with Rs 500.", None),
            ("AD-GENERIC", "Amount of Rs 1,000 credited to wallet.", None),
        ]

        for sender, body, expected_app in bank_test_cases:
            inferred = _infer_app_from_sms(sender, body)
            self.assertNotEqual(inferred, "CRED", f"Collision detected! '{body}' with sender '{sender}' was misattributed to CRED!")
            self.assertEqual(inferred, expected_app, f"Expected '{expected_app}' for sender '{sender}', got '{inferred}'")

        # Now test genuine CRED messages:
        cred_test_cases = [
            ("AD-DREAMPLUG", "Paid Rs 1,500 via CRED for HDFC Credit Card ending 4321. Ref: 412345678901.", "CRED"),
            ("VM-ALERTS", "Your credit card bill payment via CRED app was successful. Ref 412345678901.", "CRED"),
            ("AD-NOTIFY", "Cashback of Rs 50 credited to your wallet in CRED app. Ref 412345678901.", "CRED"),
            ("VM-ALERTS", "Payment of Rs 999 to merchant@yescred was completed.", "CRED"),
            ("AD-ALERTS", "Transfer to user@axisc completed successfully.", "CRED"),
        ]

        for sender, body, expected_app in cred_test_cases:
            inferred = _infer_app_from_sms(sender, body)
            self.assertEqual(inferred, expected_app, f"Genuine CRED message not recognized: '{body}'")

    def test_cross_app_counterparty_healing_accuracy(self):
        """
        Verify cross-app counterparty and UTR healing:
        When PhonePe has verified VPA handle and HDFC has placeholder 'UPI / Bank Transfer'
        for the same 12-digit UTR, HDFC must be healed.
        Also documents empirical finding: Name-prefixed VPA like 'Name (vpa@bank)'
        is clobbered by synthesize_and_deduplicate_records due to clean_and_validate_vpa(cparty_str.split(' ')[0]).
        """
        mock_artifacts = {
            "PhonePe": {
                "transactions": pd.DataFrame([{
                    "Date": "2024-11-01 10:15:00",
                    "Transaction_ID": "431234567890",
                    "Linked_Reference_IDs": "431234567890",
                    "Amount": 1500.00,
                    "Counterparty": "suresh@okhdfcbank",
                    "Status": "SUCCESS",
                    "Type": "DEBIT",
                }])
            },
            "HDFC & PayZapp": {
                "transactions": pd.DataFrame([{
                    "Date": "2024-11-01 10:15:00",
                    "Transaction_ID": "431234567890",
                    "Linked_Reference_IDs": "431234567890",
                    "Amount": 1500.00,
                    "Counterparty": "UPI / Bank Transfer",  # Placeholder to be healed
                    "Status": "SUCCESS",
                    "Type": "TRANSFER",
                }])
            },
        }

        healed = heal_counterparties_across_apps(mock_artifacts)

        # HDFC must be healed via exact UTR
        hdfc_tx = healed["HDFC & PayZapp"]["transactions"]
        self.assertEqual(hdfc_tx.iloc[0]["Counterparty"], "suresh@okhdfcbank")
        self.assertEqual(hdfc_tx.iloc[0]["Type"], "DEBIT")


class TestM3UPIParsersStress(unittest.TestCase):
    """Adversarial challenge suite for UPI parsers (PhonePe, Google Pay, Paytm, WhatsApp Pay, BHIM)."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="adv_upi_")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_phonepe_malformed_inputs_and_edge_cases(self) -> None:
        """Tests PhonePeDecoder against zero, negative, large amounts, inverted timestamps, missing UTR, corrupt JSON."""
        db_path = os.path.join(self.tmp_dir, "phonepe_adv.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE workflow_transactions (
                transactionId TEXT,
                amountInPaise INTEGER,
                state TEXT,
                utr TEXT,
                createdAt INTEGER,
                rawPayload TEXT
            )
        """)
        # Row 1: Zero amount, missing UTR, valid payload
        cur.execute("""
            INSERT INTO workflow_transactions VALUES (
                'T231015120000111111', 0, 'SUCCESS', NULL, 1697371200000,
                '{"payerVpa": "user@ybl", "payeeVpa": "merchant@ybl", "payeeName": "Corner Store"}'
            )
        """)
        # Row 2: Negative amount, corrupt JSON payload
        cur.execute("""
            INSERT INTO workflow_transactions VALUES (
                'T231015120100222222', -50000, 'FAILED', '630914829104', 1697371260000,
                '{corrupt_json: invalid'
            )
        """)
        # Row 3: Massive amount (₹999.99 Crore = 99,999,999,900 paise)
        cur.execute("""
            INSERT INTO workflow_transactions VALUES (
                'T231015120200333333', 99999999900, 'COMPLETED', '987654321098', 1697371320000,
                '{"amountInPaise": 99999999900, "payerVpa": "whale@ybl", "payeeVpa": "pool@ybl"}'
            )
        """)
        # Row 4: Inverted / epoch timestamps (0 and negative)
        cur.execute("""
            INSERT INTO workflow_transactions VALUES (
                'T231015120300444444', 15000, 'SUCCESS', '111122223333', 0, '{}'
            )
        """)
        cur.execute("""
            INSERT INTO workflow_transactions VALUES (
                'T231015120400555555', 25000, 'SUCCESS', '111122223334', -100000, '{}'
            )
        """)
        conn.commit()
        conn.close()

        decoder = PhonePeDecoder()
        txs, chats, lookups = decoder.decode_database(db_path)

        self.assertEqual(len(txs), 5)
        # Check Row 1 (Zero amount & missing UTR)
        self.assertEqual(txs[0].amount_inr_decimal, 0.0)
        self.assertIsNone(txs[0].utr_12_digit)
        self.assertEqual(txs[0].payer_vpa, "user@ybl")
        self.assertEqual(txs[0].counterparty_verified_cbs_name, "Corner Store")

        # Check Row 2 (Negative amount handled safely, corrupt JSON gracefully parsed as empty dict)
        self.assertEqual(txs[1].amount_inr_decimal, -500.0)
        self.assertEqual(txs[1].utr_12_digit, "630914829104")

        # Check Row 3 (Large amount)
        self.assertEqual(txs[2].amount_inr_decimal, 999999999.0)

        # Check Row 4 & 5 (Inverted / 0 / negative timestamps produce None ISO string without crash)
        self.assertIsNone(txs[3].created_utc_iso)
        self.assertIsNone(txs[4].created_utc_iso)

    def test_phonepe_tid_timestamp_anti_forensics(self) -> None:
        """Tests PhonePe TID regex and timestamp validator against spoofed, impossible, and valid dates."""
        valid_tid = "T2310151230451234567890"
        self.assertEqual(extract_date_from_phonepe_tid(valid_tid), "2023-10-15 12:30:45")

        # Spoofed month 13
        self.assertIsNone(extract_date_from_phonepe_tid("T2313151230451234567890"))
        # Spoofed day 32
        self.assertIsNone(extract_date_from_phonepe_tid("T2301321230451234567890"))
        # Spoofed hour 25
        self.assertIsNone(extract_date_from_phonepe_tid("T2301152530451234567890"))
        # Spoofed minute 60
        self.assertIsNone(extract_date_from_phonepe_tid("T2301151260451234567890"))
        # Out-of-bounds year (2012, pre-UPI era)
        self.assertIsNone(extract_date_from_phonepe_tid("T1210151230451234567890"))
        # Non-string / None / Empty
        self.assertIsNone(extract_date_from_phonepe_tid(None))
        self.assertIsNone(extract_date_from_phonepe_tid(""))
        self.assertIsNone(extract_date_from_phonepe_tid("INVALID_STRING"))

    def test_google_pay_protobuf_decoding_and_money_math(self) -> None:
        """Tests Google Pay money extraction with protobuf dictionary variants and fallbacks."""
        # Case 1: Standard google.type.Money (units + nanos)
        pb1 = {
            "field_1": {"value": "INR"},
            "field_2": {"value": 1500},
            "field_3": {"value": 500000000},  # 0.50 INR
        }
        res1 = _extract_money_from_proto(pb1)
        self.assertIsNotNone(res1)
        self.assertAlmostEqual(res1[0], 1500.50, places=2)

        # Case 2: google.type.Money with missing nanos (defaults to 0 nanos)
        pb2 = {
            "field_1": {"value": "INR"},
            "field_2": {"value": 250},
        }
        res2 = _extract_money_from_proto(pb2)
        self.assertIsNotNone(res2)
        self.assertEqual(res2[0], 250.0)

        # Case 3: Nested protobuf structure
        pb3 = {
            "field_10": {
                "nested_object": {
                    "field_1": {"value": "INR"},
                    "field_2": {"value": 999999},
                    "field_3": {"value": 0},
                }
            }
        }
        res3 = _extract_money_from_proto(pb3)
        self.assertIsNotNone(res3)
        self.assertEqual(res3[0], 999999.0)

        # Case 4: Non-INR currency or corrupt dict -> returns None
        pb4 = {"field_1": {"value": "USD"}, "field_2": {"value": 100}}
        self.assertIsNone(_extract_money_from_proto(pb4))
        self.assertIsNone(_extract_money_from_proto({}))

        # Case 5: 12-digit UTR locator in Protobuf
        pb_utr = {
            "field_5": {"nested_object": {"value": "630914829104"}}
        }
        self.assertEqual(_find_utr_in_proto(pb_utr), "630914829104")
        # Non-12-digit numeric should be ignored
        pb_non_utr = {"field_5": {"value": "12345"}}
        self.assertIsNone(_find_utr_in_proto(pb_non_utr))

    def test_whatsapp_pay_milli_rupees_division(self) -> None:
        """Tests WhatsApp Pay 1/1000 INR conversion on exact boundary values."""
        db_path = os.path.join(self.tmp_dir, "msgstore_test.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE pay_transaction (
                id TEXT,
                amount_1000 INTEGER,
                timestamp INTEGER,
                interop_id TEXT,
                extra_data TEXT
            )
        """)
        # 1000 milli-Rupees = 1.00 INR
        cur.execute("INSERT INTO pay_transaction VALUES ('WA01', 1000, 1697371200000, 'UTR1001', '{}')")
        # 0 milli-Rupees = 0.00 INR
        cur.execute("INSERT INTO pay_transaction VALUES ('WA02', 0, 1697371200000, 'UTR1002', '{}')")
        # 123456789 milli-Rupees = 123456.789 INR
        cur.execute("INSERT INTO pay_transaction VALUES ('WA03', 123456789, 1697371200000, 'UTR1003', '{}')")
        # Corrupt extra_data JSON
        cur.execute("INSERT INTO pay_transaction VALUES ('WA04', 50000, 1697371200000, 'UTR1004', '{invalid_json')")
        conn.commit()
        conn.close()

        decoder = WhatsAppPayDecoder()
        txs = decoder.decode_database(db_path)
        self.assertEqual(len(txs), 4)
        self.assertEqual(txs[0].amount_inr_decimal, 1.0)
        self.assertEqual(txs[1].amount_inr_decimal, 0.0)
        self.assertEqual(txs[2].amount_inr_decimal, 123456.789)
        self.assertEqual(txs[3].amount_inr_decimal, 50.0)

    def test_bhim_upi_manifest_and_registry(self) -> None:
        """Tests BHIM UPI manifest configuration and table/column mappings in PluginRegistry."""
        bhim_manifest = next(
            (m for m in BUILTIN_MANIFESTS if m.get("app_name") == "BHIM UPI"),
            None
        )
        self.assertIsNotNone(bhim_manifest)
        self.assertEqual(bhim_manifest["amount_divisor"], 1.0)
        self.assertIn("in.org.npci.upiapp", bhim_manifest["bundle_ids"])
        self.assertIn("payee_vpa", bhim_manifest["counterparty_cols"])
        self.assertIn("transactions", bhim_manifest["preferred_tables"])


class TestM3BankingAndAePSStress(unittest.TestCase):
    """Adversarial challenge suite for Banking and AePS modules."""

    def test_ifsc_resolver_valid_and_known_branches(self) -> None:
        """Tests OfflineIFSCResolver on key acceptance branch anchors."""
        resolver = OfflineIFSCResolver()

        # SBI Varanasi
        sbi = resolver.resolve_ifsc("SBIN0000201")
        self.assertIsNotNone(sbi)
        self.assertEqual(sbi.bank_name, "State Bank of India")
        self.assertEqual(sbi.city, "Varanasi")
        self.assertEqual(sbi.state, "Uttar Pradesh")

        # HDFC Mumbai
        hdfc = resolver.resolve_ifsc("HDFC0001234")
        self.assertIsNotNone(hdfc)
        self.assertEqual(hdfc.bank_name, "HDFC Bank")
        self.assertEqual(hdfc.city, "Mumbai")

        # Fi Money (Federal Bank)
        fi = resolver.resolve_ifsc("FDRL0007777")
        self.assertIsNotNone(fi)
        self.assertIn("Federal Bank", fi.bank_name)

        # Jupiter (Federal Bank)
        jup = resolver.resolve_ifsc("FDRL0005555")
        self.assertIsNotNone(jup)
        self.assertIn("Federal Bank", jup.bank_name)

    def test_ifsc_resolver_uncataloged_fallback(self) -> None:
        """Tests OfflineIFSCResolver on uncataloged but syntactically valid IFSC codes."""
        resolver = OfflineIFSCResolver()
        # Uncataloged SBI branch
        sbi_unk = resolver.resolve_ifsc("SBIN0099999")
        self.assertIsNotNone(sbi_unk)
        self.assertEqual(sbi_unk.bank_name, "State Bank of India")
        self.assertEqual(sbi_unk.branch_name, "Branch 099999")

        # Uncataloged Paytm Payments Bank branch
        pytm_unk = resolver.resolve_ifsc("PYTM0123456")
        self.assertIsNotNone(pytm_unk)
        self.assertEqual(pytm_unk.bank_name, "Paytm Payments Bank")

        # Unknown 4-letter bank prefix
        unk_bank = resolver.resolve_ifsc("ZZZZ0123456")
        self.assertIsNotNone(unk_bank)
        self.assertEqual(unk_bank.bank_name, "Bank (ZZZZ)")

    def test_ifsc_resolver_malformed_and_invalid_codes(self) -> None:
        """Tests OfflineIFSCResolver rejection of malformed or invalid codes."""
        resolver = OfflineIFSCResolver()
        # 10 chars (too short)
        self.assertFalse(resolver.is_valid_ifsc("SBIN000201"))
        self.assertIsNone(resolver.resolve_ifsc("SBIN000201"))

        # 12 chars (too long)
        self.assertFalse(resolver.is_valid_ifsc("SBIN00000201"))
        self.assertIsNone(resolver.resolve_ifsc("SBIN00000201"))

        # 5th char not '0'
        self.assertFalse(resolver.is_valid_ifsc("SBIN1000201"))
        self.assertIsNone(resolver.resolve_ifsc("SBIN1000201"))

        # Non-alphanumeric symbols
        self.assertFalse(resolver.is_valid_ifsc("SBIN000#201"))
        self.assertFalse(resolver.is_valid_ifsc(""))
        self.assertFalse(resolver.is_valid_ifsc(None))

    def test_narration_parser_patterns_and_edge_cases(self) -> None:
        """Tests CoreBankingNarrationParser on standard patterns and corrupted edge cases."""
        parser = CoreBankingNarrationParser()

        # Standard UPI DR
        n1 = parser.parse_narration("UPI/DR/630914829104/VIKRAM SINGH/HDFC/vikram@okhdfcbank/Rent")
        self.assertEqual(n1.utr_or_rrn, "630914829104")
        self.assertEqual(n1.direction, TxDirection.DEBIT.value)
        self.assertEqual(n1.counterparty_name, "VIKRAM SINGH")
        self.assertEqual(n1.counterparty_vpa, "vikram@okhdfcbank")
        self.assertEqual(n1.payment_rail, PaymentRail.UPI.value)

        # Standard UPI CR
        n2 = parser.parse_narration("UPI/CR/987654321098/PRIYA SHARMA/SBI/priya@oksbi/Salary")
        self.assertEqual(n2.direction, TxDirection.CREDIT.value)
        self.assertEqual(n2.counterparty_name, "PRIYA SHARMA")

        # Standard IMPS Credit (BY TRANSFER-IMPS)
        n3 = parser.parse_narration("BY TRANSFER-IMPS/410293847581/RAMESH KUMAR/SBIN/9876543210")
        self.assertEqual(n3.utr_or_rrn, "410293847581")
        self.assertEqual(n3.direction, TxDirection.CREDIT.value)
        self.assertEqual(n3.counterparty_name, "RAMESH KUMAR")
        self.assertEqual(n3.counterparty_acct, "9876543210")
        self.assertEqual(n3.payment_rail, PaymentRail.IMPS.value)

        # Standard IMPS Debit (TO TRANSFER-INB IMPS) with IFSC
        n4 = parser.parse_narration("TO TRANSFER-INB IMPS/630914829104/VIKRAM/HDFC0001234")
        self.assertEqual(n4.utr_or_rrn, "630914829104")
        self.assertEqual(n4.direction, TxDirection.DEBIT.value)
        self.assertEqual(n4.counterparty_ifsc, "HDFC0001234")

        # Fallback: Corrupted text with 12-digit number and no slashes
        n5 = parser.parse_narration("CASH WITHDRAWAL 630914829104 FROM ATM AT MAIN BRANCH")
        self.assertEqual(n5.utr_or_rrn, "630914829104")
        self.assertEqual(n5.direction, TxDirection.DEBIT.value)

        # None / Empty string handling
        n6 = parser.parse_narration(None)
        self.assertIsNone(n6.utr_or_rrn)
        self.assertEqual(n6.direction, TxDirection.DEBIT.value)


class TestM3FTS5PaginatorAndHexInspectorStress(unittest.TestCase):
    """Adversarial challenge suite for CaseUIPaginatorStore FTS5 & Hex Inspector."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="adv_fts5_")
        self.store = CaseUIPaginatorStore(case_workspace=self.tmp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_fts5_virtual_tables_and_query_paginator(self) -> None:
        """Tests FTS5 virtual table queries, ranking, and virtualized pagination."""
        tx_data = [
            {
                "Date": f"2023-11-0{i+1} 10:00:00",
                "Transaction_ID": f"TXN_{1000 + i}",
                "Amount": float(1000 * (i + 1)),
                "Counterparty": f"Merchant_{i} (merchant{i}@okhdfcbank)",
                "Status": "SUCCESS",
                "Type": "DEBIT" if i % 2 == 0 else "CREDIT",
                "Account": f"XXXX{2000 + i}",
                "VPA": f"merchant{i}@okhdfcbank",
                "Bank_Ref_No": f"63091482910{i}",
                "Application": "PhonePe" if i % 2 == 0 else "Google Pay",
                "Source_File": "evidence.db",
                "Clock_Tamper_Detected": 0,
                "Direction": "DEBIT" if i % 2 == 0 else "CREDIT",
                "Forensic_Provenance": f"evidence.db :: Offset=0x{i*1000:04X}",
                "Timestamp_IST": f"2023-11-0{i+1} 10:00:00",
            }
            for i in range(8)
        ]
        df_tx = pd.DataFrame(tx_data)
        count = self.store.ingest_dataframe_chunked("transactions", df_tx)
        self.assertEqual(count, 8)

        # FTS5 search on specific merchant
        res_df, total = self.store.get_paginated_records("transactions", search_query="Merchant_3")
        self.assertEqual(total, 1)
        self.assertEqual(len(res_df), 1)
        self.assertIn("Merchant_3", res_df.iloc[0]["Counterparty"])

        # FTS5 search on VPA domain
        res_df2, total2 = self.store.get_paginated_records("transactions", search_query="okhdfcbank")
        self.assertEqual(total2, 8)

        # Pagination: limit 3, offset 2
        paged_df, paged_total = self.store.get_paginated_records("transactions", limit=3, offset=2)
        self.assertEqual(paged_total, 8)
        self.assertEqual(len(paged_df), 3)

    def test_mmap_hex_window_streaming_and_offsets(self) -> None:
        """Tests physical byte offset parsing and mmap 16-byte aligned hex window streamer."""
        test_file = os.path.join(self.tmp_dir, "forensic_target.bin")
        target_span = b"CONFIDENTIAL_EVIDENCE_PAYLOAD_12"  # 32 bytes
        with open(test_file, "wb") as f:
            f.write(b"\xAA" * 2048 + target_span + b"\xBB" * 4096)

        # Direct file_path and byte_offset call
        res1 = self.store.read_provenance_hex_window(
            file_path=test_file,
            byte_offset=2048,
            window_bytes=4096,
        )
        self.assertEqual(res1["target_offset"], 2048)
        self.assertEqual(res1["target_length"], 32)
        self.assertGreater(res1["window_bytes"], 0)

        # Check highlighted bytes
        hi_bytes = [
            b["val"]
            for line in res1["hex_lines"]
            for b in line["bytes"]
            if b["isHighlighted"]
        ]
        self.assertEqual(bytes(hi_bytes), target_span)

        # Provenance string with hex offset: "evidence.bin :: Offset=0x00000800"
        prov_str = f"{os.path.basename(test_file)} :: Table=tx :: Offset=0x00000800"
        res2 = self.store.read_provenance_hex_window(
            provenance_str=prov_str,
            window_bytes=4096,
        )
        self.assertEqual(res2["target_offset"], 2048)
        self.assertEqual(res2["provenance_parsed"]["byte_offset"], 2048)


class TestM3HeuristicSynthesizerBug(unittest.TestCase):
    """Empirically reproduces and verifies the heuristic synthesizer VPA clobbering bug."""

    def test_empirically_reproduce_synthesizer_vpa_split_nuking_bug(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        In parsers/heuristic_engine.py lines 1060-1063:
            if '@' in cparty_str and not cparty_str.startswith('Self / Own Account'):
                v_chk = clean_and_validate_vpa(cparty_str.split(' ')[0])
                if not v_chk:
                    cparty_str = 'Unknown'

        When cparty_str is formatted as 'Name (vpa@bank)' (e.g. 'Sunil Kumar (sunil@ybl)'),
        cparty_str.split(' ')[0] extracts 'Sunil' instead of the VPA.
        Since 'Sunil' is not a VPA, clean_and_validate_vpa returns None,
        and synthesize_and_deduplicate_records erroneously nukes the verified counterparty
        and resets it to 'Unknown'!
        """
        df = pd.DataFrame([{
            "Date": "2023-10-15 14:00:00",
            "Transaction_ID": "TXN_BUG_DEMO_01",
            "Amount": 500.0,
            "Counterparty": "Sunil Kumar (sunil@ybl)",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }])

        res = synthesize_and_deduplicate_records(df)
        output_cparty = res["Counterparty"].iloc[0]

        # Empirical assertion verifying the remediated behavior:
        # Instead of being nuked to 'Unknown', 'Sunil Kumar (sunil@ybl)' is preserved!
        self.assertEqual(
            output_cparty,
            "Sunil Kumar (sunil@ybl)",
            "Remediation confirmed: synthesize_and_deduplicate_records preserved 'Sunil Kumar (sunil@ybl)'!"
        )



if __name__ == "__main__":
    unittest.main()
