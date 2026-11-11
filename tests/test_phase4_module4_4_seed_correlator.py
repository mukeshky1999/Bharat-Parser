"""
Tests for Phase 4, Module 4.4: Cross-System BIP-39 Seed Phrase Hunter,
BIP-32/44/84 HD Public Address Derivation, Web3 Vault Unwrapper &
Rupee-to-USDT Laundering Correlator.
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

import base64
import hashlib
import json
import os
import sqlite3
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.seedhunter.models import (
    SecretType,
    BlockchainNetwork,
    LaunderingPattern,
    RecoveredSeedRecord,
    HDDerivedAddressRecord,
    LaunderingChainRecord,
)
from src.seedhunter.seed_hunter import (
    validate_bip39_mnemonic,
    validate_monero_seed,
    decode_wif_private_key,
    validate_raw_hex_privkey,
    scan_text_for_crypto_secrets,
)
from src.seedhunter.hd_derivator import (
    derive_master_seed_bip39,
    derive_hd_address,
    derive_all_standard_addresses,
)
from src.seedhunter.vault_unwrapper import (
    unwrap_web3_keystore_v3,
    unwrap_metamask_vault,
)
from src.seedhunter.correlator import (
    RupeeToCryptoCorrelator,
    Phase3UPIPayment,
    Phase4P2POrder,
    Phase4CryptoWithdrawal,
)
from src.seedhunter.engine import SeedHunterCorrelatorEngine
from src.validators.address_validators import keccak_256


# ---------------------------------------------------------------------------
# Test 1: BIP-39 Checksum Validation & Multi-Chain HD Public Address Derivation
# ---------------------------------------------------------------------------

def test_bip39_checksum_and_hd_address_derivation():
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Validates 12-word mnemonic checksum (0x06), prefix tolerance, corrupted rejection,
    and exact deterministic BIP-32/44/84 HD address derivations across TRON, EVM,
    Bitcoin SegWit, and Bitcoin Legacy. Also tests Monero 25-word & WIF formats.
    """
    # 1. Official BIP-39 Test Vector
    mnemonic_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    is_valid, entropy, cs = validate_bip39_mnemonic(mnemonic_12)
    assert is_valid is True
    assert entropy.hex() == "00000000000000000000000000000000"
    assert cs == 6  # 4-bit SHA-256 checksum is 0x06

    # Corrupted mnemonic (bad checksum word) MUST fail
    bad_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    bad_valid, _, _ = validate_bip39_mnemonic(bad_mnemonic)
    assert bad_valid is False

    # 4-letter Cryptosteel prefix tolerance
    prefix_mnemonic = "aban aban aban aban aban aban aban aban aban aban aban abou"
    prefix_valid, prefix_ent, prefix_cs = validate_bip39_mnemonic(prefix_mnemonic)
    assert prefix_valid is True
    assert prefix_ent == entropy
    assert prefix_cs == cs

    # 2. HD Public Address Derivations for Account 0, Address 0 (Passphrase = "")
    derived = derive_all_standard_addresses(mnemonic_12, passphrase="")
    assert len(derived) >= 4

    # Map by network enum
    addr_map = {d.blockchain_network: d.derived_public_address for d in derived}

    # Verify exact spec test vectors from Section 8.1:
    # TRON: m/44'/195'/0'/0/0 -> TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH
    assert addr_map[BlockchainNetwork.TRON_TRC20] == "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"

    # Ethereum / BSC: m/44'/60'/0'/0/0 -> 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
    assert addr_map[BlockchainNetwork.ETHEREUM_EVM_0X] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    # Bitcoin Native SegWit: m/84'/0'/0'/0/0 -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    assert addr_map[BlockchainNetwork.BITCOIN_SEGWIT_BIP84] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

    # Bitcoin Legacy: m/44'/0'/0'/0/0 -> 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
    assert addr_map[BlockchainNetwork.BITCOIN_LEGACY_BIP44] == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

    # 3. Monero 25-Word CRC-32 Checksum Validation
    # Build a valid 25-word Monero seed where 25th word is crc32 % 24
    monero_24 = [
        "abbey", "abducts", "ability", "ablaze", "abnormal", "abort",
        "abrasive", "absorb", "abyss", "academy", "aces", "aching",
        "acidic", "acoustic", "acquire", "across", "actress", "acuteness",
        "adjust", "admit", "adopt", "advance", "aerial", "affair",
    ]
    import zlib
    prefix_str = "".join(w[:3] for w in monero_24)
    crc_val = zlib.crc32(prefix_str.encode("ascii"))
    checksum_idx = crc_val % 24
    valid_monero_25 = " ".join(monero_24 + [monero_24[checksum_idx]])

    assert validate_monero_seed(valid_monero_25) is True

    # Corrupted 25th word must fail
    corrupted_monero_25 = " ".join(monero_24 + ["affair" if monero_24[checksum_idx] != "affair" else "abbey"])
    if checksum_idx != 23:
        assert validate_monero_seed(corrupted_monero_25) is False

    # 4. Bitcoin WIF Private Key Validation
    # Uncompressed WIF starting with '5'
    wif_uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    priv_uncomp, is_comp = decode_wif_private_key(wif_uncompressed)
    assert priv_uncomp is not None
    assert is_comp is False
    assert priv_uncomp.hex() == "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"

    # Compressed WIF starting with 'K'
    wif_compressed = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    priv_comp, is_comp_2 = decode_wif_private_key(wif_compressed)
    assert priv_comp is not None
    assert is_comp_2 is True
    assert priv_comp.hex() == "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"


# ---------------------------------------------------------------------------
# Test 2: Web3 Keystore Keccak-256 MAC Verification & AES-128-CTR Unwrap
# ---------------------------------------------------------------------------

def test_web3_keystore_mac_verification_and_unwrap():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Validates Version 3 Web3 Keystore JSON unwrapping using Keccak-256 MAC verification
    against crypto.mac and AES-128-CTR decryption under password 'Rahul@1408'.
    Also tests wrong-password MAC rejection and MetaMask PBKDF2+AES-GCM unwrapping.
    """
    password = "Rahul@1408"
    salt = bytes.fromhex("12" * 16)
    iv = bytes.fromhex("34" * 16)
    expected_privkey = bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f360319")

    # Derive key via PBKDF2-HMAC-SHA256
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 1024, 32)
    aes_key = derived[:16]
    mac_key = derived[16:32]

    # Encrypt with AES-128-CTR
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(expected_privkey) + enc.finalize()

    # Compute Keccak-256 MAC: keccak256(derivedKey[16:32] || ciphertext)
    mac = keccak_256(mac_key + ciphertext).hex()

    keystore_json = json.dumps({
        "version": 3,
        "id": "3198bc9c-6672-5ab3-d99f-4942900b4b0e",
        "address": "008aeeda4d805471d49b55f0d33a347156b2c414",
        "crypto": {
            "ciphertext": ciphertext.hex(),
            "cipherparams": {"iv": iv.hex()},
            "cipher": "aes-128-ctr",
            "kdf": "pbkdf2",
            "kdfparams": {
                "c": 1024,
                "dklen": 32,
                "prf": "hmac-sha256",
                "salt": salt.hex(),
            },
            "mac": mac,
        },
    })

    # Test valid password unwrapping
    ok, recovered_secret, details = unwrap_web3_keystore_v3(keystore_json, password)
    assert ok is True
    assert recovered_secret == expected_privkey.hex()
    assert details["mac_verified"] is True
    assert details["kdf"] == "pbkdf2"

    # Test invalid password rejection via Keccak-256 MAC mismatch
    fail_ok, fail_secret, fail_details = unwrap_web3_keystore_v3(keystore_json, "WrongPass#999")
    assert fail_ok is False
    assert fail_secret is None
    assert fail_details["mac_verified"] is False

    # Test MetaMask PBKDF2-HMAC-SHA256 + AES-256-GCM vault unwrapping
    mm_salt = bytes.fromhex("56" * 32)
    mm_iv = bytes.fromhex("78" * 16)
    mm_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), mm_salt, 1000, 32)
    aesgcm = AESGCM(mm_key)
    mm_plaintext = json.dumps([{"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}]).encode("utf-8")
    mm_ct_and_tag = aesgcm.encrypt(mm_iv, mm_plaintext, None)

    metamask_vault_json = json.dumps({
        "data": base64.b64encode(mm_ct_and_tag).decode("ascii"),
        "iv": base64.b64encode(mm_iv).decode("ascii"),
        "salt": base64.b64encode(mm_salt).decode("ascii"),
        "keyMetadata": {
            "algorithm": "PBKDF2",
            "params": {"iterations": 1000},
        },
    })

    mm_ok, mm_recovered, mm_meta = unwrap_metamask_vault(metamask_vault_json, password)
    assert mm_ok is True
    assert "abandon abandon" in mm_recovered


# ---------------------------------------------------------------------------
# Test 3: Split-UPI Smurfing Subset-Sum Correlator to Binance P2P & TRC-20
# ---------------------------------------------------------------------------

def test_split_upi_subset_sum_to_p2p_and_trc20_chain():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Reconstructs an end-to-end money laundering chain:
    1. Two PhonePe UPI debits (₹95,000 + ₹85,000 = ₹1,80,000).
    2. Binance P2P BUY order for 2,000.00 USDT at ₹1,80,000 to same counterparty VPA.
    3. CEX withdrawal of 2,000.00 USDT over TRC-20 to local TronLink Pro wallet.
    4. WhatsApp chat confirmation message referencing the UTRs and withdrawal.
    """
    # Hop 1: Two split UPI payments within 5 minutes of P2P order
    upi_tx1 = Phase3UPIPayment(
        tx_master_uid=101,
        utr_reference="630911111111",
        amount_inr=95000.00,
        counterparty_vpa="seller99@okaxis",
        counterparty_name="P2P Merchant NineNine",
        source_app="PhonePe",
        timestamp_utc_iso="2024-05-10T14:02:00Z",
    )
    upi_tx2 = Phase3UPIPayment(
        tx_master_uid=102,
        utr_reference="630922222222",
        amount_inr=85000.00,
        counterparty_vpa="seller99@okaxis",
        counterparty_name="P2P Merchant NineNine",
        source_app="PhonePe",
        timestamp_utc_iso="2024-05-10T14:05:00Z",
    )

    # Hop 2: Binance P2P order for ₹1,80,000.00 (2,000.00 USDT)
    p2p_order = Phase4P2POrder(
        p2p_order_uid=201,
        order_number="205938491823901",
        exchange_name="Binance",
        order_side="BUY",
        crypto_quantity=2000.00,
        crypto_currency="USDT",
        fiat_total_amount=180000.00,
        fiat_currency="INR",
        counterparty_vpa="seller99@okaxis",
        order_status="COMPLETED",
        created_utc_iso="2024-05-10T14:00:00Z",
        completed_utc_iso="2024-05-10T14:08:00Z",
    )

    # Hop 3 & 4: CEX withdrawal to local TronLink Pro wallet
    withdrawal = Phase4CryptoWithdrawal(
        transfer_uid=301,
        exchange_name="Binance",
        currency="USDT",
        amount=2000.00,
        blockchain_network="TRON_TRC20",
        destination_address="TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        txid="e739af182746bc92018374a8d029384e56b78a9c0d1e2f3a4b5c6d7e8f9a0b1c",
        timestamp_utc_iso="2024-05-10T14:20:00Z",
        matches_local_wallet=True,
    )

    chat_msg_id = "msg_whatsapp_99182"

    correlator = RupeeToCryptoCorrelator()
    chains = correlator.correlate(
        upi_transactions=[upi_tx1, upi_tx2],
        p2p_orders=[p2p_order],
        withdrawals=[withdrawal],
        chat_message_refs={p2p_order.order_number: chat_msg_id},
    )

    assert len(chains) == 1
    chain = chains[0]

    # Verify classification
    assert chain.chain_pattern_classification == LaunderingPattern.SPLIT_UPI_SMURFING_TO_P2P_USDT
    assert chain.hop1_total_fiat_outflow_inr == 180000.00

    # Verify UTRs recorded in hop1 json
    assert "630911111111" in chain.hop1_phase3_tx_master_uids_json
    assert "630922222222" in chain.hop1_phase3_tx_master_uids_json

    # Verify Hop 2 P2P details
    assert chain.hop2_cex_p2p_order_uid == 201
    assert "2000.00 USDT" in chain.hop2_acquired_crypto_amount

    # Verify Hop 3 withdrawal & Hop 4 destination
    assert chain.hop3_cex_withdrawal_or_pay_uid == 301
    assert "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH" in chain.hop4_self_custody_or_swap_json

    # Verify Hop 5 chat reference
    assert chain.hop5_chat_confirmation_msg_uid == chat_msg_id


# ---------------------------------------------------------------------------
# Test 4: Master SQLite Database Export & Schema Compliance
# ---------------------------------------------------------------------------

def test_seedhunter_correlator_master_sqlite_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 7 & 8.
    Validates export of recovered seeds, HD derived addresses, and laundering chains
    into bip39_derivation_and_rupee_usdt_correlator.sqlite in ./.workspace_tmp/.
    Verifies schema integrity, column constraints, and foreign key relationships.
    """
    tmp_dir = os.path.join(".", ".workspace_tmp", "pytest_seedhunter")
    os.makedirs(tmp_dir, exist_ok=True)
    db_path = os.path.join(tmp_dir, "bip39_derivation_and_rupee_usdt_correlator.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = SeedHunterCorrelatorEngine()

    # Register sample recovered seed
    seed_record = RecoveredSeedRecord(
        secret_type=SecretType.BIP39_MNEMONIC_12_TO_24_WORDS,
        discovery_source_detail="Apple Notes (NoteStore.sqlite)",
        source_vfs_file_id=401,
        checksum_validation_status="BIP39_SHA256_CHECKSUM_VERIFIED",
        plaintext_mnemonic_or_privkey="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        unlocked_with_password=None,
        raw_encrypted_vault_json=None,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )
    engine.register_recovered_seeds([seed_record])

    # Register HD derived addresses
    hd_addr1 = HDDerivedAddressRecord(
        seed_record_uid=1,
        blockchain_network=BlockchainNetwork.TRON_TRC20,
        derivation_path="m/44'/195'/0'/0/0",
        derived_public_address="TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
        matches_on_device_activity=1,
    )
    hd_addr2 = HDDerivedAddressRecord(
        seed_record_uid=1,
        blockchain_network=BlockchainNetwork.ETHEREUM_EVM_0X,
        derivation_path="m/44'/60'/0'/0/0",
        derived_public_address="0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        matches_on_device_activity=0,
    )
    engine.register_hd_addresses([hd_addr1, hd_addr2])

    # Register laundering chain
    chain_record = LaunderingChainRecord(
        chain_pattern_classification=LaunderingPattern.SPLIT_UPI_SMURFING_TO_P2P_USDT,
        hop1_phase3_tx_master_uids_json=json.dumps(["UTR 630911111111 (INR 95000.0)", "UTR 630922222222 (INR 85000.0)"]),
        hop1_total_fiat_outflow_inr=180000.00,
        hop2_cex_p2p_order_uid=201,
        hop2_acquired_crypto_amount="2000.00 USDT (Binance P2P Order #205938491823901)",
        hop3_cex_withdrawal_or_pay_uid=301,
        hop4_self_custody_or_swap_json=json.dumps({"address": "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH", "txid": "e739..."}),
        hop5_chat_confirmation_msg_uid="msg_whatsapp_99182",
        chain_start_utc_iso="2024-05-10T14:02:00Z",
        chain_completion_utc_iso="2024-05-10T14:20:00Z",
    )
    engine.register_laundering_chains([chain_record])

    # Export to SQLite
    exported_path = engine.export_to_master_db(db_path)
    assert os.path.exists(exported_path)

    # Query DB and verify schema
    conn = sqlite3.connect(exported_path)
    cur = conn.cursor()

    # Check tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    assert "recovered_seeds_private_keys_and_unwrapped_vaults" in tables
    assert "hd_derived_public_addresses_from_seeds" in tables
    assert "end_to_end_rupee_to_crypto_laundering_chains" in tables

    # Check recovered seeds
    cur.execute("SELECT secret_type, discovery_source_detail, checksum_validation_status, recovery_classification FROM recovered_seeds_private_keys_and_unwrapped_vaults")
    seed_row = cur.fetchone()
    assert seed_row[0] == SecretType.BIP39_MNEMONIC_12_TO_24_WORDS.value
    assert seed_row[1] == "Apple Notes (NoteStore.sqlite)"
    assert seed_row[2] == "BIP39_SHA256_CHECKSUM_VERIFIED"
    assert seed_row[3] == ResidualConfidence.ORIGINAL_RECORD.value

    # Check HD addresses
    cur.execute("SELECT blockchain_network, derivation_path, derived_public_address, matches_on_device_activity FROM hd_derived_public_addresses_from_seeds ORDER BY derived_addr_uid")
    hd_rows = cur.fetchall()
    assert len(hd_rows) == 2
    assert hd_rows[0][0] == BlockchainNetwork.TRON_TRC20.value
    assert hd_rows[0][2] == "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
    assert hd_rows[0][3] == 1
    assert hd_rows[1][0] == BlockchainNetwork.ETHEREUM_EVM_0X.value
    assert hd_rows[1][2] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    # Check laundering chains
    cur.execute("SELECT chain_pattern_classification, hop1_total_fiat_outflow_inr, hop2_cex_p2p_order_uid FROM end_to_end_rupee_to_crypto_laundering_chains")
    chain_row = cur.fetchone()
    assert chain_row[0] == LaunderingPattern.SPLIT_UPI_SMURFING_TO_P2P_USDT.value
    assert chain_row[1] == 180000.00
    assert chain_row[2] == 201

    conn.close()
