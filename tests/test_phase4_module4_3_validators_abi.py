"""
Tests for Phase 4, Module 4.3: Mathematical Blockchain Address Validators,
Smart Contract ABI Unpackers & WalletConnect v2 Phishing Drainer Decoders.
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

import json
import os
import sqlite3
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.validators.models import (
    BlockchainEcosystem,
    ValidatedCryptoAddressRecord,
    UnpackedSmartContractABIRecord,
    WalletConnectAuditRecord,
    WalletConnectRecordType,
)
from src.validators.address_validators import (
    validate_crypto_address,
    verify_eip55_checksum,
    verify_bitcoin_bech32,
    verify_monero_address,
    verify_ton_address,
)
from src.validators.abi_unpacker import SmartContractABIUnpacker
from src.validators.walletconnect import WalletConnectDecoder
from src.validators.engine import ValidatorsAndABIEngine


def test_keccak256_eip55_checksum_validator():
    """
    Test 1: Acceptance Test 1 from Spec Section 7.
    Validates Original Keccak-256 (0x01 padding) against NIST SHA3-256 (0x06 padding)
    using the official EIP-55 mixed-case test vector and single-case-flipped rejection.
    """
    valid_eip55 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    invalid_case = "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed"  # single 'a' flipped to lowercase
    all_lower = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"

    # Test standalone helper
    assert verify_eip55_checksum(valid_eip55) is True
    assert verify_eip55_checksum(invalid_case) is False

    # Test full address validator
    res_valid = validate_crypto_address(valid_eip55)
    assert res_valid is not None
    assert res_valid.blockchain_ecosystem == BlockchainEcosystem.ETHEREUM_EVM_0X
    assert res_valid.canonical_address == valid_eip55
    assert res_valid.checksum_verification_method == "EIP55_KECCAK256_OK"

    # Single-case flipped mixed string MUST be rejected
    res_invalid = validate_crypto_address(invalid_case)
    assert res_invalid is None

    # All-lowercase address should be converted to canonical EIP-55
    res_lower = validate_crypto_address(all_lower, allow_unchecksummed_evm=True)
    assert res_lower is not None
    assert res_lower.canonical_address == valid_eip55


def test_bitcoin_bech32_and_bech32m_dual_constants():
    """
    Test 2: Acceptance Test 2 from Spec Section 7.
    Validates Bitcoin SegWit v0 (bc1q, polymod == 1) vs Taproot v1 (bc1p, polymod == 0x2bc830a3).
    """
    segwit_v0 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    taproot_v1 = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    mixed_case_invalid = "bc1qar0srrr7XFKVY5l643lydnw9re59gtzzwf5mdq"

    # SegWit v0
    res_v0 = validate_crypto_address(segwit_v0)
    assert res_v0 is not None
    assert res_v0.blockchain_ecosystem == BlockchainEcosystem.BITCOIN_SEGWIT_BECH32
    assert res_v0.checksum_verification_method == "BECH32_POLYMOD_1_OK"

    # Taproot v1
    res_v1 = validate_crypto_address(taproot_v1)
    assert res_v1 is not None
    assert res_v1.blockchain_ecosystem == BlockchainEcosystem.BITCOIN_TAPROOT_BECH32M
    assert res_v1.checksum_verification_method == "BECH32M_POLYMOD_0x2bc830a3_OK"

    # Mixed-case Bech32 MUST be rejected per BIP-173
    assert verify_bitcoin_bech32(mixed_case_invalid) is False
    assert validate_crypto_address(mixed_case_invalid) is None


def test_monero_blockwise_base58_and_ton_crc16():
    """
    Test 3: Acceptance Test 3 from Spec Section 7.
    Validates Monero 95-character block-wise Base58 + Keccak-256 checksum (Byte 0 == 0x12)
    and TON 48-character user-friendly address (CRC16-CCITT).
    """
    xmr_addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    ton_addr = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"

    # Monero
    assert verify_monero_address(xmr_addr) is True
    res_xmr = validate_crypto_address(xmr_addr)
    assert res_xmr is not None
    assert res_xmr.blockchain_ecosystem == BlockchainEcosystem.MONERO_XMR_CRYPTONOTE
    assert res_xmr.checksum_verification_method == "MONERO_BLOCK_BASE58_KECCAK256_OK"

    # TON
    assert verify_ton_address(ton_addr) is True
    res_ton = validate_crypto_address(ton_addr)
    assert res_ton is not None
    assert res_ton.blockchain_ecosystem == BlockchainEcosystem.TON_CRC16
    assert res_ton.checksum_verification_method == "TON_CRC16_CCITT_OK"


def test_tron_abi_unpack_and_permit2_drainer_detection():
    """
    Test 4: Acceptance Test 4 from Spec Section 7.
    Unpacks TRON TriggerSmartContract call data (a9059cbb transfer) to TR7NH... USDT contract,
    converting 20-byte word to 34-char 'T' address with 10,000.000000 USDT amount,
    and detects phishing Permit2 drainer signature from WalletConnect v2 RPC history.
    """
    # 1. TRON TriggerSmartContract call data unpacking
    outer_usdt = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    tron_call_data = (
        "a9059cbb"
        "000000000000000000000000eb8f23b921b9d83b5d69c219c0a84674a694820b"
        "00000000000000000000000000000000000000000000000000000002540be400"
    )

    unpacker = SmartContractABIUnpacker()
    abi_res = unpacker.unpack_call_data(
        outer_contract=outer_usdt,
        data_hex=tron_call_data,
        network="TRON_TRC20",
    )

    assert abi_res is not None
    assert abi_res.selector_4byte_hex == "0xa9059cbb"
    assert "transfer" in abi_res.decoded_function_name
    assert abi_res.resolved_token_or_protocol == "USDT (TRC-20)"
    # Word 0 decoded to 34-character 'T' TRON address
    assert abi_res.unpacked_true_recipient_or_spender.startswith("T")
    assert len(abi_res.unpacked_true_recipient_or_spender) == 34
    assert abi_res.unpacked_human_token_amount == "10000.000000 USDT"

    # 2. WalletConnect v2 Permit2 Phishing Drainer Detection
    wc_rpc_history_entry = {
        "id": 1698765432100,
        "topic": "7f8c12a4567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        "method": "eth_signTypedData_v4",
        "params": [
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            json.dumps({
                "types": {
                    "PermitSingle": [
                        {"name": "details", "type": "PermitDetails"},
                        {"name": "spender", "type": "address"},
                        {"name": "sigDeadline", "type": "uint256"}
                    ]
                },
                "primaryType": "PermitSingle",
                "domain": {
                    "name": "Permit2",
                    "chainId": 1,
                    "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
                },
                "message": {
                    "spender": "0xAttackerPhishingDrainerContract000000000",
                    "sigDeadline": 1799999999
                }
            })
        ],
        "response": {
            "result": "0x" + "aa" * 65  # 65-byte signed ECDSA signature
        }
    }

    wc_decoder = WalletConnectDecoder()
    wc_rec = wc_decoder.parse_rpc_record(
        rpc_entry=wc_rpc_history_entry,
        dapp_name="Suspicious Claim Airdrop",
        dapp_url="https://airdrop-usdt-claim.top",
        source_vfs_file_id=104,
    )

    assert wc_rec.is_phishing_permit_drainer_sig == 1
    assert wc_rec.wc_record_type == WalletConnectRecordType.WC_V2_EIP712_PERMIT_SIGNATURE
    assert "0xAttackerPhishingDrainerContract" in wc_rec.rpc_method_and_params_json


def test_validators_abi_master_sqlite_export(tmp_path):
    """
    Test 5: Master Relational SQLite Export Test.
    Exports validated address index, unpacked ABI calls, and WalletConnect audit
    to address_validators_abi_and_walletconnect.sqlite adhering to Section 6 schema.
    """
    engine = ValidatorsAndABIEngine()

    addr_rec = ValidatedCryptoAddressRecord(
        blockchain_ecosystem=BlockchainEcosystem.TRON_TRC20,
        canonical_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        checksum_verification_method="BASE58CHECK_DOUBLE_SHA256_OK",
        discovered_in_module_and_app="WhatsApp msgstore.db (Chat with +919876543210)",
        source_vfs_file_id=501,
        associated_actor_or_context="Payment receiver in chat",
    )
    abi_rec = UnpackedSmartContractABIRecord(
        blockchain_network="TRON_TRC20",
        outer_contract_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        resolved_token_or_protocol="USDT (TRC-20)",
        selector_4byte_hex="0xa9059cbb",
        decoded_function_name="transfer(address,uint256)",
        unpacked_true_recipient_or_spender="TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
        unpacked_raw_uint256_amount="10000000000",
        unpacked_human_token_amount="10000.000000 USDT",
        is_unlimited_approval_or_drainer=0,
    )
    wc_rec = WalletConnectAuditRecord(
        app_instance_id=1,
        source_vfs_file_id=501,
        wc_record_type=WalletConnectRecordType.WC_V2_PAIRING_OR_SESSION,
        session_topic_hex="7f8c12a4567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        dapp_peer_name="Uniswap Interface",
        dapp_peer_url="https://app.uniswap.org",
        exposed_caip10_accounts_json=json.dumps(["eip155:1:0x71C7656EC7ab88b098defB751B7401B5f6d8976F"]),
    )

    engine.register_validated_addresses([addr_rec])
    engine.register_unpacked_abi_calls([abi_rec])
    engine.register_walletconnect_records([wc_rec])

    export_path = tmp_path / "address_validators_abi_and_walletconnect.sqlite"
    exported_db = engine.export_to_master_db(str(export_path))
    assert os.path.exists(exported_db)

    conn = sqlite3.connect(exported_db)
    cursor = conn.cursor()

    cursor.execute("SELECT count(*) FROM validated_crypto_addresses_global_index")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT count(*) FROM unpacked_smart_contract_abi_calls")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT count(*) FROM walletconnect_v2_sessions_and_rpc_audit")
    assert cursor.fetchone()[0] == 1

    conn.close()
