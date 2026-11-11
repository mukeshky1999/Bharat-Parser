"""
Tests for Phase 4, Module 4.1: Self-Custody Web3, DeFi, Privacy Coin & Hardware Companion Wallets.
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
Covers: TronLink Pro, MetaMask Mobile, Trust Wallet, Cake Wallet (Monero), Ledger Live.
"""

import json
import os
import sqlite3
import struct
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.web3.models import (
    Web3AccountControlMode,
    BlockchainNetwork,
    Web3TxOperationType,
    Web3WalletAccountRecord,
    Web3TransactionRecord,
    Web3CrossChainSwapRecord,
)
from src.web3.tronlink import TronLinkDecoder
from src.web3.metamask import MetaMaskDecoder
from src.web3.trustwallet import TrustWalletDecoder
from src.web3.cakewallet import CakeWalletDecoder
from src.web3.ledgerlive import LedgerLiveDecoder
from src.web3.engine import Web3SelfCustodyWalletsEngine


def test_tronlink_hex41_to_base58check_and_watch_only(tmp_path):
    """
    Test 1: Acceptance Test 1 from Spec Section 8.
    TronLink Pro: Converts 21-byte 41... hex string to 34-character 'T' Base58Check,
    correctly classifies Watch-Only Observed Wallets (create_type=3 / isWatchOnly=1),
    and extracts Energy Delegations and TRC-20 USDT transfers.
    """
    db_path = tmp_path / "tron_main_wallet.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create TronLink wallet configuration table
    cursor.execute("""
        CREATE TABLE wallet_info (
            id INTEGER PRIMARY KEY,
            name TEXT,
            address TEXT,
            isWatchOnly INTEGER,
            create_type INTEGER
        )
    """)
    # 41a614f803b6fd780986a42c78ec9c7f77e6ded13c is TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t (USDT Contract / Boss Wallet)
    cursor.execute("""
        INSERT INTO wallet_info (id, name, address, isWatchOnly, create_type)
        VALUES (1, 'Boss Cold Wallet', '41a614f803b6fd780986a42c78ec9c7f77e6ded13c', 1, 3)
    """)

    # Create transaction table
    cursor.execute("""
        CREATE TABLE trans_record (
            tx_id TEXT PRIMARY KEY,
            owner_address TEXT,
            to_address TEXT,
            contract_address TEXT,
            contract_type INTEGER,
            amount INTEGER,
            block_timestamp INTEGER
        )
    """)
    # Tx 1: TRC-20 USDT transfer (contract_type = 31, TriggerSmartContract)
    cursor.execute("""
        INSERT INTO trans_record (tx_id, owner_address, to_address, contract_address, contract_type, amount, block_timestamp)
        VALUES (
            'a9f24c7f8976b7e1273919e917d23d8c117d9198642a8b9e1123476fef1a2b3c',
            '41a614f803b6fd780986a42c78ec9c7f77e6ded13c',
            '413c19b08f4c21e51b1473f32488d5e894458fef56',
            '41a614f803b6fd780986a42c78ec9c7f77e6ded13c',
            31,
            50000000000,
            1730872800000
        )
    """)
    # Tx 2: Energy Delegation (contract_type = 57, DelegateResourceContract)
    cursor.execute("""
        INSERT INTO trans_record (tx_id, owner_address, to_address, contract_address, contract_type, amount, block_timestamp)
        VALUES (
            'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2',
            '415555555555555555555555555555555555555555',
            '41a614f803b6fd780986a42c78ec9c7f77e6ded13c',
            NULL,
            57,
            32000000,
            1730872700000
        )
    """)
    conn.commit()
    conn.close()

    decoder = TronLinkDecoder()
    result = decoder.decode_sandbox(str(db_path), source_vfs_file_id=101)

    accounts = result["accounts"]
    transactions = result["transactions"]

    assert len(accounts) == 1
    acc = accounts[0]
    assert acc.wallet_app_name == "TronLink Pro"
    assert acc.public_address_canonical == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert acc.tron_hex41_representation == "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    assert acc.account_control_mode == Web3AccountControlMode.WATCH_ONLY_OBSERVED_WALLET
    assert acc.blockchain_network == BlockchainNetwork.TRON_TRC20
    assert acc.user_assigned_wallet_label == "Boss Cold Wallet"
    assert acc.recovery_classification == ResidualConfidence.ORIGINAL_RECORD
    assert acc.evidentiary_state.forensic_group == ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS

    assert len(transactions) == 2
    usdt_tx = next(t for t in transactions if t.tx_operation_type == Web3TxOperationType.SMART_CONTRACT_TOKEN_TRANSFER)
    assert usdt_tx.token_symbol == "USDT"
    assert usdt_tx.token_decimals == 6
    assert usdt_tx.raw_bigint_amount_str == "50000000000"
    assert usdt_tx.human_amount_decimal_str == "50000.000000"
    assert usdt_tx.from_address == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert usdt_tx.to_recipient_address.startswith("T")

    energy_tx = next(t for t in transactions if t.tx_operation_type == Web3TxOperationType.TRON_ENERGY_DELEGATION)
    assert energy_tx.raw_bigint_amount_str == "32000000"
    assert energy_tx.to_recipient_address == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def test_metamask_persist_root_double_json_and_uint256_precision(tmp_path):
    """
    Test 2: Acceptance Test 2 from Spec Section 8.
    MetaMask Mobile: Double-JSON deserialization on persist:root in RKStorage,
    avoids 64-bit int overflow on uint256 Wei amounts (100.0 ETH > 2^63-1),
    and correctly extracts transaction history, custom tokens, and connected DApps.
    """
    rk_db = tmp_path / "RKStorage"
    conn = sqlite3.connect(str(rk_db))
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE catalystLocalStorage (key TEXT PRIMARY KEY, value TEXT)")

    # Construct double-stringified redux-persist JSON payload
    inner_engine = {
        "backgroundState": {
            "KeyringController": {
                "vault": json.dumps({
                    "data": "bWV0YW1hc2tfdmF1bHRfY3B0X2RhdGE=",
                    "iv": "aXZfc2FsdF8xMjM0NTY=",
                    "salt": "c2FsdF9rZXlyaW5nXzEyMw=="
                })
            },
            "AccountTrackerController": {
                "accounts": {
                    "0x71c7656ec7ab88b098defb751b7401b5f6d8976f": {
                        # 0x152d02c7e14af6800000 Wei = 100,000,000,000,000,000,000 Wei = 100.0 ETH (> 2^63-1)
                        "balance": "0x152d02c7e14af6800000"
                    }
                }
            },
            "PreferencesController": {
                "identities": {
                    "0x71c7656ec7ab88b098defb751b7401b5f6d8976f": {
                        "address": "0x71c7656ec7ab88b098defb751b7401b5f6d8976f",
                        "name": "Syndicate Primary EOA"
                    }
                }
            },
            "TransactionController": {
                "transactions": [
                    {
                        "id": "tx_mm_001",
                        "hash": "0x5b38da6a701c568545dcfcb03fcb875f56beddc4ecf6e804f323a3cb9352e001",
                        "chainId": "0x1",
                        "time": 1730872800000,
                        "status": "confirmed",
                        "txParams": {
                            "from": "0x71c7656ec7ab88b098defb751b7401b5f6d8976f",
                            "to": "0x388c818ca8b9251b393131c08a736a67ccb19297",
                            "value": "0x152d02c7e14af6800000",
                            "data": "0x"
                        }
                    }
                ]
            }
        }
    }
    inner_browser = {
        "history": [
            {"url": "https://app.uniswap.org/#/swap", "name": "Uniswap"}
        ]
    }

    persist_root = {
        "engine": json.dumps(inner_engine),
        "browser": json.dumps(inner_browser),
    }

    cursor.execute(
        "INSERT INTO catalystLocalStorage (key, value) VALUES ('persist:root', ?)",
        (json.dumps(persist_root),)
    )
    conn.commit()
    conn.close()

    decoder = MetaMaskDecoder()
    result = decoder.decode_sandbox(str(rk_db), source_vfs_file_id=202)

    accounts = result["accounts"]
    transactions = result["transactions"]
    dapp_sessions = result["dapp_sessions"]

    assert len(accounts) == 1
    acc = accounts[0]
    assert acc.wallet_app_name == "MetaMask"
    assert acc.blockchain_network == BlockchainNetwork.ETHEREUM_ERC20
    assert acc.public_address_canonical == "0x71c7656ec7ab88b098defb751b7401b5f6d8976f"
    assert acc.user_assigned_wallet_label == "Syndicate Primary EOA"
    assert acc.account_control_mode == Web3AccountControlMode.FULL_PRIVATE_KEY_OR_SEED
    cached_balances = json.loads(acc.cached_token_balances_json)
    assert cached_balances.get("ETH") == "100.000000000000000000"

    assert len(transactions) == 1
    tx = transactions[0]
    assert tx.tx_hash_hex == "0x5b38da6a701c568545dcfcb03fcb875f56beddc4ecf6e804f323a3cb9352e001"
    assert tx.token_symbol == "ETH"
    assert tx.token_decimals == 18
    assert tx.raw_bigint_amount_str == "100000000000000000000"
    assert tx.human_amount_decimal_str == "100.000000000000000000"
    assert tx.tx_status == "CONFIRMED"
    assert tx.tx_timestamp.utc_iso8601.startswith("2024-") or tx.tx_timestamp.utc_iso8601.startswith("2026-")

    assert len(dapp_sessions) == 1
    assert "uniswap.org" in dapp_sessions[0]["url"]


def test_cake_wallet_trades_hive_usdt_to_xmr_bridge(tmp_path):
    """
    Test 3: Acceptance Test 3 from Spec Section 8.
    Cake Wallet (Monero / XMR): Decodes Flutter Hive binary boxes (trades.hive),
    extracting cross-chain swap orders (USDT-TRC20 -> Monero XMR) routed via FixedFloat,
    revealing the true destination Monero stealth payout address.
    """
    hive_box_path = tmp_path / "trades.hive"

    # Construct binary Hive frame:
    # Frame layout: [frame_len: uint32 BE][key: string with len][payload: JSON or serialized binary]
    trade_data = {
        "trade_id": "FF998877",
        "provider": "FixedFloat",
        "from_currency": "USDTTRC20",
        "to_currency": "XMR",
        "input_amount": "50000.00",
        "input_txid": "78a9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
        "payout_address": "44Affq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
        "output_amount": "312.50",
        "output_txid": "xmr_dummy_ringct_hash_00112233445566778899aabbccddeeff",
        "created_at": 1730872800
    }
    payload_bytes = json.dumps(trade_data).encode("utf-8")
    key_bytes = b"trade_FF998877"
    frame_len = len(key_bytes) + len(payload_bytes) + 2

    # Binary packing: length (4 bytes) + key_len (1 byte) + key + val_len (2 bytes) + val
    binary_content = bytearray()
    binary_content.extend(struct.pack(">I", frame_len))
    binary_content.extend(struct.pack(">B", len(key_bytes)))
    binary_content.extend(key_bytes)
    binary_content.extend(struct.pack(">H", len(payload_bytes)))
    binary_content.extend(payload_bytes)

    with open(hive_box_path, "wb") as f:
        f.write(binary_content)

    decoder = CakeWalletDecoder()
    result = decoder.decode_sandbox(str(hive_box_path), source_vfs_file_id=303)

    swaps = result["swaps"]
    assert len(swaps) == 1
    swap = swaps[0]
    assert swap.swap_aggregator_provider == "FixedFloat"
    assert swap.provider_order_or_trade_id == "FF998877"
    assert "USDT" in swap.input_chain_and_asset
    assert "XMR" in swap.output_chain_and_asset
    assert swap.input_amount_decimal == "50000.00"
    assert swap.destination_payout_address == "44Affq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    assert swap.recovery_classification == ResidualConfidence.ORIGINAL_RECORD
    assert swap.evidentiary_state.forensic_group == ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS


def test_ledger_live_hardware_cold_wallet_app_json(tmp_path):
    """
    Test 4: Acceptance Test 4 from Spec Section 8.
    Ledger Live: Unmasks paired physical hardware cold wallet from app.json,
    extracting device BLE pairing info (Nano X MAC), Extended Public Key (xpub),
    BIP-84 derivation path, current balance, and historical operations list.
    """
    app_json_path = tmp_path / "app.json"
    app_json_data = {
        "data": {
            "accounts": [
                {
                    "id": "js:2:bitcoin:xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz:native_segwit",
                    "xpub": "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz",
                    "name": "Ledger Nano X - Bitcoin Cold Storage",
                    "freshAddress": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                    "freshAddressPath": "84'/0'/0'/0/14",
                    "balance": "250000000",
                    "currencyId": "bitcoin",
                    "operations": [
                        {
                            "id": "op_ledger_001",
                            "hash": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
                            "type": "IN",
                            "value": "250000000",
                            "fee": "5000",
                            "senders": ["bc1qsendersyndicateboss0000000000000000000"],
                            "recipients": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"],
                            "blockHeight": 850000,
                            "date": "2026-11-06T00:00:00.000Z"
                        }
                    ]
                }
            ],
            "ble": {
                "knownDevices": [
                    {
                        "id": "00:1A:7D:DA:71:13",
                        "name": "Ledger Nano X 7113",
                        "modelId": "nanoX"
                    }
                ]
            }
        }
    }

    with open(app_json_path, "w", encoding="utf-8") as f:
        json.dump(app_json_data, f)

    decoder = LedgerLiveDecoder()
    result = decoder.decode_sandbox(str(app_json_path), source_vfs_file_id=404)

    accounts = result["accounts"]
    transactions = result["transactions"]

    assert len(accounts) == 1
    acc = accounts[0]
    assert acc.wallet_app_name == "Ledger Live"
    assert acc.blockchain_network == BlockchainNetwork.BITCOIN
    assert acc.account_control_mode == Web3AccountControlMode.PAIRED_HARDWARE_COLD_WALLET
    assert acc.extended_public_key_xpub == "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz"
    assert acc.public_address_canonical == "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    assert acc.bip44_derivation_path == "84'/0'/0'/0/14"
    assert "nanoX" in acc.paired_hardware_device_info
    assert "00:1A:7D:DA:71:13" in acc.paired_hardware_device_info

    cached_bal = json.loads(acc.cached_token_balances_json)
    assert cached_bal.get("BTC") == "2.50000000"

    assert len(transactions) == 1
    tx = transactions[0]
    assert tx.tx_hash_hex == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert tx.token_symbol == "BTC"
    assert tx.token_decimals == 8
    assert tx.raw_bigint_amount_str == "250000000"
    assert tx.human_amount_decimal_str == "2.50000000"
    assert tx.from_address == "bc1qsendersyndicateboss0000000000000000000"
    assert tx.to_recipient_address == "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


def test_trust_wallet_keystore_multi_coin_and_master_db_export(tmp_path):
    """
    Test 5: Acceptance Test & SQLite Master Database Export.
    Trust Wallet: Decodes multi-coin activeAccounts JSON (SLIP-0044: TRON 195, ETH 60, BTC 0),
    and exports all accounts, transactions, and swap records to web3_self_custody_wallets_engine.sqlite
    strictly honoring Section 7 table schemas and forensic invariants.
    """
    keystore_dir = tmp_path / "files" / "keystore"
    keystore_dir.mkdir(parents=True)
    keystore_file = keystore_dir / "7f8c12a4-5678-4321-abcd-0123456789ab.json"

    keystore_data = {
        "id": "7f8c12a4-5678-4321-abcd-0123456789ab",
        "name": "Syndicate Primary Multi-Chain",
        "type": "mnemonic",
        "version": 3,
        "activeAccounts": [
            {
                "coin": 195,
                "address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                "derivationPath": "m/44'/195'/0'/0/0",
                "extendedPublicKey": "xpub6D4B5wtNkpc...tron"
            },
            {
                "coin": 60,
                "address": "0x71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "derivationPath": "m/44'/60'/0'/0/0",
                "extendedPublicKey": "xpub6D4B5wtNkpc...eth"
            },
            {
                "coin": 0,
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "derivationPath": "m/84'/0'/0'/0/0",
                "extendedPublicKey": "zpub6rFR7y4Q2AijBEqTUquhZ1nWJ4mURNFrZXxW...btc"
            }
        ],
        "crypto": {
            "cipher": "aes-128-ctr",
            "ciphertext": "a1b2c3d4e5f67890",
            "kdf": "scrypt"
        }
    }

    with open(keystore_file, "w", encoding="utf-8") as f:
        json.dump(keystore_data, f)

    tw_decoder = TrustWalletDecoder()
    tw_result = tw_decoder.decode_sandbox(str(keystore_file), source_vfs_file_id=505)
    tw_accounts = tw_result["accounts"]
    assert len(tw_accounts) == 3

    tron_acc = next(a for a in tw_accounts if a.blockchain_network == BlockchainNetwork.TRON_TRC20)
    assert tron_acc.public_address_canonical == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert tron_acc.tron_hex41_representation == "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"

    eth_acc = next(a for a in tw_accounts if a.blockchain_network == BlockchainNetwork.ETHEREUM_ERC20)
    assert eth_acc.public_address_canonical == "0x71c7656ec7ab88b098defb751b7401b5f6d8976f"

    btc_acc = next(a for a in tw_accounts if a.blockchain_network == BlockchainNetwork.BITCOIN)
    assert btc_acc.public_address_canonical == "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

    # Export via Master Engine
    export_db_path = tmp_path / "web3_self_custody_wallets_engine.sqlite"
    engine = Web3SelfCustodyWalletsEngine()
    engine.register_accounts(tw_accounts)

    exported_path = engine.export_to_master_db(str(export_db_path))
    assert os.path.exists(exported_path)

    # Verify tables and schema in export database
    conn = sqlite3.connect(str(export_db_path))
    c = conn.cursor()

    c.execute("SELECT count(*) FROM web3_wallet_instances_and_accounts")
    row_count = c.fetchone()[0]
    assert row_count == 3

    c.execute("SELECT blockchain_network, public_address_canonical FROM web3_wallet_instances_and_accounts ORDER BY web3_account_uid")
    rows = c.fetchall()
    assert rows[0][0] == "TRON_TRC20"
    assert rows[0][1] == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

    conn.close()
