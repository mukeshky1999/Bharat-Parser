"""
Tests for Phase 4, Module 4.2: Centralized Exchanges (CEX), Indian FIU-IND Exchanges,
P2P Escrow Orders, In-Order Chat Decoders & Off-Chain Binance Pay Transfers.
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

import json
import os
import sqlite3
import struct
import zlib
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.cex.models import (
    CEXComplianceTier,
    CEXP2PTradeDirection,
    CEXP2POrderStatus,
    CEXTransferCategory,
    CEXAccountProfileRecord,
    CEXP2PEscrowOrderRecord,
    CEXP2PChatMessageRecord,
    CEXTransferRecord,
)
from src.cex.binance import BinanceDecoder
from src.cex.indian_cex import IndianCEXDecoder
from src.cex.engine import CEXAndP2PExchangeEngine


def encode_mmkv_kv(key: str, value: bytes) -> bytes:
    """Helper to pack a key-value entry into raw MMKV varint-prefixed bytes."""
    def encode_varint(n: int) -> bytes:
        res = bytearray()
        while n > 0x7F:
            res.append((n & 0x7F) | 0x80)
            n >>= 7
        res.append(n & 0x7F)
        return bytes(res)

    key_bytes = key.encode("utf-8")
    k_len = encode_varint(len(key_bytes))
    v_len = encode_varint(len(value))
    return k_len + key_bytes + v_len + value


def test_binance_mmkv_layer2_account_switch_and_p2p_cache(tmp_path):
    """
    Test 1: Acceptance Test 1 from Spec Section 8.
    Binance MMKV Layer-2 Account-Switch & P2P WebView Cache Test.
    Extracts active UID (Layer 1) and superseded historical UID (Layer 2) from MMKV,
    and decompresses HTTP/WebView cache for P2P order with UPI VPA counterparty.
    """
    mmkv_dir = tmp_path / "files" / "mmkv"
    mmkv_dir.mkdir(parents=True)
    mmkv_file = mmkv_dir / "com.binance.dev.default"

    # Construct MMKV binary payload:
    # Older entry (Layer 2): userId = "991122334"
    # Newer entry (Layer 1): userId = "482910482"
    # Also user profile: kycName = "RAHUL SHARMA"
    val_old_uid = b"\x09991122334"  # length-prefixed string
    val_new_uid = b"\x09482910482"
    val_kyc = b"\x0cRAHUL SHARMA"

    entry1 = encode_mmkv_kv("userId", val_old_uid)
    entry2 = encode_mmkv_kv("kycName", val_kyc)
    entry3 = encode_mmkv_kv("userId", val_new_uid)  # Overwrites userId in MMKV append log

    payload = entry1 + entry2 + entry3
    header = struct.pack("<I", len(payload))

    with open(mmkv_file, "wb") as f:
        f.write(header + payload)

    # Construct P2P Cache file (compressed HTTP response)
    cache_dir = tmp_path / "app_webview" / "Default" / "Cache" / "Cache_Data"
    cache_dir.mkdir(parents=True)
    cache_file = cache_dir / "0123456789abcdef_0"

    p2p_order_payload = {
        "data": {
            "orderNumber": "20594829104829104128",
            "tradeType": "BUY",
            "orderStatus": 4,  # COMPLETED
            "asset": "USDT",
            "amount": "2000.00",
            "fiatUnit": "INR",
            "totalPrice": "180000.00",
            "unitPrice": "90.00",
            "sellerUserNo": "887766554",
            "sellerRealName": "SANDEEP KUMAR",
            "sellerNickname": "SandeepMerchantP2P",
            "createTime": 1730872800000,
            "payMethod": {
                "tradeMethodName": "UPI",
                "fields": {
                    "upiId": "seller99@okaxis"
                }
            }
        }
    }
    raw_json_bytes = json.dumps(p2p_order_payload).encode("utf-8")
    compressed_body = zlib.compress(raw_json_bytes)

    with open(cache_file, "wb") as f:
        f.write(compressed_body)

    decoder = BinanceDecoder()
    result = decoder.decode_sandbox(
        mmkv_path=str(mmkv_file),
        cache_path=str(cache_file),
        source_vfs_file_id=101,
    )

    accounts = result["accounts"]
    orders = result["p2p_orders"]

    # Verify 2 accounts discovered: 1 active (Layer 1) and 1 superseded (Layer 2)
    assert len(accounts) == 2
    active_acc = next(a for a in accounts if a.recovery_classification == ResidualConfidence.ORIGINAL_RECORD)
    assert active_acc.cex_user_uid == "482910482"
    assert active_acc.kyc_verified_full_name == "RAHUL SHARMA"
    assert active_acc.fiu_ind_compliance_tier == CEXComplianceTier.GLOBAL_FIU_REGISTERED_VASP

    hist_acc = next(a for a in accounts if a.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD)
    assert hist_acc.cex_user_uid == "991122334"

    # Verify P2P Order decoded from cache
    assert len(orders) == 1
    p2p = orders[0]
    assert p2p.p2p_order_number == "20594829104829104128"
    assert p2p.trade_direction == CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT
    assert p2p.order_status == CEXP2POrderStatus.COMPLETED_RELEASED
    assert p2p.crypto_asset == "USDT"
    assert p2p.crypto_quantity_decimal == 2000.00
    assert p2p.fiat_total_amount == 180000.00
    assert p2p.counterparty_vpa_or_bank_ifsc == "seller99@okaxis"
    assert p2p.counterparty_verified_kyc_name == "SANDEEP KUMAR"


def test_p2p_chat_phone_utr_and_third_party_triangulation():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.
    P2P In-Order Chat Phone/UTR Extractor & Third-Party Payer Triangulation Test.
    Extracts 10-digit mobile and 12-digit UTR from chat message text,
    and flags Triangulation Fraud when CEX owner KYC name != Phase 3 bank payer name.
    """
    chat_text = "Paid Rs 1,80,000 from my brother's account, UTR 630914829104, call me on 9811223344"
    order_no = "20594829104829104128"

    decoder = BinanceDecoder()
    chat_record = decoder.parse_chat_message(
        order_number=order_no,
        sender_uid="482910482",
        sender_nick="RahulTrader",
        message_text=chat_text,
        timestamp_ms=1730872900000,
        source_vfs_file_id=102,
    )

    assert chat_record.p2p_order_number == order_no
    assert "9811223344" in chat_record.extracted_phone_utr_or_vpa
    assert "630914829104" in chat_record.extracted_phone_utr_or_vpa

    # Simulate Triangulation Cross-Check:
    # CEX owner KYC name is "RAHUL SHARMA", but linked Phase 3 bank transfer was from "AMIT VERMA"
    order_record = CEXP2PEscrowOrderRecord(
        exchange_name="Binance P2P",
        source_vfs_file_id=102,
        p2p_order_number=order_no,
        trade_direction=CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT,
        order_status=CEXP2POrderStatus.COMPLETED_RELEASED,
        crypto_asset="USDT",
        crypto_quantity_decimal=2000.0,
        fiat_currency="INR",
        fiat_total_amount=180000.0,
        extracted_utr_or_giftcard_code="630914829104",
        order_created_utc_iso="2026-11-06T00:00:00.000Z",
    )

    is_mismatch = decoder.evaluate_third_party_triangulation(
        cex_owner_kyc_name="RAHUL SHARMA",
        phase3_payer_cbs_name="AMIT VERMA",
    )
    assert is_mismatch is True

    order_record.is_third_party_payer_mismatch = 1 if is_mismatch else 0
    assert order_record.is_third_party_payer_mismatch == 1


def test_binance_pay_offchain_and_onchain_selfcustody_link():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.
    Off-Chain Binance Pay vs. On-Chain TRC-20 Self-Custody Link Test.
    Differentiates off-chain Binance Pay transfers from on-chain withdrawals,
    and links on-chain withdrawal address to local Module 4.1 self-custody wallet UID.
    """
    decoder = BinanceDecoder()

    # 1. Off-chain Binance Pay transfer
    pay_raw = {
        "orderId": "291827364519283746",
        "receiverUid": "554433221",
        "amount": "500.00",
        "currency": "USDT",
        "transactionTime": 1730873000000,
        "note": "Payment for USDT offline deal"
    }
    pay_rec = decoder.parse_transfer_record(
        transfer_dict=pay_raw,
        is_offchain_pay=True,
        source_vfs_file_id=103,
    )
    assert pay_rec.transfer_category == CEXTransferCategory.OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER
    assert pay_rec.txid_or_internal_pay_order_id == "291827364519283746"
    assert pay_rec.destination_wallet_or_peer_uid == "554433221"
    assert pay_rec.amount_decimal == 500.00

    # 2. On-chain TRC-20 withdrawal with local web3 self-custody match
    onchain_raw = {
        "txId": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        "address": "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
        "amount": "1500.00",
        "asset": "USDT",
        "network": "TRX",
        "applyTime": 1730873100000
    }
    # Provide local known self-custody wallets dictionary from Module 4.1: {canonical_address: web3_account_uid}
    local_web3_wallets = {
        "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf": 42
    }
    onchain_rec = decoder.parse_transfer_record(
        transfer_dict=onchain_raw,
        is_offchain_pay=False,
        local_web3_lookup=local_web3_wallets,
        source_vfs_file_id=103,
    )
    assert onchain_rec.transfer_category == CEXTransferCategory.ONCHAIN_CRYPTO_WITHDRAWAL
    assert onchain_rec.network_or_rail == "TRC20"
    assert onchain_rec.matches_local_web3_wallet_uid == 42


def test_indian_fiu_coindcx_pan_and_1pct_tds(tmp_path):
    """
    Test 4: Acceptance Test & Indian Domestic FIU-IND Exchange Forensics.
    CoinDCX: Extracts 10-char PAN, verified bank account + IFSC,
    and Section 194S 1% TDS deduction records on VDA spot trades.
    """
    db_path = tmp_path / "coindcx_user.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE user_profile (
            id INTEGER PRIMARY KEY,
            user_id TEXT,
            full_name TEXT,
            pan TEXT,
            aadhaar_ref TEXT,
            bank_account TEXT,
            bank_ifsc TEXT
        )
    """)
    cursor.execute("""
        INSERT INTO user_profile VALUES (
            1, 'coindcx_uid_98765', 'VIKRAM SINGH', 'ABCDE1234F', 'XXXX-XXXX-9876',
            '98765432101234', 'HDFC0000123'
        )
    """)

    cursor.execute("""
        CREATE TABLE vda_trades (
            trade_id TEXT PRIMARY KEY,
            asset TEXT,
            trade_amount REAL,
            tds_amount REAL,
            trade_time INTEGER
        )
    """)
    cursor.execute("""
        INSERT INTO vda_trades VALUES (
            'TRADE_DCX_001', 'USDT', 100000.00, 1000.00, 1730873200000
        )
    """)
    conn.commit()
    conn.close()

    indian_decoder = IndianCEXDecoder()
    result = indian_decoder.decode_sandbox(str(db_path), source_vfs_file_id=201)

    accounts = result["accounts"]
    transfers = result["transfers"]

    assert len(accounts) == 1
    acc = accounts[0]
    assert acc.exchange_name == "CoinDCX"
    assert acc.fiu_ind_compliance_tier == CEXComplianceTier.INDIAN_DOMESTIC_FIU_REGISTERED
    assert acc.indian_pan_10_char == "ABCDE1234F"
    assert acc.kyc_verified_full_name == "VIKRAM SINGH"

    linked_banks = json.loads(acc.linked_indian_banks_vpas_json)
    assert linked_banks[0]["bank_account"] == "98765432101234"
    assert linked_banks[0]["bank_ifsc"] == "HDFC0000123"

    assert len(transfers) == 1
    tr = transfers[0]
    assert tr.transfer_category == CEXTransferCategory.VDA_SPOT_TRADE_WITH_1PCT_TDS
    assert tr.amount_decimal == 100000.00
    assert tr.tds_1pct_deducted_inr == 1000.00


def test_cex_and_p2p_engine_master_sqlite_export(tmp_path):
    """
    Test 5: Relational Master SQLite Export Test.
    Exports accounts, P2P orders, chat messages, and transfers into
    cex_and_p2p_exchange_engine.sqlite and validates schema and constraints.
    """
    engine = CEXAndP2PExchangeEngine()

    acc = CEXAccountProfileRecord(
        exchange_name="Binance",
        fiu_ind_compliance_tier=CEXComplianceTier.GLOBAL_FIU_REGISTERED_VASP,
        source_vfs_file_id=301,
        cex_user_uid="482910482",
        kyc_verified_full_name="RAHUL SHARMA",
        registered_email="rahul.sharma@example.com",
    )
    p2p_order = CEXP2PEscrowOrderRecord(
        exchange_name="Binance P2P",
        source_vfs_file_id=301,
        p2p_order_number="20594829104829104128",
        trade_direction=CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT,
        order_status=CEXP2POrderStatus.COMPLETED_RELEASED,
        crypto_asset="USDT",
        crypto_quantity_decimal=2000.0,
        fiat_currency="INR",
        fiat_total_amount=180000.0,
        counterparty_vpa_or_bank_ifsc="seller99@okaxis",
        order_created_utc_iso="2026-11-06T00:00:00.000Z",
    )
    chat_msg = CEXP2PChatMessageRecord(
        p2p_order_number="20594829104829104128",
        exchange_name="Binance P2P",
        sender_uid_and_nickname="482910482 (RahulTrader)",
        message_type="TEXT",
        message_text_or_image_url="Payment done UTR 630914829104",
        extracted_phone_utr_or_vpa="630914829104",
        sent_utc_iso="2026-11-06T00:01:00.000Z",
    )
    transfer = CEXTransferRecord(
        exchange_name="Binance",
        source_vfs_file_id=301,
        transfer_category=CEXTransferCategory.OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER,
        asset_or_currency="USDT",
        amount_decimal=500.0,
        txid_or_internal_pay_order_id="291827364519283746",
        destination_wallet_or_peer_uid="554433221",
        transfer_utc_iso="2026-11-06T00:02:00.000Z",
    )

    engine.register_accounts([acc])
    engine.register_p2p_orders([p2p_order])
    engine.register_chat_messages([chat_msg])
    engine.register_transfers([transfer])

    export_path = tmp_path / "cex_and_p2p_exchange_engine.sqlite"
    exported_db = engine.export_to_master_db(str(export_path))
    assert os.path.exists(exported_db)

    conn = sqlite3.connect(exported_db)
    cursor = conn.cursor()

    cursor.execute("SELECT count(*) FROM cex_exchange_accounts_and_kyc_profiles")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT count(*) FROM cex_p2p_escrow_orders_ledger")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT count(*) FROM cex_p2p_in_order_chat_messages")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT count(*) FROM cex_withdrawals_deposits_and_internal_pay")
    assert cursor.fetchone()[0] == 1

    conn.close()
