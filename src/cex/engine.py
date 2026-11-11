"""
Master Sub-Engine 4.2: Centralized Exchange & P2P Escrow Forensics Engine.
Coordinates Binance, Bybit, KuCoin, CoinDCX, Mudrex, and P2P decoders,
performs cross-module self-custody wallet matching, and exports relational data
to cex_and_p2p_exchange_engine.sqlite adhering to Section 7 schema.
"""

from datetime import datetime, timezone
import os
import sqlite3
from typing import Any, Dict, List, Optional

from src.cex.models import (
    CEXAccountProfileRecord,
    CEXP2PChatMessageRecord,
    CEXP2PEscrowOrderRecord,
    CEXTransferRecord,
)
from src.cex.binance import BinanceDecoder
from src.cex.indian_cex import IndianCEXDecoder


class CEXAndP2PExchangeEngine:
    """Master engine managing CEX accounts, P2P orders, chats, and transfers."""

    def __init__(self) -> None:
        self.accounts: List[CEXAccountProfileRecord] = []
        self.p2p_orders: List[CEXP2PEscrowOrderRecord] = []
        self.chat_messages: List[CEXP2PChatMessageRecord] = []
        self.transfers: List[CEXTransferRecord] = []

        self.binance_decoder = BinanceDecoder()
        self.indian_decoder = IndianCEXDecoder()

    def register_accounts(self, accounts: List[CEXAccountProfileRecord]) -> None:
        """Appends discovered CEX account profiles to master registry."""
        self.accounts.extend(accounts)

    def register_p2p_orders(self, orders: List[CEXP2PEscrowOrderRecord]) -> None:
        """Appends discovered P2P escrow orders to master registry."""
        self.p2p_orders.extend(orders)

    def register_chat_messages(self, messages: List[CEXP2PChatMessageRecord]) -> None:
        """Appends discovered P2P chat messages to master registry."""
        self.chat_messages.extend(messages)

    def register_transfers(self, transfers: List[CEXTransferRecord]) -> None:
        """Appends discovered on-chain/off-chain transfers to master registry."""
        self.transfers.extend(transfers)

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates cex_and_p2p_exchange_engine.sqlite schema and inserts
        all registered accounts, P2P orders, chat messages, and transfers.
        """
        os.makedirs(os.path.dirname(os.path.abspath(export_db_path)), exist_ok=True)

        conn = sqlite3.connect(export_db_path)
        cursor = conn.cursor()

        # Table 1: cex_exchange_accounts_and_kyc_profiles
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cex_exchange_accounts_and_kyc_profiles (
                cex_account_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                exchange_name TEXT NOT NULL,
                fiu_ind_compliance_tier TEXT NOT NULL,
                app_instance_id INTEGER,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                cex_user_uid TEXT NOT NULL,
                binance_pay_id_or_nick TEXT,
                kyc_verified_full_name TEXT,
                indian_pan_10_char TEXT,
                aadhaar_or_passport_id TEXT,
                registered_email TEXT,
                registered_mobile_phone TEXT,
                linked_indian_banks_vpas_json TEXT,
                cached_spot_funding_balances TEXT,
                last_active_utc_iso TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cex_user_uid ON cex_exchange_accounts_and_kyc_profiles(cex_user_uid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cex_pan ON cex_exchange_accounts_and_kyc_profiles(indian_pan_10_char)")

        # Table 2: cex_p2p_escrow_orders_ledger
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cex_p2p_escrow_orders_ledger (
                p2p_order_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                cex_account_uid INTEGER,
                exchange_name TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                p2p_order_number TEXT NOT NULL,
                trade_direction TEXT NOT NULL,
                order_status TEXT NOT NULL,
                crypto_asset TEXT NOT NULL,
                crypto_quantity_decimal REAL NOT NULL,
                fiat_currency TEXT NOT NULL,
                fiat_total_amount REAL NOT NULL,
                unit_exchange_rate REAL,
                counterparty_cex_uid_nick TEXT,
                counterparty_verified_kyc_name TEXT,
                fiat_payment_rail TEXT,
                counterparty_vpa_or_bank_ifsc TEXT,
                extracted_utr_or_giftcard_code TEXT,
                is_third_party_payer_mismatch INTEGER DEFAULT 0,
                order_created_utc_iso TEXT NOT NULL,
                order_completed_utc_iso TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_p2p_order_no ON cex_p2p_escrow_orders_ledger(p2p_order_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_p2p_utr ON cex_p2p_escrow_orders_ledger(extracted_utr_or_giftcard_code)")

        # Table 3: cex_p2p_in_order_chat_messages
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cex_p2p_in_order_chat_messages (
                p2p_chat_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                p2p_order_number TEXT NOT NULL,
                exchange_name TEXT NOT NULL,
                sender_uid_and_nickname TEXT,
                message_type TEXT NOT NULL,
                message_text_or_image_url TEXT NOT NULL,
                extracted_phone_utr_or_vpa TEXT,
                sent_utc_iso TEXT NOT NULL,
                recovery_classification TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_order_no ON cex_p2p_in_order_chat_messages(p2p_order_number)")

        # Table 4: cex_withdrawals_deposits_and_internal_pay
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cex_withdrawals_deposits_and_internal_pay (
                cex_transfer_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                cex_account_uid INTEGER,
                exchange_name TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                transfer_category TEXT NOT NULL,
                asset_or_currency TEXT NOT NULL,
                network_or_rail TEXT,
                amount_decimal REAL NOT NULL,
                tds_1pct_deducted_inr REAL,
                txid_or_internal_pay_order_id TEXT NOT NULL,
                destination_wallet_or_peer_uid TEXT,
                matches_local_web3_wallet_uid INTEGER,
                transfer_utc_iso TEXT NOT NULL,
                recovery_classification TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cex_txid ON cex_withdrawals_deposits_and_internal_pay(txid_or_internal_pay_order_id)")

        # Insert accounts
        for acc in self.accounts:
            cursor.execute("""
                INSERT INTO cex_exchange_accounts_and_kyc_profiles (
                    exchange_name, fiu_ind_compliance_tier, app_instance_id,
                    source_vfs_file_id, recovery_classification, cex_user_uid,
                    binance_pay_id_or_nick, kyc_verified_full_name, indian_pan_10_char,
                    aadhaar_or_passport_id, registered_email, registered_mobile_phone,
                    linked_indian_banks_vpas_json, cached_spot_funding_balances,
                    last_active_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                acc.exchange_name,
                acc.fiu_ind_compliance_tier.value if hasattr(acc.fiu_ind_compliance_tier, "value") else str(acc.fiu_ind_compliance_tier),
                acc.app_instance_id,
                acc.source_vfs_file_id,
                acc.recovery_classification.value if hasattr(acc.recovery_classification, "value") else str(acc.recovery_classification),
                acc.cex_user_uid,
                acc.binance_pay_id_or_nick,
                acc.kyc_verified_full_name,
                acc.indian_pan_10_char,
                acc.aadhaar_or_passport_id,
                acc.registered_email,
                acc.registered_mobile_phone,
                acc.linked_indian_banks_vpas_json,
                acc.cached_spot_funding_balances,
                acc.last_active_utc_iso,
            ))
            acc.cex_account_uid = cursor.lastrowid

        # Insert P2P orders
        for o in self.p2p_orders:
            cursor.execute("""
                INSERT INTO cex_p2p_escrow_orders_ledger (
                    cex_account_uid, exchange_name, source_vfs_file_id,
                    recovery_classification, p2p_order_number, trade_direction,
                    order_status, crypto_asset, crypto_quantity_decimal,
                    fiat_currency, fiat_total_amount, unit_exchange_rate,
                    counterparty_cex_uid_nick, counterparty_verified_kyc_name,
                    fiat_payment_rail, counterparty_vpa_or_bank_ifsc,
                    extracted_utr_or_giftcard_code, is_third_party_payer_mismatch,
                    order_created_utc_iso, order_completed_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                o.cex_account_uid,
                o.exchange_name,
                o.source_vfs_file_id,
                o.recovery_classification.value if hasattr(o.recovery_classification, "value") else str(o.recovery_classification),
                o.p2p_order_number,
                o.trade_direction.value if hasattr(o.trade_direction, "value") else str(o.trade_direction),
                o.order_status.value if hasattr(o.order_status, "value") else str(o.order_status),
                o.crypto_asset,
                o.crypto_quantity_decimal,
                o.fiat_currency,
                o.fiat_total_amount,
                o.unit_exchange_rate,
                o.counterparty_cex_uid_nick,
                o.counterparty_verified_kyc_name,
                o.fiat_payment_rail,
                o.counterparty_vpa_or_bank_ifsc,
                o.extracted_utr_or_giftcard_code,
                o.is_third_party_payer_mismatch,
                o.order_created_utc_iso,
                o.order_completed_utc_iso,
            ))
            o.p2p_order_uid = cursor.lastrowid

        # Insert chat messages
        for c in self.chat_messages:
            cursor.execute("""
                INSERT INTO cex_p2p_in_order_chat_messages (
                    p2p_order_number, exchange_name, sender_uid_and_nickname,
                    message_type, message_text_or_image_url, extracted_phone_utr_or_vpa,
                    sent_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c.p2p_order_number,
                c.exchange_name,
                c.sender_uid_and_nickname,
                c.message_type,
                c.message_text_or_image_url,
                c.extracted_phone_utr_or_vpa,
                c.sent_utc_iso,
                c.recovery_classification.value if hasattr(c.recovery_classification, "value") else str(c.recovery_classification),
            ))
            c.p2p_chat_uid = cursor.lastrowid

        # Insert transfers
        for t in self.transfers:
            cursor.execute("""
                INSERT INTO cex_withdrawals_deposits_and_internal_pay (
                    cex_account_uid, exchange_name, source_vfs_file_id,
                    transfer_category, asset_or_currency, network_or_rail,
                    amount_decimal, tds_1pct_deducted_inr, txid_or_internal_pay_order_id,
                    destination_wallet_or_peer_uid, matches_local_web3_wallet_uid,
                    transfer_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                t.cex_account_uid,
                t.exchange_name,
                t.source_vfs_file_id,
                t.transfer_category.value if hasattr(t.transfer_category, "value") else str(t.transfer_category),
                t.asset_or_currency,
                t.network_or_rail,
                t.amount_decimal,
                t.tds_1pct_deducted_inr,
                t.txid_or_internal_pay_order_id,
                t.destination_wallet_or_peer_uid,
                t.matches_local_web3_wallet_uid,
                t.transfer_utc_iso,
                t.recovery_classification.value if hasattr(t.recovery_classification, "value") else str(t.recovery_classification),
            ))
            t.cex_transfer_uid = cursor.lastrowid

        conn.commit()
        conn.close()
        return export_db_path
