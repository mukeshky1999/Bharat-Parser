"""
Master UPI Super-App Forensic Engine.
Coordinates PhonePe, Google Pay India, Paytm, WhatsApp Pay, and BharatQR TLV decoders
and persists normalized artifacts into upi_superapp_sandbox_artifacts.sqlite.
Adheres strictly to Specification Section 8 and AGENTS.md Forensic Invariants.
"""

from pathlib import Path
import sqlite3
from typing import Any, List, Optional

from src.upi.gpay import GooglePayDecoder
from src.upi.models import (
    UPIAppSandboxTransaction,
    UPIInAppP2PChat,
    UPILiteAndCircleDelegation,
    UPIScannedQRAndVPALookup,
)
from src.upi.paytm import PaytmDecoder
from src.upi.phonepe import PhonePeDecoder
from src.upi.qr import UniversalQRDecoder
from src.upi.whatsapp_pay import WhatsAppPayDecoder


def _enum_val(val: Any) -> str:
    """Extracts raw string representation from enum or string."""
    if hasattr(val, "value"):
        return str(val.value)
    return str(val) if val is not None else ""


class UPISuperAppForensicEngine:
    """
    Coordinates dedicated sandbox decoders for Indian UPI Super-Apps and persists
    transactions, in-app chats, scanned QRs, and UPI Lite/Circle ledgers to SQLite.
    """

    def __init__(self) -> None:
        self.phonepe_decoder = PhonePeDecoder()
        self.gpay_decoder = GooglePayDecoder()
        self.whatsapp_pay_decoder = WhatsAppPayDecoder()
        self.paytm_decoder = PaytmDecoder()
        self.qr_decoder = UniversalQRDecoder()

    def export_to_ledger(
        self,
        transactions: List[UPIAppSandboxTransaction],
        chats: List[UPIInAppP2PChat],
        lookups: List[UPIScannedQRAndVPALookup],
        delegations: List[UPILiteAndCircleDelegation],
        ledger_path: Path | str,
    ) -> None:
        """
        Commits all extracted UPI records into upi_superapp_sandbox_artifacts.sqlite.
        """
        p = Path(ledger_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            # 1. Table: upi_app_sandbox_transactions
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS upi_app_sandbox_transactions (
                    sandbox_tx_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    source_subsystem TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    utr_12_digit TEXT,
                    app_order_or_tx_id TEXT,
                    instrument_mode TEXT NOT NULL,
                    tx_direction TEXT NOT NULL,
                    app_recorded_status TEXT NOT NULL,
                    raw_amount_value TEXT NOT NULL,
                    amount_inr_decimal REAL NOT NULL,
                    payer_vpa TEXT,
                    payee_vpa TEXT,
                    counterparty_display_name TEXT,
                    counterparty_verified_cbs_name TEXT,
                    counterparty_phone_number TEXT,
                    counterparty_bank_acct_ifsc TEXT,
                    payment_note_remarks TEXT,
                    created_utc_iso TEXT,
                    completed_utc_iso TEXT,
                    raw_json_or_proto_dump TEXT
                );
                """
            )

            # 2. Table: upi_in_app_p2p_chats
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS upi_in_app_p2p_chats (
                    upi_chat_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    thread_or_topic_id TEXT,
                    sender_vpa_or_phone TEXT,
                    receiver_vpa_or_phone TEXT,
                    counterparty_verified_cbs_name TEXT,
                    message_text TEXT NOT NULL,
                    linked_utr_or_tx_id TEXT,
                    sent_utc_iso TEXT
                );
                """
            )

            # 3. Table: upi_scanned_qr_and_vpa_lookups
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS upi_scanned_qr_and_vpa_lookups (
                    lookup_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    artifact_type TEXT NOT NULL,
                    raw_qr_or_uri_string TEXT,
                    extracted_payee_vpa TEXT,
                    verified_merchant_or_cbs_name TEXT,
                    mcc_4_digit TEXT,
                    merchant_city TEXT,
                    merchant_pincode_6_digit TEXT,
                    terminal_or_store_id TEXT,
                    scan_gps_lat_lon_json TEXT,
                    was_name_verified_without_tx INTEGER DEFAULT 0,
                    event_utc_iso TEXT
                );
                """
            )

            # 4. Table: upi_lite_and_circle_delegations
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS upi_lite_and_circle_delegations (
                    record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    feature_type TEXT NOT NULL,
                    lite_lrn_or_mandate_umn TEXT,
                    primary_holder_vpa TEXT,
                    secondary_delegate_vpa_phone TEXT,
                    delegation_role_on_this_device TEXT,
                    balance_or_limit_inr REAL,
                    status TEXT NOT NULL,
                    updated_utc_iso TEXT
                );
                """
            )

            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_upi_tx_utr ON upi_app_sandbox_transactions(utr_12_digit);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_upi_tx_vpa ON upi_app_sandbox_transactions(payee_vpa);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_upi_chat_utr ON upi_in_app_p2p_chats(linked_utr_or_tx_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_upi_qr_vpa ON upi_scanned_qr_and_vpa_lookups(extracted_payee_vpa);")

            # Insert transactions
            for tx in transactions:
                cur.execute(
                    """
                    INSERT INTO upi_app_sandbox_transactions (
                        app_instance_id, source_vfs_file_id, source_subsystem,
                        recovery_classification, utr_12_digit, app_order_or_tx_id,
                        instrument_mode, tx_direction, app_recorded_status,
                        raw_amount_value, amount_inr_decimal, payer_vpa,
                        payee_vpa, counterparty_display_name, counterparty_verified_cbs_name,
                        counterparty_phone_number, counterparty_bank_acct_ifsc,
                        payment_note_remarks, created_utc_iso, completed_utc_iso,
                        raw_json_or_proto_dump
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        tx.app_instance_id,
                        tx.source_vfs_file_id,
                        tx.source_subsystem,
                        _enum_val(tx.recovery_classification),
                        tx.utr_12_digit,
                        tx.app_order_or_tx_id,
                        _enum_val(tx.instrument_mode),
                        _enum_val(tx.tx_direction),
                        _enum_val(tx.app_recorded_status),
                        tx.raw_amount_value,
                        tx.amount_inr_decimal,
                        tx.payer_vpa,
                        tx.payee_vpa,
                        tx.counterparty_display_name,
                        tx.counterparty_verified_cbs_name,
                        tx.counterparty_phone_number,
                        tx.counterparty_bank_acct_ifsc,
                        tx.payment_note_remarks,
                        tx.created_utc_iso,
                        tx.completed_utc_iso,
                        tx.raw_json_or_proto_dump,
                    ),
                )
                tx.sandbox_tx_uid = cur.lastrowid

            # Insert chats
            for ch in chats:
                cur.execute(
                    """
                    INSERT INTO upi_in_app_p2p_chats (
                        app_instance_id, source_vfs_file_id, recovery_classification,
                        thread_or_topic_id, sender_vpa_or_phone, receiver_vpa_or_phone,
                        counterparty_verified_cbs_name, message_text, linked_utr_or_tx_id,
                        sent_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        ch.app_instance_id,
                        ch.source_vfs_file_id,
                        _enum_val(ch.recovery_classification),
                        ch.thread_or_topic_id,
                        ch.sender_vpa_or_phone,
                        ch.receiver_vpa_or_phone,
                        ch.counterparty_verified_cbs_name,
                        ch.message_text,
                        ch.linked_utr_or_tx_id,
                        ch.sent_utc_iso,
                    ),
                )
                ch.upi_chat_uid = cur.lastrowid

            # Insert lookups
            for lk in lookups:
                cur.execute(
                    """
                    INSERT INTO upi_scanned_qr_and_vpa_lookups (
                        app_instance_id, source_vfs_file_id, artifact_type,
                        raw_qr_or_uri_string, extracted_payee_vpa, verified_merchant_or_cbs_name,
                        mcc_4_digit, merchant_city, merchant_pincode_6_digit,
                        terminal_or_store_id, scan_gps_lat_lon_json,
                        was_name_verified_without_tx, event_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        lk.app_instance_id,
                        lk.source_vfs_file_id,
                        _enum_val(lk.artifact_type),
                        lk.raw_qr_or_uri_string,
                        lk.extracted_payee_vpa,
                        lk.verified_merchant_or_cbs_name,
                        lk.mcc_4_digit,
                        lk.merchant_city,
                        lk.merchant_pincode_6_digit,
                        lk.terminal_or_store_id,
                        lk.scan_gps_lat_lon_json,
                        lk.was_name_verified_without_tx,
                        lk.event_utc_iso,
                    ),
                )
                lk.lookup_uid = cur.lastrowid

            # Insert delegations
            for dl in delegations:
                cur.execute(
                    """
                    INSERT INTO upi_lite_and_circle_delegations (
                        app_instance_id, feature_type, lite_lrn_or_mandate_umn,
                        primary_holder_vpa, secondary_delegate_vpa_phone,
                        delegation_role_on_this_device, balance_or_limit_inr,
                        status, updated_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        dl.app_instance_id,
                        _enum_val(dl.feature_type),
                        dl.lite_lrn_or_mandate_umn,
                        dl.primary_holder_vpa,
                        dl.secondary_delegate_vpa_phone,
                        dl.delegation_role_on_this_device,
                        dl.balance_or_limit_inr,
                        _enum_val(dl.status),
                        dl.updated_utc_iso,
                    ),
                )
                dl.record_uid = cur.lastrowid

            con.commit()
        finally:
            con.close()
