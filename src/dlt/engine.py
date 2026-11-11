"""
Master Engine: DLT Financial SMS & System Notification Parser Engine.
Extracts, structures, and validates financial SMS alerts across Android mmssms.db/bugle_db
and iOS sms.db (including binary attributedBody streams), and ingests OS push notification ledgers.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 3.4 Spec.
"""

from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Union

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.dlt.attributed_body import IOSAttributedBodyUnpacker
from src.dlt.dlt_headers import DLTHeaderParser
from src.dlt.models import (
    DLTFinancialSMSLedgerRecord,
    OSFinancialNotificationRecord,
    SourceDBType,
)
from src.dlt.notifications import OSNotificationParser
from src.dlt.sms_grammar import FinancialSMSGrammarParser


class DLTFinancialSMSNotificationEngine:
    """Master engine orchestrating Layer-2 SMS extraction and Layer-3 OS notification forensics."""

    def __init__(self) -> None:
        self.attributed_unpacker = IOSAttributedBodyUnpacker()
        self.dlt_header_parser = DLTHeaderParser()
        self.grammar_parser = FinancialSMSGrammarParser()
        self.notif_parser = OSNotificationParser()

    def parse_ios_sms_db(
        self,
        db_path: Union[str, Path],
        source_vfs_file_id: int = 501,
    ) -> List[DLTFinancialSMSLedgerRecord]:
        """
        Parses iOS /private/var/mobile/Library/SMS/sms.db.
        Unpacks binary attributedBody when message.text IS NULL, decodes DLT headers,
        and applies the 10-category financial SMS grammar.
        """
        target = Path(db_path)
        if not target.exists():
            return []

        records: List[DLTFinancialSMSLedgerRecord] = []
        conn = sqlite3.connect(f"file:{target.resolve()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute("""
                SELECT 
                    m.ROWID AS msg_id,
                    h.id AS sender_id,
                    m.text,
                    m.attributedBody,
                    m.service,
                    m.date,
                    m.is_from_me
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                WHERE m.is_from_me = 0
                ORDER BY m.ROWID ASC;
            """)
            rows = cur.fetchall()

            for r in rows:
                col_keys = r.keys()
                row_id = r["msg_id"] if "msg_id" in col_keys else None
                sender = str(r["sender_id"]) if "sender_id" in col_keys and r["sender_id"] else ""
                raw_text = str(r["text"]) if "text" in col_keys and r["text"] else ""
                raw_blob = r["attributedBody"] if "attributedBody" in col_keys else None
                date_val = r["date"] if "date" in col_keys else 0

                final_text = raw_text
                source_db_type = SourceDBType.IOS_SMS_DB_TEXT.value

                # Unpack attributedBody if text is empty/null
                if not final_text.strip() and raw_blob:
                    unpacked = self.attributed_unpacker.unpack(raw_blob)
                    if unpacked:
                        final_text = unpacked
                        source_db_type = SourceDBType.IOS_SMS_DB_ATTRIBUTED_BODY.value

                if not final_text.strip():
                    continue

                # Parse DLT header
                header_info = self.dlt_header_parser.parse_header(sender)

                # Parse body with grammar pipeline
                fields = self.grammar_parser.parse_sms(
                    body=final_text,
                    dlt_header_info=header_info,
                )

                # Convert Apple Cocoa timestamp
                # Cocoa nanoseconds if > 10^12, else seconds
                utc_iso = "1970-01-01T00:00:00.000000Z"
                utc_ns = 0
                if date_val is not None and date_val > 0:
                    if date_val > 10_000_000_000_000:
                        cocoa_sec = float(date_val) / 1_000_000_000.0
                    else:
                        cocoa_sec = float(date_val)
                    ft = ForensicTimestamp.from_cocoa_seconds(cocoa_sec)
                    utc_iso = ft.utc_iso8601
                    utc_ns = int((cocoa_sec + 978307200.0) * 1_000_000_000)

                record = DLTFinancialSMSLedgerRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    source_db_type=source_db_type,
                    original_sms_rowid=row_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    raw_sender_address=sender,
                    dlt_operator_and_circle=header_info.operator_and_circle,
                    dlt_entity_code=header_info.entity_code,
                    dlt_category_suffix=header_info.category_suffix,
                    resolved_institution_name=header_info.resolved_institution,
                    sms_event_category=fields.sms_event_category,
                    masked_account_or_card=fields.masked_account_or_card,
                    account_tail_digits=fields.account_tail_digits,
                    payment_rail=fields.payment_rail,
                    utr_or_rrn_reference=fields.utr_or_rrn_reference,
                    amount_inr_decimal=fields.amount_inr_decimal,
                    post_tx_available_balance_inr=fields.post_tx_available_balance_inr,
                    counterparty_vpa_or_name=fields.counterparty_vpa_or_name,
                    atm_location_or_otp_digits=fields.atm_location_or_otp_digits,
                    android_sub_id=None,
                    receiving_sim_iccid=None,
                    carrier_smsc_number=None,
                    is_spoofed_sms_suspected=0,
                    full_sms_body_text=final_text,
                    received_utc_ns=utc_ns,
                    received_utc_iso=utc_iso,
                )
                records.append(record)

        finally:
            conn.close()

        return records

    def parse_android_sms_db(
        self,
        db_path: Union[str, Path],
        source_vfs_file_id: int = 502,
        sim_map: Optional[Dict[int, str]] = None,
    ) -> List[DLTFinancialSMSLedgerRecord]:
        """
        Parses Android mmssms.db / bugle_db, checks carrier SMSC spoofing,
        and extracts 10-category financial SMS records.
        """
        target = Path(db_path)
        if not target.exists():
            return []

        records: List[DLTFinancialSMSLedgerRecord] = []
        conn = sqlite3.connect(f"file:{target.resolve()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sms', 'messages');")
            tables = [r["name"] for r in cur.fetchall()]
            if not tables:
                conn.close()
                return []

            target_table = "sms" if "sms" in tables else tables[0]
            cur.execute(f"SELECT * FROM {target_table} WHERE type = 1 ORDER BY _id ASC;")
            rows = cur.fetchall()

            for r in rows:
                col_keys = r.keys()
                row_id = r["_id"] if "_id" in col_keys else None
                address = str(r["address"]) if "address" in col_keys and r["address"] else ""
                body = str(r["body"]) if "body" in col_keys and r["body"] else ""
                date_val = r["date"] if "date" in col_keys else 0
                service_center = str(r["service_center"]) if "service_center" in col_keys and r["service_center"] else None
                sub_id = int(r["sub_id"]) if "sub_id" in col_keys and r["sub_id"] is not None else None
                creator = str(r["creator"]) if "creator" in col_keys and r["creator"] else None

                if not body.strip():
                    continue

                # Carrier SMSC spoof check
                is_spoofed = 1 if self.dlt_header_parser.detect_smsc_spoof(
                    service_center=service_center,
                    creator=creator,
                    msg_type=1,
                ) else 0

                # DLT Header details
                header_info = self.dlt_header_parser.parse_header(address)

                # Grammar extraction
                fields = self.grammar_parser.parse_sms(
                    body=body,
                    dlt_header_info=header_info,
                )

                # SIM ICCID join
                iccid = None
                if sim_map and sub_id is not None and sub_id in sim_map:
                    iccid = sim_map[sub_id]

                # Timestamp conversion
                utc_iso = "1970-01-01T00:00:00.000000Z"
                utc_ns = 0
                if date_val and date_val > 0:
                    ft = ForensicTimestamp.from_unix_milliseconds(date_val)
                    utc_iso = ft.utc_iso8601
                    utc_ns = int(date_val) * 1_000_000

                record = DLTFinancialSMSLedgerRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    source_db_type=SourceDBType.ANDROID_MMSSMS_DE.value,
                    original_sms_rowid=row_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    raw_sender_address=address,
                    dlt_operator_and_circle=header_info.operator_and_circle,
                    dlt_entity_code=header_info.entity_code,
                    dlt_category_suffix=header_info.category_suffix,
                    resolved_institution_name=header_info.resolved_institution,
                    sms_event_category=fields.sms_event_category,
                    masked_account_or_card=fields.masked_account_or_card,
                    account_tail_digits=fields.account_tail_digits,
                    payment_rail=fields.payment_rail,
                    utr_or_rrn_reference=fields.utr_or_rrn_reference,
                    amount_inr_decimal=fields.amount_inr_decimal,
                    post_tx_available_balance_inr=fields.post_tx_available_balance_inr,
                    counterparty_vpa_or_name=fields.counterparty_vpa_or_name,
                    atm_location_or_otp_digits=fields.atm_location_or_otp_digits,
                    android_sub_id=sub_id,
                    receiving_sim_iccid=iccid,
                    carrier_smsc_number=service_center,
                    is_spoofed_sms_suspected=is_spoofed,
                    full_sms_body_text=body,
                    received_utc_ns=utc_ns,
                    received_utc_iso=utc_iso,
                )
                records.append(record)

        finally:
            conn.close()

        return records

    def export_to_ledger(
        self,
        sms_records: List[DLTFinancialSMSLedgerRecord],
        notification_records: List[OSFinancialNotificationRecord],
        ledger_path: Union[str, Path],
    ) -> None:
        """
        Initializes dlt_sms_and_notifications_engine.sqlite schema and persists all records:
        1. dlt_financial_sms_ledger
        2. os_financial_notification_ledger
        """
        target = Path(ledger_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(target)
        cur = conn.cursor()

        try:
            # 1. dlt_financial_sms_ledger
            cur.execute("""
                CREATE TABLE IF NOT EXISTS dlt_financial_sms_ledger (
                    fin_sms_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_vfs_file_id INTEGER NOT NULL,
                    source_db_type TEXT NOT NULL,
                    original_sms_rowid INTEGER,
                    recovery_classification TEXT NOT NULL,
                    raw_sender_address TEXT NOT NULL,
                    dlt_operator_and_circle TEXT,
                    dlt_entity_code TEXT,
                    dlt_category_suffix TEXT,
                    resolved_institution_name TEXT NOT NULL,
                    sms_event_category TEXT NOT NULL,
                    masked_account_or_card TEXT,
                    account_tail_digits TEXT,
                    payment_rail TEXT,
                    utr_or_rrn_reference TEXT,
                    amount_inr_decimal REAL,
                    post_tx_available_balance_inr REAL,
                    counterparty_vpa_or_name TEXT,
                    atm_location_or_otp_digits TEXT,
                    android_sub_id INTEGER,
                    receiving_sim_iccid TEXT,
                    carrier_smsc_number TEXT,
                    is_spoofed_sms_suspected INTEGER DEFAULT 0,
                    full_sms_body_text TEXT NOT NULL,
                    received_utc_ns INTEGER NOT NULL,
                    received_utc_iso TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_utr
                ON dlt_financial_sms_ledger (utr_or_rrn_reference);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_tail
                ON dlt_financial_sms_ledger (account_tail_digits);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_cat
                ON dlt_financial_sms_ledger (sms_event_category);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_sms_sender
                ON dlt_financial_sms_ledger (raw_sender_address);
            """)

            # 2. os_financial_notification_ledger
            cur.execute("""
                CREATE TABLE IF NOT EXISTS os_financial_notification_ledger (
                    fin_notif_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_vfs_file_id INTEGER NOT NULL,
                    notification_subsystem TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    target_app_bundle_or_pkg TEXT NOT NULL,
                    is_metadata_only_no_body INTEGER NOT NULL DEFAULT 0,
                    notif_title_text TEXT,
                    notif_body_text TEXT,
                    extracted_amount_inr REAL,
                    extracted_utr_reference TEXT,
                    user_interaction_state TEXT,
                    delivered_utc_iso TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_notif_target
                ON os_financial_notification_ledger (target_app_bundle_or_pkg);
            """)

            # Insert SMS records
            for s in sms_records:
                rec_val = (
                    s.recovery_classification.value
                    if hasattr(s.recovery_classification, "value")
                    else str(s.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO dlt_financial_sms_ledger (
                        source_vfs_file_id,
                        source_db_type,
                        original_sms_rowid,
                        recovery_classification,
                        raw_sender_address,
                        dlt_operator_and_circle,
                        dlt_entity_code,
                        dlt_category_suffix,
                        resolved_institution_name,
                        sms_event_category,
                        masked_account_or_card,
                        account_tail_digits,
                        payment_rail,
                        utr_or_rrn_reference,
                        amount_inr_decimal,
                        post_tx_available_balance_inr,
                        counterparty_vpa_or_name,
                        atm_location_or_otp_digits,
                        android_sub_id,
                        receiving_sim_iccid,
                        carrier_smsc_number,
                        is_spoofed_sms_suspected,
                        full_sms_body_text,
                        received_utc_ns,
                        received_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        s.source_vfs_file_id,
                        s.source_db_type,
                        s.original_sms_rowid,
                        rec_val,
                        s.raw_sender_address,
                        s.dlt_operator_and_circle,
                        s.dlt_entity_code,
                        s.dlt_category_suffix,
                        s.resolved_institution_name,
                        s.sms_event_category,
                        s.masked_account_or_card,
                        s.account_tail_digits,
                        s.payment_rail,
                        s.utr_or_rrn_reference,
                        s.amount_inr_decimal,
                        s.post_tx_available_balance_inr,
                        s.counterparty_vpa_or_name,
                        s.atm_location_or_otp_digits,
                        s.android_sub_id,
                        s.receiving_sim_iccid,
                        s.carrier_smsc_number,
                        s.is_spoofed_sms_suspected,
                        s.full_sms_body_text,
                        s.received_utc_ns,
                        s.received_utc_iso,
                    ),
                )

            # Insert Notification records
            for n in notification_records:
                rec_val = (
                    n.recovery_classification.value
                    if hasattr(n.recovery_classification, "value")
                    else str(n.recovery_classification)
                )
                cur.execute(
                    """
                    INSERT INTO os_financial_notification_ledger (
                        source_vfs_file_id,
                        notification_subsystem,
                        recovery_classification,
                        target_app_bundle_or_pkg,
                        is_metadata_only_no_body,
                        notif_title_text,
                        notif_body_text,
                        extracted_amount_inr,
                        extracted_utr_reference,
                        user_interaction_state,
                        delivered_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        n.source_vfs_file_id,
                        n.notification_subsystem,
                        rec_val,
                        n.target_app_bundle_or_pkg,
                        n.is_metadata_only_no_body,
                        n.notif_title_text,
                        n.notif_body_text,
                        n.extracted_amount_inr,
                        n.extracted_utr_reference,
                        n.user_interaction_state,
                        n.delivered_utc_iso,
                    ),
                )

            conn.commit()

        finally:
            conn.close()
