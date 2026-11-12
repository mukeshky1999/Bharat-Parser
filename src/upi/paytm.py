"""
Paytm & Paytm for Business (net.one97.paytm) Deep Sandbox Decoder.
Adheres strictly to Specification Section 5 (Sub-Engine 3.1C) and AGENTS.md Forensic Invariants.
"""

from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.upi.models import (
    infer_direction,
    QRArtifactType,
    UPIAppSandboxTransaction,
    UPIInAppP2PChat,
    UPIInstrumentMode,
    UPIScannedQRAndVPALookup,
    UPITransactionDirection,
)
from src.upi.qr import UniversalQRDecoder


class PaytmDecoder:
    """
    Sub-Engine 3.1C: Paytm & Paytm for Business database decoder.
    Parses passbook ledgers, saved beneficiaries, QR scan history, and in-app chat.
    """

    def __init__(self) -> None:
        self.qr_decoder = UniversalQRDecoder()

    def decode_database(
        self,
        db_path: Path | str,
        app_instance_id: int = 4,
        source_vfs_file_id: int = 0,
    ) -> Tuple[
        List[UPIAppSandboxTransaction],
        List[UPIInAppP2PChat],
        List[UPIScannedQRAndVPALookup],
    ]:
        """
        Parses a Paytm SQLite database.
        """
        p = Path(db_path)
        transactions: List[UPIAppSandboxTransaction] = []
        chats: List[UPIInAppP2PChat] = []
        lookups: List[UPIScannedQRAndVPALookup] = []

        if not p.is_file():
            return transactions, chats, lookups

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            cur.execute("SELECT name FROM sqlite_schema WHERE type='table';")
            tables = [row[0] for row in cur.fetchall() if not row[0].startswith("sqlite_")]

            for table_name in tables:
                t_lower = table_name.lower()
                cur.execute(f"PRAGMA table_info([{table_name}]);")
                cols = [c[1] for c in cur.fetchall()]
                col_map = {c.lower(): c for c in cols}

                # 1. Passbook and UPI transactions
                if any(k in t_lower for k in ("passbook", "upi_transaction", "transaction", "wallet_txn")):
                    cur.execute(f"SELECT * FROM [{table_name}];")
                    for r in cur.fetchall():
                        row_dict = dict(zip(cols, r))

                        order_id = row_dict.get("orderId") or row_dict.get("tx_id") or row_dict.get("id")
                        utr_val = row_dict.get("utr") or row_dict.get("rrn") or row_dict.get("bankTxnId")
                        raw_amt = row_dict.get("amount") or 0
                        try:
                            amt_f = float(raw_amt)
                            # If stored as paise integer (> 1000 and integer)
                            if amt_f > 100.0 and amt_f == int(amt_f) and "paise" in str(col_map.get("amount", "")).lower():
                                amt_decimal = amt_f / 100.0
                            else:
                                amt_decimal = amt_f
                        except (ValueError, TypeError):
                            amt_decimal = 0.0

                        ts = row_dict.get("timestamp") or row_dict.get("createdAt") or 0
                        created_iso = None
                        if ts and int(ts) > 0:
                            created_iso = ForensicTimestamp.from_unix_milliseconds(int(ts)).utc_iso8601

                        tx = UPIAppSandboxTransaction(
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            source_subsystem="PAYTM_PASSBOOK_DB",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            amount_inr_decimal=amt_decimal,
                            raw_amount_value=str(raw_amt),
                            instrument_mode=UPIInstrumentMode.UPI_BANK_ACCOUNT.value,
                            tx_direction=infer_direction(row_dict, row_dict.get("payerVpa"), row_dict.get("payeeVpa")),
                            app_recorded_status=str(row_dict.get("status") or "UNKNOWN").upper(),
                            utr_12_digit=str(utr_val) if utr_val else None,
                            app_order_or_tx_id=str(order_id) if order_id else None,
                            payer_vpa=row_dict.get("payerVpa"),
                            payee_vpa=row_dict.get("payeeVpa"),
                            counterparty_verified_cbs_name=row_dict.get("counterpartyName") or row_dict.get("payeeName"),
                            created_utc_iso=created_iso,
                        )
                        transactions.append(tx)

                # 2. QR scan history
                elif any(k in t_lower for k in ("qr", "scan")):
                    cur.execute(f"SELECT * FROM [{table_name}];")
                    for r in cur.fetchall():
                        row_dict = dict(zip(cols, r))
                        qr_text = row_dict.get("raw_qr") or row_dict.get("qr_string") or row_dict.get("payload")
                        if qr_text:
                            lookup = self.qr_decoder.decode_qr(
                                str(qr_text),
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=source_vfs_file_id,
                            )
                            if lookup:
                                lookups.append(lookup)

                # 3. In-app chat
                elif "chat" in t_lower:
                    cur.execute(f"SELECT * FROM [{table_name}];")
                    for r in cur.fetchall():
                        row_dict = dict(zip(cols, r))
                        msg = row_dict.get("message") or row_dict.get("text") or ""
                        ts = row_dict.get("timestamp") or 0
                        sent_iso = None
                        if ts and int(ts) > 0:
                            sent_iso = ForensicTimestamp.from_unix_milliseconds(int(ts)).utc_iso8601

                        chats.append(
                            UPIInAppP2PChat(
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=source_vfs_file_id,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                message_text=str(msg),
                                thread_or_topic_id=str(row_dict.get("threadId") or ""),
                                sender_vpa_or_phone=row_dict.get("sender"),
                                receiver_vpa_or_phone=row_dict.get("receiver"),
                                sent_utc_iso=sent_iso,
                            )
                        )

        finally:
            con.close()

        return transactions, chats, lookups
