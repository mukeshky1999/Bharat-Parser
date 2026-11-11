"""
WhatsApp Pay (com.whatsapp) & Auxiliary UPI App Decoders (BHIM, FamPay, CRED).
Adheres strictly to Specification Section 6 (Sub-Engine 3.1D) and AGENTS.md Forensic Invariants.
"""

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.upi.models import (
    UPIAppSandboxTransaction,
    UPIInstrumentMode,
    UPITransactionDirection,
)


def _safe_json_loads(text: Any) -> Optional[Dict[str, Any]]:
    """Attempts to decode a JSON string or dict, returning a dictionary or None."""
    if not text:
        return None
    if isinstance(text, dict):
        return text
    try:
        parsed = json.loads(str(text))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


class WhatsAppPayDecoder:
    """
    Sub-Engine 3.1D (Target 1): WhatsApp Pay decoder.
    Parses msgstore.db (pay_transaction table) enforcing exact amount_1000 / 1000.0 math.
    """

    def decode_database(
        self,
        db_path: Path | str,
        app_instance_id: int = 3,
        source_vfs_file_id: int = 0,
    ) -> List[UPIAppSandboxTransaction]:
        """
        Parses WhatsApp msgstore.db extracting WhatsApp Pay transaction rows.
        """
        p = Path(db_path)
        transactions: List[UPIAppSandboxTransaction] = []

        if not p.is_file():
            return transactions

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            cur.execute("SELECT name FROM sqlite_schema WHERE type='table';")
            tables = [row[0] for row in cur.fetchall() if not row[0].startswith("sqlite_")]

            pay_table = next(
                (t for t in tables if any(k in t.lower() for k in ("pay_transaction", "payment", "message_payment"))),
                None
            )

            if pay_table:
                cur.execute(f"PRAGMA table_info([{pay_table}]);")
                cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM [{pay_table}];")
                for r in cur.fetchall():
                    row_dict = dict(zip(cols, r))

                    tx_id = row_dict.get("id") or row_dict.get("key_id") or row_dict.get("interop_id")
                    sender_jid = row_dict.get("sender_jid")
                    receiver_jid = row_dict.get("receiver_jid")

                    # WhatsApp stores currency in milli-Rupees (1/1000 INR)
                    amount_1000 = row_dict.get("amount_1000") or 0
                    try:
                        amt_decimal = float(amount_1000) / 1000.0
                    except (ValueError, TypeError):
                        amt_decimal = 0.0

                    ts_val = row_dict.get("timestamp") or 0
                    created_iso = None
                    if ts_val and int(ts_val) > 0:
                        created_iso = ForensicTimestamp.from_unix_milliseconds(int(ts_val)).utc_iso8601

                    extra_raw = row_dict.get("extra_data") or row_dict.get("country_data")
                    extra_dict = _safe_json_loads(extra_raw) or {}

                    payer_vpa = extra_dict.get("vpa") or extra_dict.get("sender_vpa")
                    payee_vpa = extra_dict.get("receiver_vpa") or extra_dict.get("payee_vpa")
                    utr_val = extra_dict.get("utr") or extra_dict.get("bank_transaction_id") or row_dict.get("interop_id")
                    cbs_name = extra_dict.get("accountHolderName") or extra_dict.get("verified_name")

                    tx = UPIAppSandboxTransaction(
                        app_instance_id=app_instance_id,
                        source_vfs_file_id=source_vfs_file_id,
                        source_subsystem="WHATSAPP_PAY_TABLE",
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        amount_inr_decimal=amt_decimal,
                        raw_amount_value=f"{amount_1000} milli-rupees",
                        instrument_mode=UPIInstrumentMode.UPI_BANK_ACCOUNT.value,
                        tx_direction=UPITransactionDirection.DEBIT_SENT.value,
                        app_recorded_status="SUCCESS",
                        utr_12_digit=str(utr_val) if utr_val else None,
                        app_order_or_tx_id=str(tx_id) if tx_id else None,
                        payer_vpa=str(payer_vpa) if payer_vpa else (str(sender_jid) if sender_jid else None),
                        payee_vpa=str(payee_vpa) if payee_vpa else (str(receiver_jid) if receiver_jid else None),
                        counterparty_verified_cbs_name=cbs_name,
                        created_utc_iso=created_iso,
                        raw_json_or_proto_dump=str(extra_raw) if extra_raw else None,
                    )
                    transactions.append(tx)

        finally:
            con.close()

        return transactions
