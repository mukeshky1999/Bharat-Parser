"""
PhonePe & PhonePe Business Deep Sandbox Decoder.
Adheres strictly to Specification Section 3 (Sub-Engine 3.1A) and AGENTS.md Forensic Invariants.
"""

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.upi.models import (
    QRArtifactType,
    UPIAppSandboxTransaction,
    UPIInAppP2PChat,
    UPIInstrumentMode,
    UPIScannedQRAndVPALookup,
    UPITransactionDirection,
    UPITransactionStatus,
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


class PhonePeDecoder:
    """
    Sub-Engine 3.1A: Schema-driven PhonePe & PhonePe Business extractor.
    Discovers workflow ledgers, Bullhorn P2P chat threads, and VPA verification caches.
    """

    def decode_database(
        self,
        db_path: Path | str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Tuple[
        List[UPIAppSandboxTransaction],
        List[UPIInAppP2PChat],
        List[UPIScannedQRAndVPALookup],
    ]:
        """
        Processes a PhonePe SQLite database via schema fingerprinting.
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
                cur.execute(f"PRAGMA table_info([{table_name}]);")
                cols_info = cur.fetchall()
                col_names = [c[1] for c in cols_info]
                col_lower_map = {c.lower(): c for c in col_names}

                # --------------------------------------------------------------
                # Subsystem 1: Core Transaction & Workflow Ledger Fingerprint
                # --------------------------------------------------------------
                tx_indicators = {
                    "transactionid", "txnid", "unitid", "amount", "amountinpaise",
                    "state", "status", "paymentstate", "utr", "bankreferenceno",
                    "workflowtype", "instrumenttype"
                }
                matching_tx_cols = tx_indicators.intersection(set(col_lower_map.keys()))

                if len(matching_tx_cols) >= 3:
                    cur.execute(f"SELECT * FROM [{table_name}];")
                    rows = cur.fetchall()
                    for r in rows:
                        row_dict = dict(zip(col_names, r))

                        raw_payload_str = (
                            row_dict.get("rawPayload")
                            or row_dict.get("payload")
                            or row_dict.get("data")
                            or row_dict.get("workflowData")
                            or row_dict.get("extraInfo")
                        )
                        payload_data = _safe_json_loads(raw_payload_str) or {}

                        # Extract IDs
                        tx_id = (
                            row_dict.get("transactionId")
                            or row_dict.get("txnId")
                            or row_dict.get("unitId")
                            or payload_data.get("transactionId")
                            or payload_data.get("merchantOrderId")
                        )
                        utr_val = (
                            row_dict.get("utr")
                            or row_dict.get("bankReferenceNo")
                            or payload_data.get("bankReferenceNo")
                            or payload_data.get("utr")
                            or payload_data.get("upiTransactionId")
                        )

                        # Extract amount (Paise -> INR)
                        amount_paise = (
                            payload_data.get("amountInPaise")
                            or payload_data.get("amount")
                            or row_dict.get("amountInPaise")
                            or row_dict.get("amount")
                            or 0
                        )
                        try:
                            amt_decimal = float(amount_paise) / 100.0
                        except (ValueError, TypeError):
                            amt_decimal = 0.0

                        # Extract Counterparties
                        payer_vpa = (
                            payload_data.get("payerVpa")
                            or payload_data.get("senderVpa")
                            or payload_data.get("fromVpa")
                            or row_dict.get("payerVpa")
                        )
                        payee_vpa = (
                            payload_data.get("payeeVpa")
                            or payload_data.get("receiverVpa")
                            or payload_data.get("toVpa")
                            or payload_data.get("merchantVpa")
                            or row_dict.get("payeeVpa")
                        )
                        payee_name = (
                            payload_data.get("payeeName")
                            or payload_data.get("bankingName")
                            or payload_data.get("accountHolderName")
                            or payload_data.get("merchantName")
                            or row_dict.get("payeeName")
                        )
                        note = (
                            payload_data.get("note")
                            or payload_data.get("remarks")
                            or payload_data.get("message")
                            or row_dict.get("note")
                        )

                        # Timestamps
                        raw_ts = (
                            row_dict.get("createdAt")
                            or row_dict.get("creationTime")
                            or row_dict.get("timestamp")
                            or payload_data.get("createdAt")
                            or 0
                        )
                        created_iso = None
                        if raw_ts and int(raw_ts) > 0:
                            created_iso = ForensicTimestamp.from_unix_milliseconds(int(raw_ts)).utc_iso8601

                        status_val = (
                            row_dict.get("state")
                            or row_dict.get("status")
                            or payload_data.get("state")
                            or "SUCCESS"
                        )

                        inst_type = payload_data.get("instrumentType", "ACCOUNT")
                        inst_mode = (
                            UPIInstrumentMode.UPI_LITE_ON_DEVICE.value
                            if "LITE" in str(inst_type).upper()
                            else UPIInstrumentMode.UPI_BANK_ACCOUNT.value
                        )

                        tx_rec = UPIAppSandboxTransaction(
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            source_subsystem="PHONEPE_WORKFLOW_DB",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            amount_inr_decimal=amt_decimal,
                            raw_amount_value=f"{amount_paise} paise",
                            instrument_mode=inst_mode,
                            tx_direction=UPITransactionDirection.DEBIT_SENT.value,
                            app_recorded_status=str(status_val).upper(),
                            utr_12_digit=str(utr_val) if utr_val else None,
                            app_order_or_tx_id=str(tx_id) if tx_id else None,
                            payer_vpa=payer_vpa,
                            payee_vpa=payee_vpa,
                            counterparty_verified_cbs_name=payee_name,
                            payment_note_remarks=note,
                            created_utc_iso=created_iso,
                            raw_json_or_proto_dump=raw_payload_str if isinstance(raw_payload_str, str) else None,
                        )
                        transactions.append(tx_rec)
                    continue

                # --------------------------------------------------------------
                # Subsystem 2: Bullhorn Messaging & P2P Chat Fingerprint
                # --------------------------------------------------------------
                bullhorn_indicators = {"topicid", "messageid", "senderid"}
                if (
                    "message" in table_name.lower()
                    or "bullhorn" in table_name.lower()
                    or bullhorn_indicators.issubset(set(col_lower_map.keys()))
                ):
                    cur.execute(f"SELECT * FROM [{table_name}];")
                    for r in cur.fetchall():
                        row_dict = dict(zip(col_names, r))
                        payload_str = row_dict.get("payload") or row_dict.get("messageData") or row_dict.get("data")
                        p_data = _safe_json_loads(payload_str) or {}

                        msg_text = p_data.get("text") or p_data.get("message") or str(payload_str)
                        created_ts = row_dict.get("createdAt") or p_data.get("timestamp") or 0
                        sent_iso = None
                        if created_ts and int(created_ts) > 0:
                            sent_iso = ForensicTimestamp.from_unix_milliseconds(int(created_ts)).utc_iso8601

                        chats.append(
                            UPIInAppP2PChat(
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=source_vfs_file_id,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                message_text=str(msg_text),
                                thread_or_topic_id=str(row_dict.get("topicId") or p_data.get("topicId") or ""),
                                sender_vpa_or_phone=p_data.get("senderVpa") or p_data.get("senderPhone"),
                                receiver_vpa_or_phone=p_data.get("receiverVpa") or p_data.get("receiverPhone"),
                                counterparty_verified_cbs_name=p_data.get("verifiedName"),
                                linked_utr_or_tx_id=p_data.get("utr") or p_data.get("transactionId"),
                                sent_utc_iso=sent_iso,
                            )
                        )
                    continue

                # --------------------------------------------------------------
                # Subsystem 3: VPA Verification Cache Fingerprint
                # --------------------------------------------------------------
                if any(k in table_name.lower() for k in ("vpa", "beneficiary", "payee", "contact")):
                    vpa_col = col_lower_map.get("vpa")
                    name_col = (
                        col_lower_map.get("verifiedname")
                        or col_lower_map.get("accountholdername")
                        or col_lower_map.get("bankingname")
                        or col_lower_map.get("name")
                    )
                    if vpa_col:
                        cur.execute(f"SELECT * FROM [{table_name}];")
                        for r in cur.fetchall():
                            row_dict = dict(zip(col_names, r))
                            vpa_str = row_dict.get(vpa_col)
                            name_str = row_dict.get(name_col) if name_col else None
                            if vpa_str:
                                lookups.append(
                                    UPIScannedQRAndVPALookup(
                                        app_instance_id=app_instance_id,
                                        source_vfs_file_id=source_vfs_file_id,
                                        artifact_type=QRArtifactType.VPA_NAME_VERIFICATION_CACHE.value,
                                        raw_qr_or_uri_string=None,
                                        extracted_payee_vpa=str(vpa_str),
                                        verified_merchant_or_cbs_name=str(name_str) if name_str else None,
                                        was_name_verified_without_tx=1,
                                    )
                                )

        finally:
            con.close()

        return transactions, chats, lookups
