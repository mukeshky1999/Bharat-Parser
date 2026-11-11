"""
Google Pay India (com.google.android.apps.nbu.paisa.user) Deep Sandbox & Protobuf Decoder.
Adheres strictly to Specification Section 4 (Sub-Engine 3.1B) and AGENTS.md Forensic Invariants.
"""

from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.nonsqlite.protobuf import decode_raw_protobuf
from src.upi.models import (
    UPIAppSandboxTransaction,
    UPIInAppP2PChat,
    UPIInstrumentMode,
    UPITransactionDirection,
)


def _extract_money_from_proto(d: Any) -> Optional[Tuple[float, str]]:
    """
    Recursively inspects a decoded Protobuf dictionary for google.type.Money or amount_micros:
    - google.type.Money: Field 1="INR", Field 2=units, Field 3=nanos -> units + (nanos / 10^9).
    - amount_micros: micros / 10^6.
    """
    if isinstance(d, dict):
        f1 = d.get("field_1", {})
        f2 = d.get("field_2", {})
        f3 = d.get("field_3", {})

        # Check google.type.Money
        if isinstance(f1, dict) and str(f1.get("value", "")).upper() == "INR":
            if isinstance(f2, dict) and "value" in f2:
                units = int(f2["value"])
                nanos = int(f3.get("value", 0)) if isinstance(f3, dict) else 0
                amt = float(units) + (float(nanos) / 1_000_000_000.0)
                return amt, f"units:{units}, nanos:{nanos}"

        # Recurse
        for v in d.values():
            if isinstance(v, dict):
                nested = v.get("nested_object") or v
                res = _extract_money_from_proto(nested)
                if res is not None:
                    return res

    return None


def _find_utr_in_proto(d: Any) -> Optional[str]:
    """Recursively searches for a 12-digit numeric UTR/RRN string in decoded Protobuf."""
    if isinstance(d, dict):
        val = d.get("value")
        if isinstance(val, str) and len(val) == 12 and val.isdigit():
            return val
        for v in d.values():
            if isinstance(v, dict):
                nested = v.get("nested_object") or v
                res = _find_utr_in_proto(nested)
                if res is not None:
                    return res
    return None


class GooglePayDecoder:
    """
    Sub-Engine 3.1B: Google Pay India (Tez / Paisa) database and Protobuf decoder.
    Preserves dual-name attribution (display_name vs banking_name) and 3-format currency math.
    """

    def decode_database(
        self,
        db_path: Path | str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Tuple[List[UPIAppSandboxTransaction], List[UPIInAppP2PChat]]:
        """
        Parses paisa.db extracting transactions and P2P chat messages.
        """
        p = Path(db_path)
        transactions: List[UPIAppSandboxTransaction] = []
        chats: List[UPIInAppP2PChat] = []

        if not p.is_file():
            return transactions, chats

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            # 1. Load participants table
            participants_map: Dict[str, Dict[str, Any]] = {}
            cur.execute("SELECT name FROM sqlite_schema WHERE type='table';")
            tables = [row[0] for row in cur.fetchall() if not row[0].startswith("sqlite_")]

            part_table = next(
                (t for t in tables if any(k in t.lower() for k in ("participant", "people", "contact"))),
                None
            )

            if part_table:
                cur.execute(f"PRAGMA table_info([{part_table}]);")
                part_cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM [{part_table}];")
                for r in cur.fetchall():
                    row_dict = dict(zip(part_cols, r))
                    pid = (
                        row_dict.get("participant_id")
                        or row_dict.get("id")
                        or row_dict.get("gaia_id")
                    )
                    if pid:
                        participants_map[str(pid)] = {
                            "phone_number": row_dict.get("phone_number"),
                            "vpa": row_dict.get("vpa"),
                            "display_name": row_dict.get("display_name"),
                            "banking_name": row_dict.get("banking_name"),
                        }

            # 2. Process stream_items / transactions tables
            stream_table = next(
                (t for t in tables if any(k in t.lower() for k in ("stream_item", "transaction", "payment"))),
                None
            )

            if stream_table:
                cur.execute(f"PRAGMA table_info([{stream_table}]);")
                stream_cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM [{stream_table}];")
                for r in cur.fetchall():
                    row_dict = dict(zip(stream_cols, r))

                    item_id = row_dict.get("item_id") or row_dict.get("id") or row_dict.get("tx_id")
                    pid = row_dict.get("participant_id")
                    item_type = str(row_dict.get("item_type") or "PAYMENT_TRANSACTION").upper()
                    status_val = str(row_dict.get("status") or "SUCCESS").upper()
                    col_utr = row_dict.get("utr")
                    ts_ms = row_dict.get("timestamp_ms") or row_dict.get("timestamp") or 0

                    proto_blob = row_dict.get("proto_blob") or row_dict.get("payload_proto") or row_dict.get("data")
                    pb_dict: Dict[str, Any] = {}
                    if proto_blob and isinstance(proto_blob, (bytes, bytearray)):
                        pb_dict, _ = decode_raw_protobuf(bytes(proto_blob))

                    # Counterparty attribution
                    counterparty = participants_map.get(str(pid), {})
                    display_name = counterparty.get("display_name")
                    banking_name = counterparty.get("banking_name")
                    payee_vpa = counterparty.get("vpa") or row_dict.get("receiver_vpa") or row_dict.get("payee_vpa")
                    payer_vpa = row_dict.get("sender_vpa") or row_dict.get("payer_vpa")
                    phone = counterparty.get("phone_number")

                    created_iso = None
                    if ts_ms:
                        try:
                            ts_num = float(ts_ms)
                            if ts_num > 1e11:
                                created_iso = ForensicTimestamp.from_unix_milliseconds(int(ts_num)).utc_iso8601
                            elif ts_num > 0:
                                created_iso = ForensicTimestamp.from_unix_seconds(int(ts_num)).utc_iso8601
                        except (ValueError, TypeError):
                            try:
                                created_iso = ForensicTimestamp.from_iso_string(str(ts_ms)).utc_iso8601
                            except Exception:
                                created_iso = str(ts_ms)

                    if "CHAT" in item_type or "MESSAGE" in item_type:
                        msg_text = row_dict.get("text") or (pb_dict.get("field_1", {}).get("value") if pb_dict else "")
                        chats.append(
                            UPIInAppP2PChat(
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=source_vfs_file_id,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                message_text=str(msg_text),
                                thread_or_topic_id=str(pid or ""),
                                sender_vpa_or_phone=phone,
                                counterparty_verified_cbs_name=banking_name or display_name,
                                linked_utr_or_tx_id=str(col_utr) if col_utr else None,
                                sent_utc_iso=created_iso,
                            )
                        )
                    else:
                        # Extract currency amount
                        money_res = _extract_money_from_proto(pb_dict)
                        if money_res is not None and money_res[0] > 0.0:
                            amt_decimal, raw_amt_str = money_res
                        elif "amount" in row_dict and row_dict["amount"] is not None:
                            try:
                                amt_decimal = float(row_dict["amount"])
                                raw_amt_str = str(row_dict["amount"])
                            except (ValueError, TypeError):
                                amt_decimal = 0.0
                                raw_amt_str = "0"
                        elif money_res is not None:
                            amt_decimal, raw_amt_str = money_res
                        elif "amount_micros" in row_dict and row_dict["amount_micros"]:
                            micros = int(row_dict["amount_micros"])
                            amt_decimal = float(micros) / 1_000_000.0
                            raw_amt_str = f"{micros} micros"
                        elif "amount_paise" in row_dict and row_dict["amount_paise"]:
                            paise = int(row_dict["amount_paise"])
                            amt_decimal = float(paise) / 100.0
                            raw_amt_str = f"{paise} paise"
                        else:
                            amt_decimal = 0.0
                            raw_amt_str = "0"

                        utr_val = col_utr or _find_utr_in_proto(pb_dict)

                        tx_rec = UPIAppSandboxTransaction(
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=source_vfs_file_id,
                            source_subsystem="GPAY_STREAM_ITEMS_PROTO",
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            amount_inr_decimal=amt_decimal,
                            raw_amount_value=raw_amt_str,
                            instrument_mode=UPIInstrumentMode.UPI_BANK_ACCOUNT.value,
                            tx_direction=UPITransactionDirection.DEBIT_SENT.value,
                            app_recorded_status=status_val,
                            utr_12_digit=str(utr_val) if utr_val else None,
                            app_order_or_tx_id=str(item_id) if item_id else None,
                            payer_vpa=payer_vpa,
                            payee_vpa=payee_vpa,
                            counterparty_display_name=display_name,
                            counterparty_verified_cbs_name=banking_name,
                            counterparty_phone_number=phone,
                            created_utc_iso=created_iso,
                        )
                        transactions.append(tx_rec)

        finally:
            con.close()

        return transactions, chats
