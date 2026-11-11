"""
Sub-Engine 4.2C: Domestic Indian FIU-IND Registered Exchanges Decoder.
Parses CoinDCX, CoinSwitch, Mudrex, ZebPay, Flitpay, and WazirX sandboxes.
Extracts Indian 10-char PAN, Aadhaar KYC reference, penny-drop bank account + IFSC,
and Section 194S 1% VDA TDS transaction records.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.cex.models import (
    CEXAccountProfileRecord,
    CEXComplianceTier,
    CEXTransferCategory,
    CEXTransferRecord,
)


class IndianCEXDecoder:
    """Decoder for domestic Indian FIU-IND registered exchange sandboxes."""

    def __init__(self) -> None:
        self.supported_platforms = (
            "CoinDCX",
            "CoinSwitch",
            "Mudrex",
            "ZebPay",
            "Flitpay",
            "WazirX",
            "Giottus",
            "SunCrypto",
            "Delta Exchange",
            "Pi42",
        )

    def decode_sandbox(
        self,
        db_path: str,
        source_vfs_file_id: int = 0,
        exchange_name: str = "CoinDCX",
    ) -> Dict[str, Any]:
        """
        Parses SQLite database of an Indian FIU-IND registered exchange.
        Returns dict containing 'accounts' and 'transfers'.
        """
        accounts: List[CEXAccountProfileRecord] = []
        transfers: List[CEXTransferRecord] = []

        if not os.path.exists(db_path):
            return {"accounts": accounts, "transfers": transfers}

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Step 1: Detect tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]

        # Step 2: Parse KYC & Profile
        profile_tables = [
            t for t in tables if any(k in t.lower() for k in ["profile", "user", "kyc", "account"])
        ]
        for tbl in profile_tables:
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            cols = {col["name"].lower(): col["name"] for col in cursor.fetchall()}

            pan_col = cols.get("pan") or cols.get("pan_number") or cols.get("pan_no")
            name_col = cols.get("full_name") or cols.get("name") or cols.get("user_name")
            uid_col = cols.get("user_id") or cols.get("uid") or cols.get("id")
            aadhaar_col = cols.get("aadhaar_ref") or cols.get("aadhaar")
            bank_col = cols.get("bank_account") or cols.get("account_number")
            ifsc_col = cols.get("bank_ifsc") or cols.get("ifsc")

            cursor.execute(f"SELECT * FROM [{tbl}]")
            for row in cursor.fetchall():
                user_id_val = str(row[uid_col] or "indian_cex_user") if uid_col else "indian_cex_user"
                pan_val = str(row[pan_col] or "") if pan_col else None
                name_val = str(row[name_col] or "") if name_col else None
                aadhaar_val = str(row[aadhaar_col] or "") if aadhaar_col else None

                bank_acc = str(row[bank_col] or "") if bank_col else None
                bank_ifsc = str(row[ifsc_col] or "") if ifsc_col else None

                linked_banks = []
                if bank_acc or bank_ifsc:
                    linked_banks.append({
                        "bank_account": bank_acc or "",
                        "bank_ifsc": bank_ifsc or "",
                    })

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{db_path}::{tbl}::{user_id_val}",
                    forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
                )

                acc_rec = CEXAccountProfileRecord(
                    exchange_name=exchange_name,
                    fiu_ind_compliance_tier=CEXComplianceTier.INDIAN_DOMESTIC_FIU_REGISTERED,
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    cex_user_uid=user_id_val,
                    kyc_verified_full_name=name_val,
                    indian_pan_10_char=pan_val,
                    aadhaar_or_passport_id=aadhaar_val,
                    linked_indian_banks_vpas_json=json.dumps(linked_banks) if linked_banks else None,
                    evidentiary_state=ev_state,
                )
                accounts.append(acc_rec)

        # Step 3: Parse Trades & 1% TDS Records
        trade_tables = [
            t for t in tables if any(k in t.lower() for k in ["trade", "order", "vda", "tds"])
        ]
        for tbl in trade_tables:
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            cols = {col["name"].lower(): col["name"] for col in cursor.fetchall()}

            id_col = cols.get("trade_id") or cols.get("order_id") or cols.get("id")
            asset_col = cols.get("asset") or cols.get("currency") or cols.get("coin")
            amt_col = cols.get("trade_amount") or cols.get("amount") or cols.get("total")
            tds_col = cols.get("tds_amount") or cols.get("tds") or cols.get("tds_inr")
            time_col = cols.get("trade_time") or cols.get("timestamp") or cols.get("time")

            cursor.execute(f"SELECT * FROM [{tbl}]")
            for row in cursor.fetchall():
                tx_id = str(row[id_col] or "VDA_TX") if id_col else "VDA_TX"
                asset_val = str(row[asset_col] or "USDT") if asset_col else "USDT"
                amt_val = float(row[amt_col] or 0.0) if amt_col else 0.0
                tds_val = float(row[tds_col] or 0.0) if tds_col else None
                raw_time = row[time_col] if time_col else 0

                ts_val = int(raw_time) if raw_time else 0
                if ts_val > 10_000_000_000:
                    ts_iso = ForensicTimestamp.from_unix_milliseconds(ts_val).utc_iso8601
                elif ts_val > 0:
                    ts_iso = ForensicTimestamp.from_unix_seconds(ts_val).utc_iso8601
                else:
                    ts_iso = datetime.now(timezone.utc).isoformat()

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{db_path}::{tbl}::{tx_id}",
                    forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
                )

                category = (
                    CEXTransferCategory.VDA_SPOT_TRADE_WITH_1PCT_TDS
                    if tds_val is not None
                    else CEXTransferCategory.ONCHAIN_CRYPTO_DEPOSIT
                )

                tr_rec = CEXTransferRecord(
                    exchange_name=exchange_name,
                    source_vfs_file_id=source_vfs_file_id,
                    transfer_category=category,
                    asset_or_currency=asset_val,
                    amount_decimal=amt_val,
                    tds_1pct_deducted_inr=tds_val,
                    txid_or_internal_pay_order_id=tx_id,
                    transfer_utc_iso=ts_iso,
                    evidentiary_state=ev_state,
                )
                transfers.append(tr_rec)

        conn.close()
        return {"accounts": accounts, "transfers": transfers}
