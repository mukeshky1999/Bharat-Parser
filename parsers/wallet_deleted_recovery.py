"""
parsers/wallet_deleted_recovery.py

Applies the existing freelist_carver and wal_rollback_analyzer to wallet DBs,
with wallet-specific record extraction rules.

Reuses:
  - parsers.freelist_carver.carve_sqlite_freelists
  - parsers.wal_rollback_analyzer.analyze_wal_revisions

Both are called with the wallet DB path and their output is reclassified
into wallet Data_Class rows.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from parsers.custodial_wallet_parser import (
    _empty_record,
    detect_chain_from_address,
    _normalize_timestamp,
    compute_risk_badge,
)

try:
    from fs_handler import _log_forensic_error
except Exception:  # pragma: no cover
    def _log_forensic_error(c, e):
        logging.getLogger("parsers.wallet").warning("Forensic error in %s: %s", c, e)


_TXHASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$|^[a-fA-F0-9]{64}$|^[1-9A-HJ-NP-Za-km-z]{86,90}$")
_ORDERID_RE = re.compile(r"^[A-Z0-9]{6,32}$")


def _walletize_carved_rows(
    carved_rows: List[Dict[str, Any]],
    app_label: str,
    source_artifact: str,
    recovery_method: str,
) -> List[Dict[str, Any]]:
    """Convert generic carved rows into wallet Data_Class records."""
    out = []
    for row in carved_rows:
        addr = row.get("Counterparty") or row.get("address") or ""
        addr_str = str(addr) if addr else ""
        chain = detect_chain_from_address(addr_str) if addr_str else None
        if not chain:
            continue  # not a wallet-shaped carved row

        direction = row.get("Direction") or row.get("Type") or "UNKNOWN"
        direction = str(direction).upper()
        if "DEBIT" in direction or "SEND" in direction:
            direction = "WITHDRAWAL"
        elif "CREDIT" in direction or "RECEIVE" in direction:
            direction = "DEPOSIT"
        else:
            direction = "UNKNOWN"

        r = _empty_record(app_label, source_artifact, direction)
        r["Recovery_Method"] = recovery_method
        r["Direction"] = direction
        r["Chain"] = chain
        r["Counterparty_Address"] = addr_str
        r["Address_Type"] = "COUNTERPARTY"
        if row.get("Amount") is not None:
            try:
                r["Amount_Crypto"] = float(row["Amount"])
            except (TypeError, ValueError):
                pass
        if row.get("Date"):
            r["Timestamp_UTC"] = _normalize_timestamp(row["Date"])
        txid = row.get("Transaction_ID") or ""
        if txid and _TXHASH_RE.match(str(txid)):
            r["TxHash"] = str(txid)
        elif txid and _ORDERID_RE.match(str(txid)):
            r["Order_ID"] = str(txid)
        r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
        out.append(r)
    return out


def recover_deleted_wallet_records(
    db_path: str,
    app_label: str,
) -> pd.DataFrame:
    """
    Returns deleted / previous-version wallet records recovered from
    freelist pages and WAL frames. Never raises.
    """
    rows: List[Dict[str, Any]] = []

    # Freelist carving
    try:
        from parsers.freelist_carver import carve_sqlite_freelists
        carved = carve_sqlite_freelists(db_path, allow_crypto_addresses=True)
        carved_list = carved.to_dict(orient="records") if isinstance(carved, pd.DataFrame) else carved
        if carved_list:
            rows.extend(_walletize_carved_rows(
                carved_list, app_label,
                f"{Path(db_path).name}::freelist",
                "DELETED (Freelist Carved)",
            ))
    except Exception as e:
        _log_forensic_error(f"wallet.freelist.{app_label}", e)

    # WAL rollback
    try:
        from parsers.wal_rollback_analyzer import analyze_wal_revisions
        wal_path = str(db_path) + "-wal"
        target_wal = wal_path if Path(wal_path).exists() else db_path
        wal_rows = analyze_wal_revisions(target_wal, allow_crypto_addresses=True)
        wal_list = wal_rows.to_dict(orient="records") if isinstance(wal_rows, pd.DataFrame) else wal_rows
        if wal_list:
            rows.extend(_walletize_carved_rows(
                wal_list, app_label,
                f"{Path(db_path).name}::wal",
                "WAL Rollback Revision",
            ))
    except Exception as e:
        _log_forensic_error(f"wallet.wal.{app_label}", e)

    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)
