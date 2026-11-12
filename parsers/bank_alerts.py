"""
Bank alerts (IN TESTING): bank and SMS notices read from a phone's SMS database.

What it reads
* Android: a database with an ``sms`` table (``mmssms.db``, a Messages-app copy). Received messages only (type 1); when the
  table has no ``type`` column every message is read and the record says sent and received were not told apart.
* iOS: ``sms.db`` (``message`` joined to ``handle``). Received messages only. When ``text`` is empty the message body
  is unpacked from ``attributedBody``.
Found by what the database contains, not by its file name.

What it says about each message, using the ``src/dlt`` rules
* who sent it: the sender header resolved to an institution when the header is one the tool knows, otherwise "not resolved";
* what kind of notice it looks like (debit, credit, cash withdrawal, new beneficiary, one-time code, lien or freeze,
  device binding, autopay, failed payment, or not classified) and the amount, balance, account tail, reference and
  counterparty the wording gives;
* a "sent without a service-centre number" indicator on Android: it is an indicator, not proof of a forged message, and
  it is left empty when the database does not store the fields it needs.

What it does not do
* It does not say a message is genuine. The category is the tool's reading of the wording.
* Promotional messages are counted and left out; a message of no recognised kind is kept only when its sender header
  is a bank or service the tool recognises.
* An unknown time stays empty; it is never filled with a default.

This reader has been run on synthetic databases only. It has not been tested on real bank and SMS data, and the screens
say so.
"""
from __future__ import annotations

import os
import re
import pathlib
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from src.dlt.attributed_body import IOSAttributedBodyUnpacker
from src.dlt.dlt_headers import DLTHeaderParser
from src.dlt.models import FinancialSMSCategory
from src.dlt.sms_grammar import FinancialSMSGrammarParser

STATUS_NOTE = "In testing: read with the tool's SMS rules, run on synthetic data only, not yet tested on real bank and SMS data."
DECODER = "src.dlt (DLT header + SMS grammar) via parsers.bank_alerts, in testing"

COLUMNS = [
    "Received_UTC", "Received_IST", "Received_Raw", "Sender", "Institution", "Category", "Amount", "Balance", "Account_Masked",
    "Payment_Rail", "UTR", "Counterparty", "Code_Or_Location", "Spoof_Indicator", "Smsc_Number", "Sim_Sub_Id", "Message_Body",
    "Source_File", "Source_Db", "Application", "Forensic_Provenance",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS bank_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Received_UTC TEXT,
    Received_IST TEXT,
    Received_Raw TEXT,
    Sender TEXT,
    Institution TEXT,
    Category TEXT,
    Amount REAL,
    Balance REAL,
    Account_Masked TEXT,
    Payment_Rail TEXT,
    UTR TEXT,
    Counterparty TEXT,
    Code_Or_Location TEXT,
    Spoof_Indicator INTEGER,
    Smsc_Number TEXT,
    Sim_Sub_Id INTEGER,
    Message_Body TEXT,
    Source_File TEXT,
    Source_Db TEXT,
    Application TEXT,
    Forensic_Provenance TEXT
);
CREATE INDEX IF NOT EXISTS idx_bank_alerts_cat ON bank_alerts(Category);
CREATE INDEX IF NOT EXISTS idx_bank_alerts_ist ON bank_alerts(Received_IST);
CREATE VIRTUAL TABLE IF NOT EXISTS bank_alerts_fts USING fts5(
    Sender, Institution, Category, Account_Masked, UTR, Counterparty, Message_Body, Forensic_Provenance,
    content='bank_alerts', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS trg_bank_alerts_ai AFTER INSERT ON bank_alerts BEGIN
    INSERT INTO bank_alerts_fts(rowid, Sender, Institution, Category, Account_Masked, UTR, Counterparty, Message_Body, Forensic_Provenance)
    VALUES (new.id, new.Sender, new.Institution, new.Category, new.Account_Masked, new.UTR, new.Counterparty, new.Message_Body, new.Forensic_Provenance);
END;
"""

_TRANSACTION_CATEGORIES = {
    FinancialSMSCategory.TX_DEBIT_OUTFLOW.value, FinancialSMSCategory.TX_CREDIT_INFLOW.value,
    FinancialSMSCategory.ATM_CASH_WITHDRAWAL.value, FinancialSMSCategory.FAILED_OR_DECLINED_TX.value,
    FinancialSMSCategory.UPI_AUTOPAY_OR_MANDATE.value,
}

_header = DLTHeaderParser()
_grammar = FinancialSMSGrammarParser()
_unpacker = IOSAttributedBodyUnpacker()


def _tables(conn: sqlite3.Connection) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        out[name] = [r[1] for r in conn.execute(f'PRAGMA table_info("{name}")')]
    return out


def _ro_uri(path: str) -> str:
    """A read-only SQLite URI. as_uri() percent-encodes '#', '%' and '?' in the name, which a hand-built URI does not."""
    return pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro"


_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def sms_database_kind(path: str) -> Optional[str]:
    """'android', 'ios' or None, from the tables the database holds."""
    try:
        conn = sqlite3.connect(_ro_uri(path), uri=True)
    except sqlite3.Error:
        return None
    try:
        t = _tables(conn)
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if "sms" in t and {"address", "body"} <= set(t["sms"]):
        return "android"
    if "message" in t and "handle" in t and {"handle_id", "is_from_me"} <= set(t["message"]):
        return "ios"
    return None


def _times(raw: Any, hint: str) -> Tuple[Any, str, str]:
    from parsers.enterprise_1tb_chat_and_container_engine import format_timestamp_triplet
    return format_timestamp_triplet(raw, epoch_hint=hint)


def _row(vfs_path: str, table: str, rowid: Any, sender: str, body: str, raw_time: Any, hint: str, source_db: str, app: str,
         smsc: Optional[str], sub_id: Optional[int], spoof: Optional[int], raw_as_read: Any = None) -> Optional[Dict[str, Any]]:
    info = _header.parse_header(sender)
    f = _grammar.parse_sms(body=body, dlt_header_info=info)
    cat = f.sms_event_category
    if cat == FinancialSMSCategory.PROMOTIONAL_SPAM_IGNORED.value:
        return {"_promo": True}
    known_sender = not str(info.resolved_institution).lower().startswith("unknown")
    if cat == FinancialSMSCategory.UNCLASSIFIED.value and not known_sender:
        return None
    raw, utc, ist = _times(raw_time, hint)
    # a value the converter could not place comes back as the raw number in the time fields: that is not a time
    if not (utc and _DATE_LIKE.match(str(utc))):
        utc = None
    if not (ist and _DATE_LIKE.match(str(ist))):
        ist = None
    if raw_as_read is not None:
        raw = raw_as_read
    rail = f.payment_rail if cat in _TRANSACTION_CATEGORIES else None     # a rail is not guessed for other kinds of notice
    return {
        "Received_UTC": utc or None, "Received_IST": ist or None, "Received_Raw": None if raw is None else str(raw),
        "Sender": sender or None, "Institution": info.resolved_institution if known_sender else None, "Category": cat,
        "Amount": f.amount_inr_decimal, "Balance": f.post_tx_available_balance_inr, "Account_Masked": f.masked_account_or_card,
        "Payment_Rail": rail, "UTR": f.utr_or_rrn_reference, "Counterparty": f.counterparty_vpa_or_name,
        "Code_Or_Location": f.atm_location_or_otp_digits, "Spoof_Indicator": spoof, "Smsc_Number": smsc, "Sim_Sub_Id": sub_id,
        "Message_Body": body, "Source_File": vfs_path, "Source_Db": source_db, "Application": app,
        "Forensic_Provenance": f"{vfs_path} :: {table} :: RowID={rowid} :: State=Allocated B-Tree",
    }


def read_alerts(path: str, vfs_path: str) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """Alerts found in one SMS database, and counts: messages read, kept, promotional left out, not classified and left out."""
    stats = {"read": 0, "kept": 0, "promotional_left_out": 0, "unclassified_left_out": 0}
    kind = sms_database_kind(path)
    if kind is None:
        return pd.DataFrame(columns=COLUMNS), stats
    rows: List[Dict[str, Any]] = []
    conn = sqlite3.connect(_ro_uri(path), uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if kind == "android":
            cols = set(_tables(conn)["sms"])
            has_type = "type" in cols      # without it, sent and received messages cannot be told apart: all are read, and the record says so
            source_label = "Android sms table" if has_type else "Android sms table (no type column: sent and received not distinguished)"
            for r in conn.execute("SELECT * FROM sms" + (" WHERE type = 1" if has_type else "") + " ORDER BY " + ("_id" if "_id" in cols else "rowid")):
                body = str(r["body"]) if r["body"] else ""
                if not body.strip():
                    continue
                stats["read"] += 1
                smsc = str(r["service_center"]) if "service_center" in cols and r["service_center"] else None
                creator = str(r["creator"]) if "creator" in cols and r["creator"] else None
                # the indicator needs the service-centre or creator fields; without them it is unknown, not "suspect"
                # (and it is only meaningful for received messages: a sent one has no service centre)
                spoof: Optional[int] = None
                if has_type and ("service_center" in cols or "creator" in cols):
                    spoof = 1 if _header.detect_smsc_spoof(service_center=smsc, creator=creator, msg_type=1) else 0
                sub_id = int(r["sub_id"]) if "sub_id" in cols and r["sub_id"] is not None else None
                row = _row(vfs_path, "sms", r["_id"] if "_id" in cols else None, str(r["address"] or ""), body,
                           r["date"] if "date" in cols else None, "unix_ms", source_label, "SMS (Android)", smsc, sub_id, spoof)
                _collect(row, rows, stats)
        else:
            for r in conn.execute("SELECT m.ROWID AS rid, h.id AS sender, m.text, m.attributedBody, m.date FROM message m "
                                  "LEFT JOIN handle h ON m.handle_id = h.ROWID WHERE m.is_from_me = 0 ORDER BY m.ROWID"):
                body, source = str(r["text"]) if r["text"] else "", "iOS message.text"
                if not body.strip() and r["attributedBody"]:
                    unpacked = _unpacker.unpack(r["attributedBody"])
                    if unpacked:
                        body, source = unpacked, "iOS message.attributedBody"
                if not body.strip():
                    continue
                stats["read"] += 1
                raw = as_read = r["date"]
                if isinstance(raw, (int, float)) and raw > 10_000_000_000_000:       # Cocoa nanoseconds
                    raw = raw / 1_000_000_000.0
                row = _row(vfs_path, "message", r["rid"], str(r["sender"] or ""), body, raw, "cocoa", source, "SMS (iOS)", None, None, None,
                           raw_as_read=as_read)
                _collect(row, rows, stats)
    finally:
        conn.close()
    df = pd.DataFrame(rows, columns=COLUMNS) if rows else pd.DataFrame(columns=COLUMNS)
    return df, stats


def _collect(row: Optional[Dict[str, Any]], rows: List[Dict[str, Any]], stats: Dict[str, int]) -> None:
    if row is None:
        stats["unclassified_left_out"] += 1
    elif row.get("_promo"):
        stats["promotional_left_out"] += 1
    else:
        rows.append(row)
        stats["kept"] += 1
