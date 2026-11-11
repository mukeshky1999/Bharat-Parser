"""
Sub-Engine 3.3A / Section 7.2: Cardless ATM Cash-Out Token Correlator.
Correlates 6-digit Cardless ATM withdrawal tokens (YONO Cash, ICICI Cardless, IMT)
with outbound chat and SMS communications (WhatsApp, Telegram, Signal, mmssms.db)
to attribute suspected field cash-out runners.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7.2 of Module 3.3 Spec.
"""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import List, Optional, Union

from src.banking.models import CardlessATMOrPDFRecord


class CardlessRunnerCorrelator:
    """Correlates ATM cash-out reference numbers with outbound messages to identify field runners."""

    def normalize_phone_number(self, raw_jid_or_addr: Optional[str]) -> Optional[str]:
        """Normalizes WhatsApp JID or phone number string to E.164 +91 format."""
        if not raw_jid_or_addr:
            return None
        clean = raw_jid_or_addr.split("@")[0].strip().replace("-", "").replace(" ", "")
        if clean.startswith("+"):
            return clean
        if len(clean) == 10 and clean.isdigit():
            return f"+91{clean}"
        if len(clean) == 12 and clean.startswith("91") and clean.isdigit():
            return f"+{clean}"
        return clean

    def parse_iso_to_unix_ms(self, iso_str: Optional[str]) -> Optional[int]:
        """Parses UTC ISO-8601 string to Unix epoch milliseconds."""
        if not iso_str:
            return None
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            return None

    def find_runner_recipient_for_cardless_token(
        self,
        token_record: CardlessATMOrPDFRecord,
        chat_db_paths: List[Union[str, Path]],
    ) -> Optional[str]:
        """
        Searches chat databases for outbound messages containing the cardless reference token
        within the 4-hour validity window following token generation.
        """
        ref_id = token_record.cardless_ref_id_or_pdf_name.strip()
        if not ref_id:
            return None

        event_ms = self.parse_iso_to_unix_ms(token_record.event_utc_iso)
        window_end_ms = (event_ms + 4 * 3600 * 1000) if event_ms is not None else None

        for db_file in chat_db_paths:
            db_path = Path(db_file)
            if not db_path.exists():
                continue

            conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            try:
                # Check tables
                cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('messages', 'sms', 'message');"
                )
                tables = [r["name"] for r in cur.fetchall()]

                # Case A: WhatsApp messages table
                if "messages" in tables:
                    cur.execute(
                        "SELECT key_remote_jid, data, timestamp, from_me FROM messages WHERE data LIKE ?;",
                        (f"%{ref_id}%",),
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        col_keys = r.keys()
                        from_me = r["from_me"] if "from_me" in col_keys else 1
                        if from_me != 1:
                            continue

                        ts = r["timestamp"] if "timestamp" in col_keys else 0
                        # Filter timestamp window if available
                        if event_ms is not None and window_end_ms is not None and ts > 0:
                            if not (event_ms - 60000 <= ts <= window_end_ms):
                                continue

                        jid = r["key_remote_jid"] if "key_remote_jid" in col_keys else None
                        normalized = self.normalize_phone_number(jid)
                        if normalized:
                            conn.close()
                            return normalized

                # Case B: mmssms.db sms table
                if "sms" in tables:
                    cur.execute(
                        "SELECT address, body, date, type FROM sms WHERE body LIKE ?;",
                        (f"%{ref_id}%",),
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        col_keys = r.keys()
                        msg_type = r["type"] if "type" in col_keys else 2
                        if msg_type != 2:
                            continue

                        ts = r["date"] if "date" in col_keys else 0
                        if event_ms is not None and window_end_ms is not None and ts > 0:
                            if not (event_ms - 60000 <= ts <= window_end_ms):
                                continue

                        addr = r["address"] if "address" in col_keys else None
                        normalized = self.normalize_phone_number(addr)
                        if normalized:
                            conn.close()
                            return normalized

            finally:
                conn.close()

        return None
