"""
Sub-Engine 5.4D: Virtual Burner Number & Local Messenger Account OTP Bridge.
Extracts +1 / +44 virtual phone numbers and registration OTP codes from burner apps
(TextNow, 2ndLine, NextPlus, Hushed, Dingtone, etc.) and links them to local WhatsApp/Telegram profiles.
Complies with Section 6 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.social_voip.models import (
    BurnerBridgeRecord,
    format_utc_iso_ms,
)

logger = logging.getLogger(__name__)


def _extract_digits_only(phone: str) -> str:
    """Extracts only digit characters from a phone number string."""
    return re.sub(r"\D", "", phone or "")


class BurnerBridge:
    """Processor for virtual burner numbers and OTP cross-referencing."""

    OTP_PATTERNS = [
        ("TELEGRAM", re.compile(r"Telegram.*?code:?\s*([0-9]{4,6})", re.IGNORECASE)),
        ("WHATSAPP", re.compile(r"WhatsApp.*?code:?\s*([0-9]{3}-?[0-9]{3})", re.IGNORECASE)),
        ("SIGNAL", re.compile(r"Signal.*?code:?\s*([0-9]{5,6})", re.IGNORECASE)),
        ("GOOGLE", re.compile(r"G-([0-9]{6})", re.IGNORECASE)),
    ]

    def extract_otp_from_text(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """Extracts service name and verification OTP code from text message."""
        if not text:
            return None, None

        for svc_name, pattern in self.OTP_PATTERNS:
            match = pattern.search(text)
            if match:
                code = match.group(1).replace("-", "")
                return svc_name, code

        # Generic fallback
        generic_match = re.search(r"\b(?:code|otp|pin)\b.*?\b([0-9]{4,6})\b", text, re.IGNORECASE)
        if generic_match:
            return "GENERIC_OTP", generic_match.group(1)

        return None, None

    def process_burner_database(
        self,
        db_path: str,
        app_name: str = "TextNow",
        app_instance_id: int = 4,
        local_messenger_accounts: Optional[List[Dict[str, Any]]] = None,
    ) -> List[BurnerBridgeRecord]:
        """
        Extracts assigned virtual number, parses OTPs, and correlates with local accounts.
        """
        results: List[BurnerBridgeRecord] = []
        if not os.path.exists(db_path):
            return results

        local_accounts = local_messenger_accounts or []

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            assigned_num = None
            login_user = None

            # 1. Extract assigned number from user/numbers table
            for u_tbl in ["user", "users", "user_profile", "numbers"]:
                if u_tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({u_tbl})")
                        cols = [r[1] for r in cur.fetchall()]
                        p_col = "phone_number" if "phone_number" in cols else ("number" if "number" in cols else None)
                        u_col = "username" if "username" in cols else ("email" if "email" in cols else None)

                        if p_col:
                            cur.execute(f"SELECT {p_col}, {u_col or 'NULL'} FROM {u_tbl}")
                            row = cur.fetchone()
                            if row and row[0]:
                                assigned_num = str(row[0])
                                login_user = str(row[1]) if row[1] else None
                                break
                    except Exception as exc:
                        logger.debug("Failed querying %s in burner DB: %s", u_tbl, exc)

            if not assigned_num:
                assigned_num = "+10000000000"

            # Check correlation against local messenger accounts
            assigned_digits = _extract_digits_only(assigned_num)
            is_linked = 0
            link_details = None

            for l_acc in local_accounts:
                l_phone = l_acc.get("phone_e164", "") or l_acc.get("phone", "")
                l_digits = _extract_digits_only(str(l_phone))
                if l_digits and (l_digits == assigned_digits or assigned_digits.endswith(l_digits) or l_digits.endswith(assigned_digits)):
                    is_linked = 1
                    plat = l_acc.get("platform", "Messenger")
                    slot = l_acc.get("account_slot", "primary")
                    uname = l_acc.get("username", "")
                    link_details = f"Matches {plat.capitalize()} Slot {slot} ({assigned_num}, @{uname})"
                    break

            # 2. Extract incoming messages & OTP codes
            intercepted_any = False
            for m_tbl in ["messages", "message", "sms_messages"]:
                if m_tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({m_tbl})")
                        cols = [r[1] for r in cur.fetchall()]
                        txt_col = "message_text" if "message_text" in cols else ("text" if "text" in cols else "body")
                        date_col = "date" if "date" in cols else ("timestamp" if "timestamp" in cols else "0")

                        cur.execute(f"SELECT {txt_col}, {date_col} FROM {m_tbl}")
                        for txt_val, date_val in cur.fetchall():
                            svc, code = self.extract_otp_from_text(txt_val or "")
                            if svc and code:
                                ts_ms = int(date_val) if date_val else 0
                                if 0 < ts_ms < 10_000_000_000:
                                    ts_ms *= 1000
                                iso_ts = format_utc_iso_ms(ts_ms)

                                results.append(
                                    BurnerBridgeRecord(
                                        burner_app_name=app_name,
                                        app_instance_id=app_instance_id,
                                        assigned_virtual_number=assigned_num,
                                        burner_login_email_or_user=login_user,
                                        intercepted_otp_service=svc,
                                        intercepted_otp_code=code,
                                        otp_received_utc_iso=iso_ts,
                                        is_linked_to_local_messenger=is_linked,
                                        linked_messenger_details=link_details,
                                    )
                                )
                                intercepted_any = True
                    except Exception as exc:
                        logger.debug("Failed querying messages in burner DB: %s", exc)

            if not intercepted_any:
                # Add base burner lease record
                results.append(
                    BurnerBridgeRecord(
                        burner_app_name=app_name,
                        app_instance_id=app_instance_id,
                        assigned_virtual_number=assigned_num,
                        burner_login_email_or_user=login_user,
                        is_linked_to_local_messenger=is_linked,
                        linked_messenger_details=link_details,
                    )
                )

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening burner database %s: %s", db_path, exc)

        return results
