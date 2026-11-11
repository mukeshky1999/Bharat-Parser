"""
Sub-Engine 3.4D: OS Financial Notification Ledgers Parser.
Extracts push notifications across iOS DuetExpertCenter (metadata only),
Apple Biome streams, and Android Notification History archives.
Adheres strictly to AGENTS.md Forensic Invariants and Section 6 of Module 3.4 Spec.
"""

from pathlib import Path
import re
import sqlite3
from typing import List, Optional, Union

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.dlt.models import NotificationSubsystem, OSFinancialNotificationRecord


class OSNotificationParser:
    """Parses iOS and Android push notification stores for financial and payment app events."""

    FINANCIAL_APP_PATTERNS = (
        "phonepe",
        "paisa",
        "paytm",
        "bhim",
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "kotak",
        "cred",
        "navi",
        "super.money",
        "airtel",
        "ippb",
        "spicemoney",
        "paynearby",
    )

    UTR_REGEX = re.compile(r"\b(\d{12})\b")
    AMOUNT_REGEX = re.compile(r"(?:Rs\.?|INR|₹)\s*[:\-]?\s*([0-9,]+(?:\.[0-9]{1,2})?)", re.IGNORECASE)

    def is_financial_package(self, pkg_or_bundle: Optional[str]) -> bool:
        """Determines if a bundle ID or package name belongs to a financial application."""
        if not pkg_or_bundle:
            return False
        clean = pkg_or_bundle.lower()
        return any(pat in clean for pat in self.FINANCIAL_APP_PATTERNS)

    def parse_ios_duet_expert_center(
        self,
        db_path: Union[str, Path],
        source_vfs_file_id: int = 601,
    ) -> List[OSFinancialNotificationRecord]:
        """
        Parses iOS /private/var/mobile/Library/DuetExpertCenter/streams/notificationAndSuggestionDB.db.
        Extracts delivery timestamp, bundle ID, and user engagement metadata.
        Mandatory Forensic Invariant: is_metadata_only_no_body is set to 1.
        """
        target = Path(db_path)
        if not target.exists():
            return []

        records: List[OSFinancialNotificationRecord] = []
        conn = sqlite3.connect(f"file:{target.resolve()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notifications';")
            if not cur.fetchone():
                conn.close()
                return []

            cur.execute("SELECT * FROM notifications;")
            rows = cur.fetchall()

            for r in rows:
                col_keys = r.keys()
                bundle_id = None
                for b_col in ("app_bundle_id", "bundle_id", "source_id"):
                    if b_col in col_keys and r[b_col]:
                        bundle_id = str(r[b_col]).strip()
                        break

                if not bundle_id or not self.is_financial_package(bundle_id):
                    continue

                ts_val = None
                for t_col in ("timestamp", "creation_date", "date"):
                    if t_col in col_keys and r[t_col] is not None:
                        ts_val = float(r[t_col])
                        break

                utc_iso = "1970-01-01T00:00:00.000000Z"
                if ts_val is not None:
                    # Apple Cocoa seconds since 2001-01-01
                    utc_iso = ForensicTimestamp.from_cocoa_seconds(ts_val).utc_iso8601

                user_state = "DELIVERED"
                for s_col in ("user_engagement", "engagement", "category_id", "action"):
                    if s_col in col_keys and r[s_col]:
                        user_state = str(r[s_col]).strip()
                        break

                rec = OSFinancialNotificationRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    notification_subsystem=NotificationSubsystem.IOS_DUET_EXPERT_CENTER.value,
                    target_app_bundle_or_pkg=bundle_id,
                    delivered_utc_iso=utc_iso,
                    is_metadata_only_no_body=1,
                    notif_title_text=None,
                    notif_body_text=None,
                    extracted_amount_inr=None,
                    extracted_utr_reference=None,
                    user_interaction_state=user_state,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
                records.append(rec)

        finally:
            conn.close()

        return records

    def parse_android_notification_record(
        self,
        package_name: str,
        title: Optional[str],
        text: Optional[str],
        posted_ms: Optional[int],
        source_vfs_file_id: int = 602,
    ) -> Optional[OSFinancialNotificationRecord]:
        """
        Parses an Android Notification History record or bugreport dumpsys notification entry.
        """
        if not self.is_financial_package(package_name):
            return None

        body_str = text or ""
        amt: Optional[float] = None
        amt_match = self.AMOUNT_REGEX.search(body_str)
        if amt_match:
            try:
                amt = float(amt_match.group(1).replace(",", "").strip())
            except ValueError:
                amt = None

        utr: Optional[str] = None
        utr_match = self.UTR_REGEX.search(body_str)
        if utr_match:
            utr = utr_match.group(1)

        utc_iso = "1970-01-01T00:00:00.000000Z"
        if posted_ms is not None and posted_ms > 0:
            utc_iso = ForensicTimestamp.from_unix_milliseconds(posted_ms).utc_iso8601

        return OSFinancialNotificationRecord(
            source_vfs_file_id=source_vfs_file_id,
            notification_subsystem=NotificationSubsystem.ANDROID_NOTIF_HISTORY_PROTO.value,
            target_app_bundle_or_pkg=package_name,
            delivered_utc_iso=utc_iso,
            is_metadata_only_no_body=0,
            notif_title_text=title,
            notif_body_text=text,
            extracted_amount_inr=amt,
            extracted_utr_reference=utr,
            user_interaction_state="POSTED",
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        )
