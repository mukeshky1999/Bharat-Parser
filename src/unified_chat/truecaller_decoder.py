"""
Sub-Engine 5.5A: Truecaller Deep Decoder & Global Unsaved Caller-ID Cache.
Parses Truecaller tc.db and msg.db, unmasking crowd-sourced caller names, spam scores, and IM messages.
Complies with Section 3 of Phase 5 Module 5.5 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.unified_chat.models import (
    SpecialChannelCategory,
    TruecallerEnrichmentRecord,
    RegionalMarketplaceRecord,
    canonical_phone_10_and_e164,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix milliseconds into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TruecallerDecoder:
    """Decoder for Truecaller tc.db (Caller ID cache) and msg.db (IM/SMS/Flash)."""

    def decode_truecaller_database(
        self,
        db_path: str,
        device_contacts_e164: Optional[Set[str]] = None,
        source_vfs_file_id: int = 701,
    ) -> List[TruecallerEnrichmentRecord]:
        """Extracts cached Truecaller Caller-ID lookups from tc.db."""
        enrich_records: List[TruecallerEnrichmentRecord] = []
        if not os.path.exists(db_path):
            return enrich_records

        known_contacts = device_contacts_e164 or set()

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            for tbl in ["aggregated_contact", "raw_contact", "data"]:
                if tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({tbl})")
                        cols = [r[1] for r in cur.fetchall()]

                        num_col = "normalized_number" if "normalized_number" in cols else ("number" if "number" in cols else "phone")
                        name_col = "contact_name" if "contact_name" in cols else ("name" if "name" in cols else "display_name")
                        spam_col = "spam_score" if "spam_score" in cols else "0"
                        carr_col = "carrier" if "carrier" in cols else "NULL"
                        email_col = "email" if "email" in cols else "NULL"
                        city_col = "city_area" if "city_area" in cols else "NULL"

                        if num_col in cols and name_col in cols:
                            q = f"SELECT {num_col}, {name_col}, {spam_col}, {carr_col}, {email_col}, {city_col} FROM {tbl}"
                            cur.execute(q)
                            for p_raw, name_raw, spam_val, carr_val, email_val, city_val in cur.fetchall():
                                if not p_raw or not name_raw:
                                    continue

                                e164, tail10 = canonical_phone_10_and_e164(str(p_raw))
                                if not e164:
                                    continue

                                is_saved = 1 if (e164 in known_contacts or (tail10 and any(tail10 in c for c in known_contacts))) else 0
                                spam_score = int(spam_val) if spam_val else 0

                                carr_circle = carr_val
                                if city_val and carr_val:
                                    carr_circle = f"{carr_val} — {city_val}"
                                elif city_val:
                                    carr_circle = str(city_val)

                                rec = TruecallerEnrichmentRecord(
                                    normalized_e164_phone=e164,
                                    subscriber_10_tail=tail10,
                                    tc_resolved_name=str(name_raw),
                                    is_saved_in_device_contacts=is_saved,
                                    tc_spam_score=spam_score,
                                    tc_carrier_and_circle=carr_circle,
                                    tc_extracted_email_or_vpa=str(email_val) if email_val else None,
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                )
                                enrich_records.append(rec)
                    except Exception as exc:
                        logger.debug("Failed reading %s in Truecaller tc.db: %s", tbl, exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Truecaller tc.db %s: %s", db_path, exc)

        return enrich_records

    def decode_truecaller_messages(
        self,
        db_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 701,
    ) -> List[RegionalMarketplaceRecord]:
        """Parses Truecaller msg.db for IM, SMS, and Flash messages."""
        msg_records: List[RegionalMarketplaceRecord] = []
        if not os.path.exists(db_path):
            return msg_records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            if "messages" in tables:
                try:
                    cur.execute("PRAGMA table_info(messages)")
                    cols = [r[1] for r in cur.fetchall()]
                    m_id_col = "_id" if "_id" in cols else "id"
                    txt_col = "text" if "text" in cols else ("body" if "body" in cols else "NULL")
                    date_col = "date" if "date" in cols else "0"
                    trans_col = "transport" if "transport" in cols else "0"

                    cur.execute(f"SELECT {m_id_col}, {txt_col}, {date_col}, {trans_col} FROM messages")
                    for mid, txt, dt_val, trans in cur.fetchall():
                        ts_ms = int(dt_val) if dt_val else 0
                        sent_ns = ts_ms * 1_000_000
                        sent_iso = _format_utc_iso_ms(ts_ms)

                        rec = RegionalMarketplaceRecord(
                            channel_category=SpecialChannelCategory.TRUECALLER_IM_OR_FLASH,
                            app_name="Truecaller",
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            thread_or_document_id=str(mid),
                            message_or_mutation_text=str(txt) if txt else "",
                            event_utc_ns=sent_ns,
                            event_utc_iso=sent_iso,
                        )
                        msg_records.append(rec)
                except Exception as exc:
                    logger.debug("Failed querying messages in Truecaller msg.db: %s", exc)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening Truecaller msg.db %s: %s", db_path, exc)

        return msg_records
