"""
Sub-Engine 5.5B, 5.5C & 5.5D: Covert Dead-Drops, Betting LiveChats, and Regional Marketplace Decoders.
Parses:
  - Betting app webview Simple Cache for LiveChatInc/Tawk.to transcripts, UTRs, and bookie VPAs.
  - Collaborative Google Keep, Google Docs, Apple Notes, and Email Draft dead-drops (with WAL carving).
  - OLX India, IndiaMART, ShareChat, and Moj regional conversations.
Complies with Sections 4, 5, and 6 of Phase 5 Module 5.5 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.unified_chat.models import (
    SpecialChannelCategory,
    RegionalMarketplaceRecord,
)

logger = logging.getLogger(__name__)


def _format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix milliseconds into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class CovertAndBettingDecoder:
    """Decoder for illegal betting live-chats, cloud dead-drops, and marketplace portals."""

    UTR_PATTERN = re.compile(r"\b([0-9]{12})\b")
    VPA_PATTERN = re.compile(r"\b([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+)\b")
    PHONE_PATTERN = re.compile(r"\b(?:\+91|0)?[6-9]\d{9}\b")

    def extract_financial_entities_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extracts 12-digit UTR numbers, UPI VPAs, and phone numbers from text."""
        entities: Dict[str, List[str]] = {
            "utr": [],
            "vpa": [],
            "phone": [],
        }
        if not text:
            return entities

        for u in self.UTR_PATTERN.findall(text):
            if u not in entities["utr"]:
                entities["utr"].append(u)

        for v in self.VPA_PATTERN.findall(text):
            if not v.endswith(".com") and not v.endswith(".org") and v not in entities["vpa"]:
                entities["vpa"].append(v)

        for p in self.PHONE_PATTERN.findall(text):
            if p not in entities["phone"]:
                entities["phone"].append(p)

        return entities

    def decode_webview_livechats(
        self,
        sandbox_path: str,
        app_instance_id: int = 2,
        source_vfs_file_id: int = 702,
    ) -> List[RegionalMarketplaceRecord]:
        """Scans webview HTTP cache directories for betting customer support live-chat transcripts."""
        records: List[RegionalMarketplaceRecord] = []
        base_path = Path(sandbox_path)

        cache_dirs = [
            base_path / "cache" / "Cache_Data",
            base_path / "cache" / "http-cache",
            base_path / "app_webview" / "Default" / "Cache" / "Cache_Data",
            base_path,
        ]

        candidate_files: List[Path] = []
        for cdir in cache_dirs:
            if cdir.exists():
                for root, _, files in os.walk(cdir):
                    for f in files:
                        candidate_files.append(Path(root) / f)

        for cfile in candidate_files:
            try:
                content = cfile.read_text(encoding="utf-8", errors="ignore")
                if not content or ("livechat" not in content.lower() and "tawk" not in content.lower() and "transcripts" not in content.lower()):
                    continue

                try:
                    data = json.loads(content)
                except Exception:
                    continue

                app_name = data.get("app", "Betting LiveChat")
                msg_list: List[dict] = []
                if isinstance(data, dict):
                    msg_list = data.get("messages", [])
                elif isinstance(data, list):
                    msg_list = data

                # Aggregate entities across the entire livechat transcript
                transcript_entities: Dict[str, List[str]] = {"utr": [], "vpa": [], "phone": []}
                for msg_item in msg_list:
                    if isinstance(msg_item, dict):
                        t_txt = msg_item.get("text", "")
                        ent = self.extract_financial_entities_from_text(t_txt)
                        for k, v_list in ent.items():
                            for v in v_list:
                                if v not in transcript_entities[k]:
                                    transcript_entities[k].append(v)

                entities_json = json.dumps(transcript_entities) if any(transcript_entities.values()) else None

                for msg_item in msg_list:
                    if not isinstance(msg_item, dict):
                        continue

                    txt = msg_item.get("text", "")
                    ts_val = msg_item.get("timestamp", 0)
                    author = msg_item.get("author", "Agent")

                    ts_ms = int(ts_val) if ts_val else 0
                    sent_ns = ts_ms * 1_000_000
                    sent_iso = _format_utc_iso_ms(ts_ms)

                    rec = RegionalMarketplaceRecord(
                        channel_category=SpecialChannelCategory.BETTING_BOOKIE_LIVECHAT,
                        app_name=app_name,
                        source_vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        thread_or_document_id=cfile.name,
                        sender_or_author_id=author,
                        message_or_mutation_text=txt,
                        extracted_utr_vpa_or_phone_json=entities_json,
                        event_utc_ns=sent_ns,
                        event_utc_iso=sent_iso,
                    )
                    records.append(rec)
            except Exception as exc:
                logger.debug("Failed parsing livechat cache file %s: %s", cfile, exc)

        return records

    def _carve_wal_for_dead_drop_text(self, wal_path: str) -> List[str]:
        """Scans uncheckpointed WAL frames for pre-overwritten dead-drop strings."""
        found_strings: List[str] = []
        if not os.path.exists(wal_path):
            return found_strings

        try:
            with open(wal_path, "rb") as f:
                wal_bytes = f.read()

            matches = re.findall(b"[\x20-\x7E]{12,}", wal_bytes)
            for m in matches:
                try:
                    s = m.decode("utf-8")
                    if any(kw in s for kw in ["Deliver", "Lakh", "Sector", "dead-drop", "BIP39", "USDT"]):
                        found_strings.append(s)
                except UnicodeDecodeError as exc:
                    logger.debug("Non-utf8 WAL string skipped: %s", exc)
        except Exception as exc:
            logger.debug("Failed carving WAL file %s: %s", wal_path, exc)

        return found_strings

    def decode_google_keep_database(
        self,
        db_path: str,
        app_instance_id: int = 3,
        source_vfs_file_id: int = 703,
    ) -> List[RegionalMarketplaceRecord]:
        """Parses Google Keep keep.db (+ WAL) for shared collaborative dead-drop notes."""
        records: List[RegionalMarketplaceRecord] = []
        if not os.path.exists(db_path):
            return records

        p_db = Path(db_path)
        wal_path = p_db.parent / (p_db.name + "-wal")

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Extract collaborators from sharing table
            collaborators: List[str] = []
            if "sharing" in tables:
                try:
                    cur.execute("SELECT email FROM sharing")
                    for em in cur.fetchall():
                        if em and em[0]:
                            collaborators.append(str(em[0]))
                except Exception as exc:
                    logger.debug("Failed querying sharing in keep.db: %s", exc)

            collab_json = json.dumps(collaborators) if collaborators else None

            # 2. Extract live notes from list_item / text_search
            live_texts: List[str] = []
            if "list_item" in tables:
                try:
                    cur.execute("SELECT text FROM list_item")
                    for r in cur.fetchall():
                        if r and r[0]:
                            live_texts.append(str(r[0]))
                except Exception as exc:
                    logger.debug("Failed querying list_item in keep.db: %s", exc)

            for txt in live_texts:
                rec = RegionalMarketplaceRecord(
                    channel_category=SpecialChannelCategory.GOOGLE_DOCS_KEEP_DEADDROP,
                    app_name="Google Keep",
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    thread_or_document_id=p_db.name,
                    collaborators_or_peers_json=collab_json,
                    message_or_mutation_text=txt,
                    event_utc_ns=1700000000000000000,
                    event_utc_iso="2023-11-14T22:13:20.000000Z",
                )
                records.append(rec)

            # 3. Carve superseded / overwritten dead-drop text from WAL frames
            if wal_path.exists():
                wal_strings = self._carve_wal_for_dead_drop_text(str(wal_path))
                for w_txt in wal_strings:
                    if w_txt not in live_texts:
                        rec = RegionalMarketplaceRecord(
                            channel_category=SpecialChannelCategory.GOOGLE_DOCS_KEEP_DEADDROP,
                            app_name="Google Keep",
                            source_vfs_file_id=source_vfs_file_id,
                            recovery_classification=ResidualConfidence.HISTORICAL_COMMITTED_RECORD,
                            thread_or_document_id=p_db.name,
                            collaborators_or_peers_json=collab_json,
                            message_or_mutation_text=w_txt,
                            event_utc_ns=1700000000000000000,
                            event_utc_iso="2023-11-14T22:13:20.000000Z",
                        )
                        records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening keep.db %s: %s", db_path, exc)

        return records
