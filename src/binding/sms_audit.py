"""
Sub-Engine 3.2B: Outbound VMN Verification SMS & Binary Data Port Decoder.
Audits mmssms.db and bugle_db for outbound silent SMS messages sent to NPCI
and bank VMN longcodes/shortcodes, executing the 3-Way Attribution Join.
Adheres strictly to AGENTS.md Forensic Invariants and Section 4 of Module 3.2 Spec.
"""

from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Set, Union

from src.binding.models import (
    DeviceSIMCardHistoryRecord,
    NPCICommonLibraryVaultRecord,
    UPIOutboundBindingSMSAudit,
)
from src.binding.trojan_detector import GhostSIMBindingTrojanDetector
from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp


class OutboundBindingSMSDecoder:
    """Decodes and audits outbound UPI device-binding verification SMS messages."""

    KNOWN_VMN_NUMBERS: Set[str] = {
        "9223008333",
        "9289592895",
        "9266801801",
        "9212500888",
        "8422849999",
        "7065970659",
        "9211400400",
        "9870807070",
        "8657002200",
        "9223488888",
        "9289200017",
        "9215676766",
        "9971056767",
        "56161",
        "56161140",
        "56767",
    }

    KNOWN_VMN_PREFIXES = (
        "9223",
        "9289",
        "9266",
        "9212",
        "8422",
        "7065",
        "9211",
        "9870",
        "8657",
        "56161",
        "56767",
    )

    BINDING_PAYLOAD_PREFIXES = (
        "PP ",
        "UPI ",
        "VERIFY ",
        "GPay ",
        "PYTM ",
        "ACTIVATE ",
        "WA ",
        "MBSREG ",
        "VER ",
        "ACT ",
        "RSB ",
    )

    def __init__(self) -> None:
        self.trojan_detector = GhostSIMBindingTrojanDetector()

    def is_binding_vmn_destination(self, address: Optional[str]) -> bool:
        """Checks if recipient address matches known NPCI / bank VMN longcodes or shortcodes."""
        if not address:
            return False
        clean_addr = address.strip().replace("+91", "").replace("-", "").replace(" ", "")
        if clean_addr in self.KNOWN_VMN_NUMBERS:
            return True
        for prefix in self.KNOWN_VMN_PREFIXES:
            if clean_addr.startswith(prefix):
                return True
        return False

    def is_binding_payload(self, body: Optional[str]) -> bool:
        """Checks if message payload matches known UPI registration challenge tokens."""
        if not body:
            return False
        body_trimmed = body.strip()
        for prefix in self.BINDING_PAYLOAD_PREFIXES:
            if body_trimmed.startswith(prefix):
                return True
        if "UPI " in body_trimmed or "PP " in body_trimmed or "GPay " in body_trimmed:
            return True
        return False

    def infer_target_psp_or_bank(
        self,
        address: Optional[str],
        body: Optional[str],
        creator: Optional[str],
    ) -> str:
        """Determines the target PSP or sponsor bank from VMN, payload prefix, and creator package."""
        clean_addr = (address or "").strip().replace("+91", "").replace("-", "").replace(" ", "")
        clean_body = (body or "").strip()
        clean_creator = (creator or "").strip().lower()

        # PhonePe
        if (
            clean_body.startswith("PP ")
            or clean_creator == "com.phonepe.app"
            or clean_addr in ("9223008333", "9266801801")
        ):
            return "PhonePe"

        # Google Pay India
        if (
            clean_body.startswith("GPay ")
            or clean_body.startswith("VERIFY ")
            or "paisa" in clean_creator
            or clean_addr in ("9870807070", "8657002200")
        ):
            return "Google Pay India"

        # Paytm
        if (
            clean_body.startswith("PYTM ")
            or clean_body.startswith("ACTIVATE ")
            or "paytm" in clean_creator
            or clean_addr in ("7065970659", "9211400400")
        ):
            return "Paytm"

        # WhatsApp Pay
        if clean_body.startswith("WA ") or "whatsapp" in clean_creator:
            return "WhatsApp Pay"

        # Specific Bank Apps
        if clean_body.startswith("MBSREG ") or clean_addr == "9223488888" or "sbi" in clean_creator:
            return "SBI"
        if clean_addr == "9289200017" or "hdfc" in clean_creator:
            return "HDFC"
        if clean_addr == "9215676766" or "icici" in clean_creator:
            return "ICICI"
        if clean_addr == "9212500888" or "axis" in clean_creator:
            return "Axis Bank"
        if clean_addr == "9971056767" or "kbank" in clean_creator:
            return "Kotak Bank"

        # General BHIM / NPCI Direct
        if clean_body.startswith("UPI "):
            if "npci" in clean_creator:
                return "BHIM"
            return "BHIM"

        return "UPI / NPCI Direct"

    def audit_outbound_sms(
        self,
        sms_db_path: Union[str, Path],
        sim_ledger: Optional[List[DeviceSIMCardHistoryRecord]] = None,
        cl_records: Optional[List[NPCICommonLibraryVaultRecord]] = None,
        source_vfs_file_id: int = 101,
    ) -> List[UPIOutboundBindingSMSAudit]:
        """
        Parses Android mmssms.db / bugle_db, filters for outbound silent binding SMS messages,
        joins to siminfo._id (ICCID), and applies the 3-Point Trojan Correlation test.
        """
        target = Path(sms_db_path)
        if not target.exists():
            return []

        # Build sub_id mapping from sim_ledger
        sim_map: Dict[int, DeviceSIMCardHistoryRecord] = {}
        if sim_ledger:
            for sim in sim_ledger:
                if sim.android_sub_id is not None:
                    sim_map[sim.android_sub_id] = sim

        audits: List[UPIOutboundBindingSMSAudit] = []
        conn = sqlite3.connect(f"file:{target.resolve()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sms', 'messages');"
            )
            tables = [r["name"] for r in cur.fetchall()]
            if not tables:
                conn.close()
                return []

            target_table = "sms" if "sms" in tables else tables[0]
            cur.execute(f"SELECT * FROM {target_table} ORDER BY _id ASC;")
            rows = cur.fetchall()

            for row in rows:
                col_keys = row.keys()
                row_id: Optional[int] = row["_id"] if "_id" in col_keys else None
                address: Optional[str] = str(row["address"]) if "address" in col_keys and row["address"] else ""
                body: Optional[str] = str(row["body"]) if "body" in col_keys and row["body"] else ""
                date_val = row["date"] if "date" in col_keys else None
                msg_type = row["type"] if "type" in col_keys else 2
                sub_id = row["sub_id"] if "sub_id" in col_keys else None
                creator = str(row["creator"]) if "creator" in col_keys and row["creator"] else None

                # Must match either destination VMN or binding payload pattern
                if not (self.is_binding_vmn_destination(address) or self.is_binding_payload(body)):
                    continue

                # Delivery status
                if msg_type == 5:
                    delivery_status = "FAILED_NO_BALANCE_OR_NETWORK"
                elif msg_type == 4:
                    delivery_status = "OUTBOX_QUEUED"
                else:
                    delivery_status = "SENT_SUCCESS"

                # Sent UTC ISO-8601
                sent_utc_iso = "1970-01-01T00:00:00.000000Z"
                if date_val is not None:
                    try:
                        ts_num = int(date_val)
                        if ts_num > 10_000_000_000:
                            sent_utc_iso = ForensicTimestamp.from_unix_milliseconds(ts_num).utc_iso8601
                        elif ts_num > 0:
                            sent_utc_iso = ForensicTimestamp.from_unix_seconds(ts_num).utc_iso8601
                    except ValueError:
                        sent_utc_iso = str(date_val)

                # Join 1: Resolve Physical SIM ICCID & MSISDN via sub_id
                resolved_iccid: Optional[str] = None
                resolved_msisdn: Optional[str] = None
                if sub_id is not None and sub_id in sim_map:
                    matched_sim = sim_map[sub_id]
                    resolved_iccid = matched_sim.iccid_20_digit
                    resolved_msisdn = matched_sim.msisdn_phone_number

                # Inferred target PSP / Bank
                target_psp = self.infer_target_psp_or_bank(
                    address=address,
                    body=body,
                    creator=creator,
                )

                # 3-Point Trojan Attribution Verdict
                verdict = self.trojan_detector.classify_binding_sms(
                    creator_package=creator,
                    sms_timestamp_ms=int(date_val) if date_val is not None else None,
                    cl_records=cl_records,
                )

                audit_record = UPIOutboundBindingSMSAudit(
                    source_vfs_file_id=source_vfs_file_id,
                    sms_row_id=row_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    destination_vmn_number=address or "",
                    sms_payload_raw=body or "",
                    inferred_target_psp_or_bank=target_psp,
                    android_sub_id=sub_id,
                    resolved_sim_iccid=resolved_iccid,
                    resolved_sim_msisdn=resolved_msisdn,
                    creator_package_name=creator,
                    delivery_status=delivery_status,
                    sent_utc_iso=sent_utc_iso,
                    binding_attribution_verdict=verdict,
                )
                audits.append(audit_record)

        finally:
            conn.close()

        return audits
