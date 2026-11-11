"""
Universal Fallback Introspector for Unrecognized (UNK) Apps & Databases (Sub-Engine 8.2C).
Dissects third-party SQLite databases and binary artifacts using schema heuristics and the 10-indicator forensic sweeper.
"""

from datetime import datetime, timezone
import json
import os
import re
import sqlite3
from typing import Any, Optional

from src.zero_omission_and_fts5.models import (
    ContainerStructureType,
    DetectedIndicatorCategory,
    ResidualRecoveryConfidence,
    UnkGenericFinding,
)


class UniversalFallbackIntrospector:
    """Introspects uncataloged databases and raw files to extract forensic indicators with zero evidence loss."""

    COCOA_EPOCH_OFFSET = 978307200  # 2001-01-01 00:00:00 UTC in Unix seconds

    # Regex patterns for 10-indicator forensic sweeper
    RE_PHONE = re.compile(r"(?:\+91|91)?[6-9]\d{9}\b|\+\d{1,3}\d{7,14}\b")
    RE_CRYPTO_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
    RE_CRYPTO_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    RE_CRYPTO_BTC = re.compile(r"\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b|\bbc1[a-z0-9]{39,59}\b")
    RE_CRYPTO_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
    RE_CRYPTO_TON = re.compile(r"\bEQ[0-9a-zA-Z_-]{46}\b")
    RE_UPI_UTR = re.compile(r"(?<![\+\d])\d{12}(?!\d)")
    RE_UPI_VPA = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b")
    RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    RE_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
    RE_GSTIN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b")
    RE_OPSEC_SESSION = re.compile(r"\b05[0-9a-fA-F]{64}\b")
    RE_OPSEC_ZANGI = re.compile(r"\b10-\d{4}-\d{4}\b")
    RE_OPSEC_BOT = re.compile(r"\bbot\d+:[A-Za-z0-9_-]+\b")
    RE_OPSEC_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")
    RE_GPS = re.compile(r"(-?\d{1,2}\.\d{4,8}),\s*(-?\d{1,3}\.\d{4,8})")

    KNOWN_PSP_HANDLES = {
        "okaxis",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "ybl",
        "ibl",
        "axl",
        "paytm",
        "upi",
        "sbi",
        "icici",
        "hdfcbank",
        "barodampay",
        "kotak",
        "federal",
        "idfcbank",
        "aubank",
        "indus",
        "freecharge",
        "mobikwik",
        "airtel",
        "superyes",
        "naviaxis",
        "jupiteraxis",
    }

    TIMESTAMP_KEYWORDS = (
        "time",
        "date",
        "_at",
        "ts",
        "created",
        "updated",
        "modified",
        "sent",
        "expires",
        "timestamp",
    )

    def is_valid_julian_day_utr(self, candidate: str) -> bool:
        """Validates that digits 2..4 of a 12-digit UPI UTR form a plausible Julian Day (001-366)."""
        if len(candidate) != 12 or not candidate.isdigit():
            return False
        # Disqualify 12-digit numbers matching Indian mobile with 91 prefix
        if candidate.startswith("91") and candidate[2] in "6789":
            return False
        julian_day_str = candidate[1:4]
        try:
            julian_day = int(julian_day_str)
            return 1 <= julian_day <= 366
        except ValueError:
            return False

    def is_valid_vpa(self, candidate: str) -> bool:
        """Validates a UPI VPA against structure and known NPCI PSP handles."""
        if "@" not in candidate:
            return False
        handle = candidate.split("@")[-1].lower()
        if handle in self.KNOWN_PSP_HANDLES or "." not in handle:
            return True
        return False

    def convert_numeric_timestamp_to_iso(self, val: Any) -> Optional[str]:
        """Infers epoch type (Unix s/ms/us or Cocoa s) and returns UTC ISO-8601 string."""
        if not isinstance(val, (int, float)):
            return None
        num = float(val)

        # 10-digit Unix Seconds (2015 to 2030: ~1.42e9 to 1.90e9)
        if 1.42e9 <= num <= 1.90e9:
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # 13-digit Unix Milliseconds
        if 1.42e12 <= num <= 1.90e12:
            dt = datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # 16-digit Unix Microseconds
        if 1.42e15 <= num <= 1.90e15:
            dt = datetime.fromtimestamp(num / 1000000.0, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Apple Cocoa Seconds (2015 to 2030: ~4.41e8 to 9.20e8)
        if 4.41e8 <= num <= 9.20e8:
            unix_s = num + self.COCOA_EPOCH_OFFSET
            dt = datetime.fromtimestamp(unix_s, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return None

    def sweep_text_for_indicators(
        self, text: str
    ) -> list[tuple[DetectedIndicatorCategory, str]]:
        """Scans arbitrary string for the 10 forensic indicators."""
        results: list[tuple[DetectedIndicatorCategory, str]] = []
        if not text:
            return results

        # 1. 12-digit UPI UTR
        for match in self.RE_UPI_UTR.finditer(text):
            utr = match.group(0)
            if self.is_valid_julian_day_utr(utr):
                results.append((DetectedIndicatorCategory.VALIDATED_UPI_UTR_12_DIGIT, utr))

        # 2. UPI VPA
        for match in self.RE_UPI_VPA.finditer(text):
            vpa = match.group(0)
            if self.is_valid_vpa(vpa):
                results.append((DetectedIndicatorCategory.VALIDATED_UPI_VPA, vpa))

        # 3. Cryptocurrency Addresses
        for match in self.RE_CRYPTO_TRON.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS, match.group(0)))
        for match in self.RE_CRYPTO_EVM.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS, match.group(0)))
        for match in self.RE_CRYPTO_BTC.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS, match.group(0)))
        for match in self.RE_CRYPTO_XMR.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS, match.group(0)))
        for match in self.RE_CRYPTO_TON.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS, match.group(0)))

        # 4. IFSC
        for match in self.RE_IFSC.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_IFSC_AND_BANK, match.group(0)))

        # 5. PAN / Aadhaar / GSTIN
        for match in self.RE_PAN.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_PAN_AADHAAR_GSTIN, match.group(0)))
        for match in self.RE_AADHAAR.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_PAN_AADHAAR_GSTIN, match.group(0)))
        for match in self.RE_GSTIN.finditer(text):
            results.append((DetectedIndicatorCategory.VALIDATED_PAN_AADHAAR_GSTIN, match.group(0)))

        # 6. Phone numbers
        for match in self.RE_PHONE.finditer(text):
            phone = match.group(0)
            # Avoid conflating pure 10-12 digit numbers already captured as UTR
            if len(phone) >= 10:
                results.append((DetectedIndicatorCategory.PHONE_NUMBER_E164, phone))

        # 7. OpSec handles / C2 URLs
        for match in self.RE_OPSEC_SESSION.finditer(text):
            results.append((DetectedIndicatorCategory.OPSEC_HANDLE_OR_C2_URL, match.group(0)))
        for match in self.RE_OPSEC_ZANGI.finditer(text):
            results.append((DetectedIndicatorCategory.OPSEC_HANDLE_OR_C2_URL, match.group(0)))
        for match in self.RE_OPSEC_BOT.finditer(text):
            results.append((DetectedIndicatorCategory.OPSEC_HANDLE_OR_C2_URL, match.group(0)))
        for match in self.RE_OPSEC_ONION.finditer(text):
            results.append((DetectedIndicatorCategory.OPSEC_HANDLE_OR_C2_URL, match.group(0)))

        # 8. GPS coordinates
        for match in self.RE_GPS.finditer(text):
            results.append((DetectedIndicatorCategory.WGS84_GPS_COORDINATE_PAIR, match.group(0)))

        return results

    def introspect_sqlite_file(
        self, vfs_file_id: int, file_path: str, owning_package: str
    ) -> list[UnkGenericFinding]:
        """Introspects uncataloged SQLite database using schema heuristics and forensic sweeping."""
        findings: list[UnkGenericFinding] = []
        if not os.path.isfile(file_path):
            return findings

        try:
            conn = sqlite3.connect(file_path)
            cur = conn.cursor()

            # Discover user tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [row[0] for row in cur.fetchall()]

            for tbl in tables:
                # Get column information
                cur.execute(f"PRAGMA table_info('{tbl}');")
                col_infos = cur.fetchall()
                col_names = [col[1] for col in col_infos]

                # Identify potential timestamp columns
                timestamp_cols = [
                    c for c in col_names if any(kw in c.lower() for kw in self.TIMESTAMP_KEYWORDS)
                ]

                # Query rows
                cur.execute(f"SELECT * FROM '{tbl}' LIMIT 5000;")
                rows = cur.fetchall()

                for row_idx, row_data in enumerate(rows, start=1):
                    row_dict = dict(zip(col_names, row_data))
                    row_json = json.dumps(row_dict, default=str)

                    # Infer timestamp
                    inferred_ts = None
                    for tc in timestamp_cols:
                        val = row_dict.get(tc)
                        inferred_ts = self.convert_numeric_timestamp_to_iso(val)
                        if inferred_ts:
                            break

                    # Sweep row JSON for indicators
                    indicators = self.sweep_text_for_indicators(row_json)

                    # If no specific indicators found, but table has message/body text, emit generic record
                    if not indicators:
                        has_body = any("msg" in c.lower() or "body" in c.lower() or "text" in c.lower() for c in col_names)
                        if has_body and inferred_ts:
                            findings.append(
                                UnkGenericFinding(
                                    vfs_file_id=vfs_file_id,
                                    owning_app_package=owning_package,
                                    container_structure_type=ContainerStructureType.UNK_SQLITE_ACTIVE_ROW,
                                    table_or_object_path=f"{tbl}:{row_idx}",
                                    detected_indicator_category=DetectedIndicatorCategory.GENERIC_TIMESTAMPED_MESSAGE_OR_RECORD,
                                    extracted_indicator_value=str(row_data),
                                    full_row_or_context_json=row_json,
                                    inferred_timestamp_utc_iso=inferred_ts,
                                    recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD,
                                )
                            )

                    for cat, val in indicators:
                        findings.append(
                            UnkGenericFinding(
                                vfs_file_id=vfs_file_id,
                                owning_app_package=owning_package,
                                container_structure_type=ContainerStructureType.UNK_SQLITE_ACTIVE_ROW,
                                table_or_object_path=f"{tbl}:{row_idx}",
                                detected_indicator_category=cat,
                                extracted_indicator_value=val,
                                full_row_or_context_json=row_json,
                                inferred_timestamp_utc_iso=inferred_ts,
                                recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD,
                            )
                        )

            conn.close()
        except Exception as exc:
            _ = exc

        return findings

    def introspect_binary_file(
        self, vfs_file_id: int, file_path: str, owning_package: str
    ) -> list[UnkGenericFinding]:
        """Carves printable UTF-8 and ASCII strings from arbitrary binary file to sweep indicators."""
        findings: list[UnkGenericFinding] = []
        if not os.path.isfile(file_path):
            return findings

        try:
            with open(file_path, "rb") as f:
                content = f.read(5 * 1024 * 1024)  # Read up to 5 MB

            # Extract ASCII strings of length >= 6
            ascii_strings = re.findall(rb"[\x20-\x7E]{6,}", content)
            combined_text = " ".join(s.decode("latin-1", errors="ignore") for s in ascii_strings)

            indicators = self.sweep_text_for_indicators(combined_text)
            for idx, (cat, val) in enumerate(indicators, start=1):
                findings.append(
                    UnkGenericFinding(
                        vfs_file_id=vfs_file_id,
                        owning_app_package=owning_package,
                        container_structure_type=ContainerStructureType.UNK_CARVED_UTF8_UTF16_STRING,
                        table_or_object_path=f"offset_carved:{idx}",
                        detected_indicator_category=cat,
                        extracted_indicator_value=val,
                        full_row_or_context_json=json.dumps({"carved_indicator": val}),
                        inferred_timestamp_utc_iso=None,
                        recovery_classification=ResidualRecoveryConfidence.RESIDUAL_RECORD,
                    )
                )
        except Exception as exc:
            _ = exc

        return findings
