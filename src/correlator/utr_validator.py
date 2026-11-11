"""
Sub-Engine 3.5A: 12-Digit NPCI UTR / RRN Validator vs. UIDAI Aadhaar Verhoeff Disambiguator.
Distinguishes genuine Indian banking NPCI Julian-day YDDD reference numbers
from 12-digit Indian Aadhaar biometric identity numbers using the Verhoeff D5 dihedral algorithm.
Adheres strictly to AGENTS.md Forensic Invariants and Section 3 of Module 3.5 Spec.
"""

from datetime import datetime, timezone, timedelta
import math
from typing import Any, Optional

from src.correlator.models import UTRValidationResult


class NPCIUTRJulianAndVerhoeffValidator:
    """Mathematical validator for NPCI 12-digit YDDD UTRs and Verhoeff D5 Aadhaar checksums."""

    IST_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")

    # Verhoeff Dihedral Group D5 Lookup Tables
    D_TABLE = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]

    P_TABLE = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]

    INV_TABLE = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    def validate_verhoeff(self, num_str: str) -> bool:
        """Evaluates whether a numeric string satisfies the Verhoeff D5 dihedral checksum."""
        if not isinstance(num_str, str) or not num_str.isdigit():
            return False
        c = 0
        digits = [int(x) for x in reversed(num_str)]
        for i, digit in enumerate(digits):
            c = self.D_TABLE[c][self.P_TABLE[i % 8][digit]]
        return c == 0

    def parse_iso_to_ist_datetime(self, iso_str: Optional[str]) -> Optional[datetime]:
        """Converts UTC ISO-8601 string to Indian Standard Time (IST) datetime."""
        if not iso_str:
            return None
        try:
            dt_utc = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return dt_utc.astimezone(self.IST_TIMEZONE)
        except Exception:
            return None

    def classify_12_digit_number(
        self,
        candidate_number: Optional[Any],
        tx_utc_iso: Optional[str] = None,
        is_explicit_utr_labeled: bool = False,
    ) -> UTRValidationResult:
        """
        Disambiguates 12-digit numeric strings into valid NPCI YDDD UTRs or UIDAI Aadhaar IDs.
        """
        if candidate_number is None or isinstance(candidate_number, bool):
            return UTRValidationResult(
                candidate_number="",
                is_aadhaar_number=False,
                utr_validation_status="INVALID_LENGTH_OR_FORMAT",
            )
        if isinstance(candidate_number, int):
            clean_num = str(candidate_number).strip()
        elif isinstance(candidate_number, float):
            if math.isnan(candidate_number) or math.isinf(candidate_number) or not candidate_number.is_integer():
                return UTRValidationResult(
                    candidate_number="",
                    is_aadhaar_number=False,
                    utr_validation_status="INVALID_LENGTH_OR_FORMAT",
                )
            clean_num = str(int(candidate_number)).strip()
        elif isinstance(candidate_number, str):
            clean_num = candidate_number.strip()
        else:
            return UTRValidationResult(
                candidate_number="",
                is_aadhaar_number=False,
                utr_validation_status="INVALID_LENGTH_OR_FORMAT",
            )

        if len(clean_num) != 12 or not clean_num.isdigit():
            return UTRValidationResult(
                candidate_number=clean_num,
                is_aadhaar_number=False,
                utr_validation_status="INVALID_LENGTH_OR_FORMAT",
            )

        d1 = int(clean_num[0])
        julian_day_utr = int(clean_num[1:4])
        year_digit_utr = d1

        # Check Verhoeff Aadhaar algorithm
        is_verhoeff_valid = self.validate_verhoeff(clean_num)
        # Aadhaar numbers never start with 0 or 1
        is_aadhaar_prefix_valid = d1 in (2, 3, 4, 5, 6, 7, 8, 9)

        # Aadhaar test criteria
        if is_verhoeff_valid and is_aadhaar_prefix_valid:
            if julian_day_utr > 366 or julian_day_utr == 0 or not is_explicit_utr_labeled:
                return UTRValidationResult(
                    candidate_number=clean_num,
                    is_aadhaar_number=True,
                    utr_validation_status="AADHAAR_NUMBER_NOT_UTR",
                    extracted_year_digit=year_digit_utr,
                    extracted_julian_day=julian_day_utr,
                )

        # Condition A: Invalid Julian Day range
        if julian_day_utr == 0 or julian_day_utr > 366:
            return UTRValidationResult(
                candidate_number=clean_num,
                is_aadhaar_number=False,
                utr_validation_status="INVALID_JULIAN_DAY_RANGE",
                extracted_year_digit=year_digit_utr,
                extracted_julian_day=julian_day_utr,
            )

        # Condition B: Compare with transaction timestamp in IST
        if tx_utc_iso:
            dt_ist = self.parse_iso_to_ist_datetime(tx_utc_iso)
            if dt_ist:
                tx_julian_day = dt_ist.timetuple().tm_yday
                tx_year_digit = dt_ist.year % 10

                if year_digit_utr == tx_year_digit and abs(julian_day_utr - tx_julian_day) <= 1:
                    return UTRValidationResult(
                        candidate_number=clean_num,
                        is_aadhaar_number=False,
                        utr_validation_status="VALID_NPCI_YDDD_MATCH",
                        extracted_year_digit=year_digit_utr,
                        extracted_julian_day=julian_day_utr,
                    )
                else:
                    return UTRValidationResult(
                        candidate_number=clean_num,
                        is_aadhaar_number=False,
                        utr_validation_status="ANOMALOUS_UTR_DATE_MISMATCH",
                        extracted_year_digit=year_digit_utr,
                        extracted_julian_day=julian_day_utr,
                    )

        # Default fallback if no timestamp provided but Julian day is structurally valid
        return UTRValidationResult(
            candidate_number=clean_num,
            is_aadhaar_number=False,
            utr_validation_status="VALID_NPCI_YDDD_MATCH",
            extracted_year_digit=year_digit_utr,
            extracted_julian_day=julian_day_utr,
        )
