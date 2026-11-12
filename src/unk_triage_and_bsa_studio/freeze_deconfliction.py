"""
Golden-Hour Nodal Freeze De-Confliction Center & 1930 NCRP CSV Generator (Sub-Engine 9.5C).
Enforces 3-tier freeze safeguards: locking complainant/victim accounts and excluding utility billers.
"""

import csv
import io
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from src.unk_triage_and_bsa_studio.models import FreezeCandidateAccount


LF = chr(10)
FORMULA_PREFIXES = ("=", "+", "-", "@", chr(9), chr(13))


class NodalFreezeDeconflictionCenter:
    """Evaluates candidate freeze accounts and exports de-conflicted 14-column 1930 NCRP bank lien sheets."""

    KNOWN_UTILITY_KEYWORDS = [
        "irctc",
        "bescom",
        "uppcl",
        "mahadiscom",
        "cesc",
        "billdesk",
        "tata_power",
        "airtel_prepaid",
        "jio_postpaid",
    ]

    NOT_PROVIDED = "NOT_PROVIDED"

    @staticmethod
    def _tokens(text: str) -> list[str]:
        return [t for t in re.split(r"[^a-z0-9]+", str(text).lower()) if t]

    @classmethod
    def is_utility_biller(cls, *identifiers: str) -> bool:
        """True if a known biller name appears as whole word(s) in any identifier.

        Whole-token matching: 'francesca@ybl' does NOT match 'cesc'; 'bescom.billdesk@icici' matches.
        """
        for ident in identifiers:
            toks = cls._tokens(ident)
            for kw in cls.KNOWN_UTILITY_KEYWORDS:
                kt = cls._tokens(kw)
                n = len(kt)
                if n and any(toks[i:i + n] == kt for i in range(len(toks) - n + 1)):
                    return True
        return False

    @staticmethod
    def _cell(value: Any) -> str:
        """Neutralise spreadsheet formula injection for text cells."""
        text = str(value)
        return "'" + text if text[:1] in FORMULA_PREFIXES else text

    def evaluate_freeze_candidates(
        self, candidates: list[dict[str, Any]]
    ) -> list[FreezeCandidateAccount]:
        """Applies 3-color de-confliction: victim lock, utility exclude, and mule target badge."""
        evaluated: list[FreezeCandidateAccount] = []

        for c in candidates:
            acc_no = str(c.get("account_no", ""))
            ifsc = str(c.get("ifsc", ""))
            vpa = str(c.get("vpa", ""))
            is_victim = bool(c.get("is_complainant_victim", False))
            volume = float(c.get("volume_inr", 0.0))

            is_utility = self.is_utility_biller(vpa, acc_no)

            if is_victim:
                evaluated.append(
                    FreezeCandidateAccount(
                        account_no=acc_no,
                        ifsc=ifsc,
                        vpa=vpa,
                        is_complainant_victim=True,
                        volume_inr=volume,
                        is_freeze_locked=True,
                        freeze_checkbox_disabled=True,
                        is_utility_excluded=False,
                        role_badge="[🛡️ VICTIM / COMPLAINANT — DO NOT FREEZE]",
                    )
                )
            elif is_utility:
                evaluated.append(
                    FreezeCandidateAccount(
                        account_no=acc_no,
                        ifsc=ifsc,
                        vpa=vpa,
                        is_complainant_victim=False,
                        volume_inr=volume,
                        is_freeze_locked=False,
                        freeze_checkbox_disabled=False,
                        is_utility_excluded=True,
                        role_badge="[⚠️ UTILITY / GOVT BILLER — EXCLUDED BY DEFAULT]",
                    )
                )
            else:
                evaluated.append(
                    FreezeCandidateAccount(
                        account_no=acc_no,
                        ifsc=ifsc,
                        vpa=vpa,
                        is_complainant_victim=False,
                        volume_inr=volume,
                        is_freeze_locked=False,
                        freeze_checkbox_disabled=False,
                        is_utility_excluded=False,
                        role_badge="[🚨 LAYER-1 MULE TARGET]",
                    )
                )

        return evaluated

    def generate_1930_ncrp_csv(
        self,
        evaluated_candidates: list[FreezeCandidateAccount],
        complainant_account: str,
        acknowledgement_no: str,
        state_ut: str = "",
        police_station: str = "",
        investigating_officer: str = "",
        crime_category: str = "",
    ) -> str:
        """14-column NCRP bank-lien sheet for non-victim, non-biller candidates.

        State, station, officer and crime category are written exactly as supplied; blank values
        are written as NOT_PROVIDED, never invented. The acknowledgement number is required.
        """
        if not str(acknowledgement_no or "").strip():
            raise ValueError("NCRP acknowledgement number is required.")
        headers = [
            "Acknowledgement_No", "Complainant_Source_Account", "Beneficiary_Account_to_Freeze",
            "Beneficiary_IFSC", "Beneficiary_UPI_VPA", "Lien_Amount_INR", "Action_Required",
            "Crime_Category", "State_UT", "Police_Station", "Investigating_Officer",
            "Generated_At_IST", "Safeguard_Check_Passed", "Remarks",
        ]
        ist = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30)))
        ist_str = ist.strftime("%Y-%m-%d %H:%M:%S IST")
        given = lambda v: str(v).strip() or self.NOT_PROVIDED  # noqa: E731

        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(headers)
        for c in evaluated_candidates:
            if c.is_freeze_locked or c.is_utility_excluded:
                continue
            w.writerow([self._cell(x) for x in (
                acknowledgement_no, complainant_account, c.account_no, c.ifsc, c.vpa,
            )] + [
                f"{c.volume_inr:.2f}",
                "IMMEDIATE_DEBIT_FREEZE_LIEN",
                self._cell(given(crime_category)),
                self._cell(given(state_ut)),
                self._cell(given(police_station)),
                self._cell(given(investigating_officer)),
                ist_str,
                "AUTOMATED_RULES_PASSED",
                "Generated by BharatAnalyzer; examiner must review before submission",
            ])
        return buf.getvalue().rstrip("\n")
