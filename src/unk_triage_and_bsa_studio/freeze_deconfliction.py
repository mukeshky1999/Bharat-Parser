"""
Golden-Hour Nodal Freeze De-Confliction Center & 1930 NCRP CSV Generator (Sub-Engine 9.5C).
Enforces 3-tier freeze safeguards: locking complainant/victim accounts and excluding utility billers.
"""

from datetime import datetime, timezone
from typing import Any

from src.unk_triage_and_bsa_studio.models import FreezeCandidateAccount


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

            is_utility = any(
                k in vpa.lower() or k in acc_no.lower()
                for k in self.KNOWN_UTILITY_KEYWORDS
            )

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
        acknowledgement_no: str = "NCRP-2026-DEFAULT",
    ) -> str:
        """Generates 14-column 1930 NCRP Bank Lien CSV excluding locked and utility accounts."""
        headers = [
            "Acknowledgement_No",
            "Complainant_Source_Account",
            "Beneficiary_Account_to_Freeze",
            "Beneficiary_IFSC",
            "Beneficiary_UPI_VPA",
            "Lien_Amount_INR",
            "Action_Required",
            "Crime_Category",
            "State_UT",
            "Police_Station",
            "Investigating_Officer",
            "Generated_At_IST",
            "Safeguard_Check_Passed",
            "Remarks",
        ]

        now_dt = datetime.now(timezone.utc)
        ist_str = datetime.fromtimestamp(
            now_dt.timestamp() + 19800.0, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S IST")

        rows = [",".join(headers)]

        for c in evaluated_candidates:
            # Exclude locked victim accounts and utility billers from the freeze list
            if c.is_freeze_locked or c.is_utility_excluded:
                continue

            row = [
                acknowledgement_no,
                complainant_account,
                c.account_no,
                c.ifsc,
                c.vpa,
                f"{c.volume_inr:.2f}",
                "IMMEDIATE_DEBIT_FREEZE_LIEN",
                "CYBER_FINANCIAL_FRAUD",
                "Uttar Pradesh",
                "Cyber Crime PS",
                "Inspector Verma",
                ist_str,
                "YES_DECONFLICTED",
                "Exported from BharatAnalyzer Section 9.5",
            ]
            rows.append(",".join(row))

        return "\n".join(rows)
