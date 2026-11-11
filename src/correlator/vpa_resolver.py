"""
Sub-Engine 3.5B: Master VPA Suffix Resolver & Identity Graph Builder.
Resolves 45+ Indian UPI VPA handles to their TPAP applications and acquiring/sponsor banks.
Extracts underlying 10-digit mobile numbers (stripping secondary suffixes) and direct account+IFSC VPAs.
Adheres strictly to AGENTS.md Forensic Invariants and Section 4 of Module 3.5 Spec.
"""

import re
from typing import Dict, Optional, Tuple

from src.correlator.models import VPAResolutionResult


class VPARoutingResolver:
    """Resolves Indian UPI Virtual Payment Addresses (VPAs) to TPAP apps, banks, and phones."""

    # Master Directory of 45+ Indian VPA Handles (Section 4.1)
    VPA_HANDLE_MAP: Dict[str, Tuple[str, str]] = {
        # PhonePe
        "@ybl": ("PhonePe", "Yes Bank"),
        "@ibl": ("PhonePe", "ICICI Bank"),
        "@axl": ("PhonePe", "Axis Bank"),
        # Google Pay India
        "@okaxis": ("Google Pay India", "Axis Bank"),
        "@okhdfcbank": ("Google Pay India", "HDFC Bank"),
        "@okicici": ("Google Pay India", "ICICI Bank"),
        "@oksbi": ("Google Pay India", "State Bank of India (SBI)"),
        # Paytm
        "@ptyes": ("Paytm", "Yes Bank"),
        "@ptaxis": ("Paytm", "Axis Bank"),
        "@pthdfc": ("Paytm", "HDFC Bank"),
        "@ptsbi": ("Paytm", "State Bank of India (SBI)"),
        "@paytm": ("Paytm (Legacy PPBL)", "Paytm Payments Bank / Migrated TPAP"),
        # BHIM / NPCI
        "@upi": ("BHIM", "NPCI (National Payments Corporation of India)"),
        # WhatsApp Pay
        "@waicici": ("WhatsApp Pay", "ICICI Bank"),
        "@wahdfcbank": ("WhatsApp Pay", "HDFC Bank"),
        "@waaxis": ("WhatsApp Pay", "Axis Bank"),
        "@wasbi": ("WhatsApp Pay", "State Bank of India (SBI)"),
        # Amazon Pay India
        "@apl": ("Amazon Pay India", "Axis Bank"),
        "@yapl": ("Amazon Pay India", "Yes Bank"),
        "@rapl": ("Amazon Pay India", "RBL Bank"),
        # Neo / FinTech
        "@fam": ("FamPay", "IDFC FIRST Bank"),
        "@fampay": ("FamPay", "IDFC FIRST Bank"),
        "@sliceaxis": ("Slice", "Axis Bank"),
        "@slice": ("Slice", "Axis Bank"),
        "@axisb": ("CRED", "Axis Bank"),
        "@yescred": ("CRED", "Yes Bank"),
        "@naviaxis": ("Navi", "Axis Bank"),
        "@superyes": ("super.money", "Yes Bank"),
        "@ikwik": ("MobiKwik", "HDFC Bank / ICICI Bank"),
        "@freecharge": ("Freecharge", "Axis Bank"),
        "@bharatpe": ("BharatPe", "Unity Small Finance Bank / Yes Bank"),
        "@bpunity": ("BharatPe", "Unity Small Finance Bank"),
        # Bank-Specific Apps
        "@sbi": ("YONO SBI / BHIM SBI Pay", "State Bank of India (SBI)"),
        "@icici": ("iMobile Pay", "ICICI Bank"),
        "@hdfcbank": ("HDFC MobileBanking", "HDFC Bank"),
        "@pz": ("HDFC PayZapp", "HDFC Bank"),
        "@kotak": ("Kotak811 / Kotak Mobile", "Kotak Mahindra Bank"),
        "@axisbank": ("Axis Mobile", "Axis Bank"),
        "@barodampay": ("bob World", "Bank of Baroda"),
        "@pnb": ("PNB One", "Punjab National Bank"),
        "@cnrb": ("Canara ai1", "Canara Bank"),
        "@uboi": ("Union Bank Vyom", "Union Bank of India"),
        "@indianbank": ("IndOASIS", "Indian Bank"),
        "@airtel": ("Airtel Thanks", "Airtel Payments Bank"),
        "@airtelpaymentsbank": ("Airtel Thanks", "Airtel Payments Bank"),
        "@postbank": ("IPPB Mobile", "India Post Payments Bank (IPPB)"),
        "@dakpay": ("IPPB DakPay", "India Post Payments Bank (IPPB)"),
        "@jio": ("MyJio / JioFinance", "Jio Payments Bank"),
        "@federal": ("FedMobile", "Federal Bank"),
        "@fi": ("Fi Money", "Federal Bank"),
        "@jupiteraxis": ("Jupiter", "Axis Bank"),
        "@indus": ("IndusMobile", "IndusInd Bank"),
        "@idfcfirst": ("IDFC FIRST Mobile", "IDFC FIRST Bank"),
        "@yesbank": ("IRIS by YES BANK", "Yes Bank"),
        "@yespay": ("IRIS by YES BANK", "Yes Bank"),
        "@aubank": ("AU 0101", "AU Small Finance Bank"),
    }

    MOBILE_10_REGEX = re.compile(r"^[6-9][0-9]{9}$")
    MOBILE_91_REGEX = re.compile(r"^91([6-9][0-9]{9})$")

    def resolve_vpa(self, raw_vpa: Optional[str]) -> VPAResolutionResult:
        """
        Resolves a UPI VPA string into TPAP app, sponsor bank, and extracts mobile or direct bank A/C.
        """
        if not raw_vpa or "@" not in raw_vpa:
            return VPAResolutionResult(
                raw_vpa=raw_vpa or "",
                owning_tpap_app="Unknown TPAP",
                sponsor_psp_bank="Unknown Bank",
            )

        clean_vpa = raw_vpa.strip().lower()
        parts = clean_vpa.split("@", 1)
        prefix = parts[0].strip()
        suffix = "@" + parts[1].strip()

        # Step 1: Direct Bank Account + IFSC Routing VPA (<AccountNo>@<IFSC>.ifsc.npci)
        if clean_vpa.endswith(".ifsc.npci"):
            direct_acct = prefix
            ifsc_part = parts[1].replace(".ifsc.npci", "").upper().strip()
            return VPAResolutionResult(
                raw_vpa=raw_vpa,
                owning_tpap_app="Direct NPCI Account Transfer",
                sponsor_psp_bank="NPCI Direct Clearing",
                inferred_mobile_number=None,
                is_direct_account_ifsc_vpa=True,
                direct_account_number=direct_acct,
                direct_ifsc_code=ifsc_part,
            )

        # Step 2: Resolve TPAP App & Sponsor PSP Bank from Suffix
        owning_app = "UPI Application"
        sponsor_bank = "Sponsor Bank"

        if suffix in self.VPA_HANDLE_MAP:
            owning_app, sponsor_bank = self.VPA_HANDLE_MAP[suffix]
        else:
            for handle, (app_name, bank_name) in self.VPA_HANDLE_MAP.items():
                if suffix.endswith(handle) or handle in suffix:
                    owning_app, sponsor_bank = app_name, bank_name
                    break

        # Step 3: Extract Inferred Mobile Number from Prefix
        inferred_mobile: Optional[str] = None

        # Check pure 10-digit or 91+10-digit mobile
        if self.MOBILE_10_REGEX.match(prefix):
            inferred_mobile = prefix
        else:
            match_91 = self.MOBILE_91_REGEX.match(prefix)
            if match_91:
                inferred_mobile = match_91.group(1)
            else:
                # Strip secondary account suffixes: e.g. "9876543210-2" or "9876543210.wallet"
                stripped_prefix = re.sub(r"-[0-9]+$", "", prefix)
                stripped_prefix = re.sub(r"\..+$", "", stripped_prefix)

                if self.MOBILE_10_REGEX.match(stripped_prefix):
                    inferred_mobile = stripped_prefix
                else:
                    match_strip_91 = self.MOBILE_91_REGEX.match(stripped_prefix)
                    if match_strip_91:
                        inferred_mobile = match_strip_91.group(1)

        return VPAResolutionResult(
            raw_vpa=raw_vpa,
            owning_tpap_app=owning_app,
            sponsor_psp_bank=sponsor_bank,
            inferred_mobile_number=inferred_mobile,
            is_direct_account_ifsc_vpa=False,
            direct_account_number=None,
            direct_ifsc_code=None,
        )
