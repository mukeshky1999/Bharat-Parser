"""
Sub-Engine 3.3A: Core Banking Narration Parser.
Splits Indian core-banking narration strings (UPI, IMPS, NEFT, RTGS)
into structured forensic attributes (12-digit UTR/RRN, Direction, Counterparty, VPA, IFSC).
Adheres strictly to AGENTS.md Forensic Invariants and Section 3.1 of Module 3.3 Spec.
"""

import re
from typing import Optional

from src.banking.models import ParsedNarration, PaymentRail, TxDirection


_CREDIT_CUE = re.compile(r"(?<![A-Z0-9])(CR|CREDIT)(?![A-Z0-9])")
_DEBIT_CUE = re.compile(r"(?<![A-Z0-9])(DR|DEBIT)(?![A-Z0-9])")


def direction_from_cues(narration: str) -> str:
    """Direction from whole-token cues only. 'CRED' (the app), 'SCRIPT' or 'MICRO' are not credits.

    Returns UNKNOWN when there is no cue or the cues conflict; it never defaults to DEBIT.
    """
    t = narration.upper().strip()
    credit = bool(_CREDIT_CUE.search(t)) or t.startswith("BY ")
    debit = bool(_DEBIT_CUE.search(t)) or t.startswith("TO ")
    if credit and not debit:
        return TxDirection.CREDIT.value
    if debit and not credit:
        return TxDirection.DEBIT.value
    return TxDirection.UNKNOWN.value


class CoreBankingNarrationParser:
    """Parses Indian Core Banking Solution (CBS) transaction narration strings."""

    UTR_12_REGEX = re.compile(r"\b(\d{12})\b")
    VPA_REGEX = re.compile(r"\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9.\-_]{2,32})\b")

    def parse_narration(self, raw_narration: Optional[str]) -> ParsedNarration:
        """
        Parses narration strings conforming to SBI, HDFC, ICICI, and NPCI CBS standards.
        Examples:
        - "UPI/DR/630914829104/VIKRAM SINGH/HDFC/vikram@okhdfcbank/Rent"
        - "BY TRANSFER-IMPS/410293847581/RAMESH KUMAR/SBIN/9876543210"
        - "TO TRANSFER-INB IMPS/630914829104/VIKRAM/HDFC0001234"
        """
        if not raw_narration:
            return ParsedNarration(
                utr_or_rrn=None,
                direction=TxDirection.DEBIT.value,
                counterparty_name=None,
                counterparty_vpa=None,
                counterparty_acct=None,
                counterparty_ifsc=None,
                payment_rail=PaymentRail.INTERNAL_TRANSFER.value,
                remarks=None,
            )

        narration = raw_narration.strip()

        # Pattern 1: Standard UPI Narration: UPI/(DR|CR)/<UTR>/<Name>/<Bank>/<VPA>/<Remarks>
        if narration.upper().startswith("UPI/"):
            parts = narration.split("/")
            direction = TxDirection.DEBIT.value
            if len(parts) > 1:
                dr_cr = parts[1].strip().upper()
                if dr_cr == "CR":
                    direction = TxDirection.CREDIT.value
                elif dr_cr == "DR":
                    direction = TxDirection.DEBIT.value

            utr = parts[2].strip() if len(parts) > 2 else None
            counterparty = parts[3].strip() if len(parts) > 3 else None
            vpa = parts[5].strip() if len(parts) > 5 else None
            remarks = parts[6].strip() if len(parts) > 6 else None

            # If VPA is in parts[4] or remarks
            if not vpa and len(parts) > 4 and "@" in parts[4]:
                vpa = parts[4].strip()

            return ParsedNarration(
                utr_or_rrn=utr,
                direction=direction,
                counterparty_name=counterparty,
                counterparty_vpa=vpa,
                counterparty_acct=None,
                counterparty_ifsc=None,
                payment_rail=PaymentRail.UPI.value,
                remarks=remarks,
            )

        # Pattern 2: BY TRANSFER-IMPS (Inflow / Credit)
        if "TRANSFER-IMPS/" in narration.upper() and narration.upper().startswith("BY "):
            parts = narration.split("/")
            utr = parts[1].strip() if len(parts) > 1 else None
            counterparty = parts[2].strip() if len(parts) > 2 else None
            acct_or_mob = parts[4].strip() if len(parts) > 4 else None

            return ParsedNarration(
                utr_or_rrn=utr,
                direction=TxDirection.CREDIT.value,
                counterparty_name=counterparty,
                counterparty_vpa=None,
                counterparty_acct=acct_or_mob,
                counterparty_ifsc=None,
                payment_rail=PaymentRail.IMPS.value,
                remarks=None,
            )

        # Pattern 3: TO TRANSFER-INB IMPS (Outflow / Debit)
        if "TRANSFER-INB IMPS/" in narration.upper() or ("IMPS/" in narration.upper() and narration.upper().startswith("TO ")):
            parts = narration.split("/")
            utr = parts[1].strip() if len(parts) > 1 else None
            counterparty = parts[2].strip() if len(parts) > 2 else None
            ifsc_or_acct = parts[3].strip() if len(parts) > 3 else None

            ifsc = ifsc_or_acct if (ifsc_or_acct and len(ifsc_or_acct) == 11 and ifsc_or_acct[4] == "0") else None
            acct = ifsc_or_acct if not ifsc else None

            return ParsedNarration(
                utr_or_rrn=utr,
                direction=TxDirection.DEBIT.value,
                counterparty_name=counterparty,
                counterparty_vpa=None,
                counterparty_acct=acct,
                counterparty_ifsc=ifsc,
                payment_rail=PaymentRail.IMPS.value,
                remarks=None,
            )

        # Pattern 4: General NEFT / RTGS
        if "NEFT" in narration.upper():
            utr_match = self.UTR_12_REGEX.search(narration)
            utr = utr_match.group(1) if utr_match else None
            direction = direction_from_cues(narration)
            return ParsedNarration(
                utr_or_rrn=utr,
                direction=direction,
                counterparty_name=None,
                counterparty_vpa=None,
                counterparty_acct=None,
                counterparty_ifsc=None,
                payment_rail=PaymentRail.NEFT.value,
                remarks=narration,
            )

        if "RTGS" in narration.upper():
            utr_match = self.UTR_12_REGEX.search(narration)
            utr = utr_match.group(1) if utr_match else None
            direction = direction_from_cues(narration)
            return ParsedNarration(
                utr_or_rrn=utr,
                direction=direction,
                counterparty_name=None,
                counterparty_vpa=None,
                counterparty_acct=None,
                counterparty_ifsc=None,
                payment_rail=PaymentRail.RTGS.value,
                remarks=narration,
            )

        # Fallback regex search
        utr_match = self.UTR_12_REGEX.search(narration)
        utr = utr_match.group(1) if utr_match else None
        vpa_match = self.VPA_REGEX.search(narration)
        vpa = vpa_match.group(1) if vpa_match else None
        direction = direction_from_cues(narration)
        rail = PaymentRail.UPI.value if vpa or "UPI" in narration.upper() else PaymentRail.INTERNAL_TRANSFER.value

        return ParsedNarration(
            utr_or_rrn=utr,
            direction=direction,
            counterparty_name=None,
            counterparty_vpa=vpa,
            counterparty_acct=None,
            counterparty_ifsc=None,
            payment_rail=rail,
            remarks=narration,
        )
