"""
Sub-Engine 3.4C: The 10-Category Financial SMS Grammar & Regex Extraction Pipeline.
Classifies SMS into 10 forensic categories, parses Indian Lakh/Crore amounts,
disambiguates available balance from transaction values, and extracts UTR/VPA tokens.
Adheres strictly to AGENTS.md Forensic Invariants and Section 5 of Module 3.4 Spec.
"""

import re

from src.core.amounts import AMOUNT_VALID_RE
from typing import Optional

from src.dlt.models import DLTHeaderInfo, FinancialSMSCategory, ParsedFinancialSMSFields


class FinancialSMSGrammarParser:
    """Deterministic parser for Indian banking, UPI, and regulatory SMS alerts."""

    # Regex for Indian Lakh/Crore currency amounts: e.g. Rs.1,25,000.00 or INR 45,000.00
    AMOUNT_PATTERN = AMOUNT_VALID_RE  # shared parser: handles lakh grouping, rejects fragments (C-10)

    # Regex for Available Balance clause
    BALANCE_PATTERN = re.compile(
        r"(?:Avl\s*Bal|Available\s*Bal|Bal|Clear\s*Bal|Closing\s*Bal|Updated\s*Bal)\s*[:\-]?\s*(?:Rs\.?|INR|₹)?\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        re.IGNORECASE,
    )

    # Regex for Masked Bank Account or Card Number
    ACCOUNT_PATTERN = re.compile(
        r"(?:A/c|Acct|Account|Card)\s*(?:no\.?|number|ending)?\s*[:\-]?\s*([X\*x#0-9\-]*[0-9]{3,6})",
        re.IGNORECASE,
    )

    # Regex for 12-to-22 char UTR / RRN
    UTR_EXPLICIT_PATTERN = re.compile(
        r"(?:Ref\s*(?:No\.?)?|UTR|RRN|IMPS\s*Ref|UPI\s*Ref|UPI:|txn\s*id)\s*[:\-]?\s*([A-Za-z0-9]{12,22})",
        re.IGNORECASE,
    )
    UTR_NUMERIC_12_PATTERN = re.compile(r"\b(\d{12})\b")

    # Regex for Counterparty VPA (e.g. name@bank)
    VPA_PATTERN = re.compile(r"\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9.\-_]{2,32})\b")

    # Regex for NCRP Cybercrime Ack No (14–15 digits starting with 33 or 2)
    NCRP_ACK_PATTERN = re.compile(r"(?:Ack\s*(?:No\.?)?|Complaint\s*(?:No\.?)?)\s*[:\-]?\s*([0-9]{12,16})", re.IGNORECASE)

    # Regex for OTP Authentication Code (4 to 8 digits)
    OTP_PATTERN = re.compile(r"\b([0-9]{4,8})\b")

    # Promotional spam keywords
    PROMO_SPAM_KEYWORDS = (
        "pre-approved",
        "instant loan",
        "offer account",
        "click http",
        "apply now",
        "eligible for",
        "bonus",
        "rummy",
        "fantasy",
        "win cash",
    )

    # Whole words only. Substrings caused "consent" to read as "sent" and "Account holder" as "hold".
    _DEBIT_WORDS = re.compile(r"\b(debited|debit|withdrawn|paid|sent|transferred|spent|deducted|dr)\b", re.IGNORECASE)
    _CREDIT_WORDS = re.compile(r"\b(credited|credit|received|deposited|refunded|cr)\b", re.IGNORECASE)
    _LIEN_WORDS = re.compile(r"\b(lien|freeze|freezing|frozen|ncrp)\b", re.IGNORECASE)
    _HOLD_WORD = re.compile(r"\bhold\b", re.IGNORECASE)
    _CYBER_REF = re.compile(r"\b(cyber\s*crime|ack(?:nowledg\w+)?)\b", re.IGNORECASE)
    _OTP_WORDS = re.compile(r"\b(otp|one time password|verification code|secret code)\b", re.IGNORECASE)
    _ATM_WORDS = re.compile(r"\b(atm|cash withdrawal|cardless|yono cash)\b", re.IGNORECASE)
    # A 12-digit number that is 91 + a ten-digit mobile number is a phone number, not a UTR.
    _PHONE_WITH_91 = re.compile(r"^91[6-9]\d{9}$")

    def normalize_amount_str(self, amt_str: Optional[str]) -> Optional[float]:
        """Strips Indian commas and converts numeric string to float."""
        if not amt_str:
            return None
        clean = amt_str.replace(",", "").strip()
        try:
            return float(clean)
        except ValueError:
            return None

    def parse_sms(
        self,
        body: Optional[str],
        dlt_header_info: Optional[DLTHeaderInfo] = None,
    ) -> ParsedFinancialSMSFields:
        """
        Executes the 10-Category Classification and Field Extraction Pipeline.
        """
        if not body:
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.PROMOTIONAL_SPAM_IGNORED.value
            )

        norm_body = " ".join(body.split())
        body_lower = norm_body.lower()

        # Step 1: Check Promotional Spam Rejection
        is_promo = False
        if dlt_header_info and dlt_header_info.is_promotional_dlt:
            is_promo = True

        if any(keyword in body_lower for keyword in self.PROMO_SPAM_KEYWORDS):
            # If it's a promotional offer without an authentic transaction UTR
            if not self.UTR_EXPLICIT_PATTERN.search(norm_body):
                is_promo = True

        if is_promo:
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.PROMOTIONAL_SPAM_IGNORED.value
            )

        # Step 2: Extract Available Balance first to avoid collision with Tx Amount
        post_bal: Optional[float] = None
        bal_match = self.BALANCE_PATTERN.search(norm_body)
        bal_span = None
        if bal_match:
            post_bal = self.normalize_amount_str(bal_match.group(1))
            bal_span = bal_match.span()

        # Step 3: Extract Transaction Amount
        tx_amount: Optional[float] = None
        for m in self.AMOUNT_PATTERN.finditer(norm_body):
            # Ensure this amount is not the available balance
            if bal_span and (m.start() >= bal_span[0] and m.end() <= bal_span[1] + 5):
                continue
            cand_amt = self.normalize_amount_str(m.group(1))
            if cand_amt is not None and cand_amt > 0:
                tx_amount = cand_amt
                break

        # Step 4: Extract Masked Account / Card and Account Tail Digits
        masked_acct: Optional[str] = None
        tail_digits: Optional[str] = None
        acct_match = self.ACCOUNT_PATTERN.search(norm_body)
        if acct_match:
            raw_acct = acct_match.group(1).strip()
            masked_acct = f"A/c {raw_acct}"
            digits_only = re.sub(r"\D", "", raw_acct)
            if len(digits_only) >= 3:
                tail_digits = digits_only[-4:] if len(digits_only) >= 4 else digits_only[-3:]

        # Step 5: Extract UTR / RRN
        utr: Optional[str] = None
        utr_match = self.UTR_EXPLICIT_PATTERN.search(norm_body)
        if utr_match:
            utr = utr_match.group(1).strip()
        else:
            num12_matches = self.UTR_NUMERIC_12_PATTERN.findall(norm_body)
            for cand12 in num12_matches:
                # Disambiguate from mobile or timestamp
                if cand12 != tail_digits and not cand12.startswith("17") and not self._PHONE_WITH_91.match(cand12):
                    utr = cand12
                    break

        # Step 6: Extract Counterparty VPA or Name
        counterparty: Optional[str] = None
        vpa_match = self.VPA_PATTERN.search(norm_body)
        if vpa_match:
            counterparty = vpa_match.group(1).strip()
        else:
            # Look for recipient after 'to ' or 'from '
            to_match = re.search(r"\bto\s+([A-Za-z0-9\s.\-_]+?)(?:\s+on|\s+UPI|\s+Ref|\.|$)", norm_body, re.IGNORECASE)
            if to_match:
                counterparty = to_match.group(1).strip()

        # Step 7: Determine Payment Rail
        payment_rail = "INTERNAL_TRANSFER"
        if "UPI" in norm_body.upper() or counterparty and "@" in counterparty:
            payment_rail = "UPI"
        elif "IMPS" in norm_body.upper():
            payment_rail = "IMPS"
        elif "NEFT" in norm_body.upper():
            payment_rail = "NEFT"
        elif "RTGS" in norm_body.upper():
            payment_rail = "RTGS"
        elif "ATM" in norm_body.upper() or "CASH" in norm_body.upper():
            payment_rail = "ATM"
        elif "POS" in norm_body.upper():
            payment_rail = "POS"

        # Step 8: Categorize Event & Extract Specialized Tokens
        special_token: Optional[str] = None

        # Category 6: LIEN_HOLD_OR_FREEZE_ALERT
        # "call 1930 to report" is advice printed on ordinary alerts, so the number alone is not evidence of a hold.
        if self._LIEN_WORDS.search(norm_body) or (self._HOLD_WORD.search(norm_body) and self._CYBER_REF.search(norm_body)):
            ncrp_match = self.NCRP_ACK_PATTERN.search(norm_body)
            if ncrp_match:
                special_token = ncrp_match.group(1).strip()
            else:
                num_matches = re.findall(r"\b(33\d{12,13}|\d{14,15})\b", norm_body)
                if num_matches:
                    special_token = num_matches[0]
                elif utr:
                    special_token = utr

            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.LIEN_HOLD_OR_FREEZE_ALERT.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
                atm_location_or_otp_digits=special_token,
            )

        # Category 3: ATM_CASH_WITHDRAWAL
        if self._ATM_WORDS.search(norm_body) and (
            "debited" in body_lower or "withdrawn" in body_lower
        ):
            loc_match = re.search(r"\b(?:at|ATM)\s+([A-Za-z0-9\s\-]+?)(?:\s+on|\.|$)", norm_body)
            if loc_match:
                special_token = loc_match.group(1).strip()
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.ATM_CASH_WITHDRAWAL.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail="ATM",
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
                atm_location_or_otp_digits=special_token,
            )

        # Category 4: BENEFICIARY_ADDITION_ALERT
        if ("beneficiary" in body_lower or "payee" in body_lower) and any(
            k in body_lower for k in ("added", "registered", "activated", "cooling")
        ):
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.BENEFICIARY_ADDITION_ALERT.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
            )

        # Category 5: OTP_AUTHENTICATION_CODE
        if self._OTP_WORDS.search(norm_body) and not any(
            k in body_lower for k in ("debited", "credited")
        ):
            otp_match = re.search(r"\b(\d{4,8})\b", norm_body)
            if otp_match:
                special_token = otp_match.group(1)
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.OTP_AUTHENTICATION_CODE.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                atm_location_or_otp_digits=special_token,
            )

        # Category 9: FAILED_OR_DECLINED_TX
        if any(k in body_lower for k in ("failed", "declined", "unsuccessful", "dishonoured", "insufficient balance")):
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.FAILED_OR_DECLINED_TX.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
            )

        # Direction comes from the first explicit debit or credit word in the message. "A/c debited ... beneficiary
        # credited" is a debit for the account holder; a message with neither word has no stated direction.
        d_hit = self._DEBIT_WORDS.search(norm_body)
        c_hit = self._CREDIT_WORDS.search(norm_body)
        direction = None
        if d_hit and (not c_hit or d_hit.start() < c_hit.start()):
            direction = "DEBIT"
        elif c_hit:
            direction = "CREDIT"

        # Category 1: TX_DEBIT_OUTFLOW
        if direction == "DEBIT":
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.TX_DEBIT_OUTFLOW.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
            )

        # Category 2: TX_CREDIT_INFLOW
        if direction == "CREDIT":
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.TX_CREDIT_INFLOW.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
            )

        # An amount with no debit or credit word: the direction is not recorded, so none is claimed.
        if tx_amount is not None:
            return ParsedFinancialSMSFields(
                sms_event_category=FinancialSMSCategory.UNCLASSIFIED.value,
                amount_inr_decimal=tx_amount,
                post_tx_available_balance_inr=post_bal,
                masked_account_or_card=masked_acct,
                account_tail_digits=tail_digits,
                payment_rail=payment_rail,
                utr_or_rrn_reference=utr,
                counterparty_vpa_or_name=counterparty,
            )

        return ParsedFinancialSMSFields(
            sms_event_category=FinancialSMSCategory.UNCLASSIFIED.value
        )
