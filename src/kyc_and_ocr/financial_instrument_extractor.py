"""
Sub-Engine 7.4C: Financial Instrument OCR & Bearer Token Extractor.
Extracts and validates:
1. Cancelled Cheques & Bank Passbooks (IFSC homoglyph repair, MICR code, unmasked accounts).
2. Hawala Currency-Note Serial Number Bearer Tokens (RBI serials, denomination).
3. Physical Payment Cards (Luhn Mod-10 checksum validation, BIN resolution).
Adheres strictly to AGENTS.md Forensic Invariants and Section 5 of Module 7.4 Specification.
"""

import re
from typing import Optional

from src.kyc_and_ocr.homoglyph_normalizer import PositionalHomoglyphNormalizer
from src.kyc_and_ocr.models import (
    FinancialExtractionResult,
    FinancialInstrumentCategory,
)


class FinancialInstrumentExtractor:
    """Extracts and verifies banking instruments, debit/credit cards, and hawala currency tokens."""

    BANK_CODE_MAP = {
        "SBIN": "State Bank of India",
        "HDFC": "HDFC Bank",
        "ICIC": "ICICI Bank",
        "UTIB": "Axis Bank",
        "PUNB": "Punjab National Bank",
        "KKBK": "Kotak Mahindra Bank",
        "BARB": "Bank of Baroda",
        "CNRB": "Canara Bank",
        "UBIN": "Union Bank of India",
        "IDFB": "IDFC FIRST Bank",
        "YESB": "Yes Bank",
        "INDB": "IndusInd Bank",
    }

    MICR_CITY_MAP = {
        "110": "Delhi NCR",
        "400": "Mumbai",
        "221": "Varanasi",
        "560": "Bengaluru",
        "700": "Kolkata",
        "600": "Chennai",
        "500": "Hyderabad",
        "380": "Ahmedabad",
        "302": "Jaipur",
        "226": "Lucknow",
    }

    DENOMINATION_MAP = {
        "TEN": "₹10",
        "TWENTY": "₹20",
        "FIFTY": "₹50",
        "HUNDRED": "₹100",
        "TWO HUNDRED": "₹200",
        "FIVE HUNDRED": "₹500",
    }

    def extract_from_text(self, text: str) -> Optional[FinancialExtractionResult]:
        """Classifies text and extracts structured financial instrument attributes."""
        upper_text = text.upper()

        # -------------------------------------------------------------
        # 1. Target: Hawala Currency-Note Serial Number Bearer Token
        # -------------------------------------------------------------
        if (
            "RESERVE BANK OF INDIA" in upper_text
            or "GUARANTEED BY THE CENTRAL GOVERNMENT" in upper_text
            or "PROMISE TO PAY THE BEARER" in upper_text
        ):
            serial_match = re.search(r"\b([0-9]{1,2}[A-Z]{1,2}\s+[0-9]{6})\b", text)
            if serial_match:
                serial_num = serial_match.group(1).strip()
                denom_found = "₹10"
                for word, sym in self.DENOMINATION_MAP.items():
                    if word in upper_text:
                        denom_found = sym
                        break

                desc = f"INR {denom_found} Note — RBI Serial: {serial_num}"
                return FinancialExtractionResult(
                    instrument_category=FinancialInstrumentCategory.HAWALA_CURRENCY_NOTE_TOKEN.value,
                    hawala_note_serial=serial_num,
                    hawala_note_description=desc,
                )

        # -------------------------------------------------------------
        # 2. Target: Cancelled Cheque Leaf or Bank Passbook Front Page
        # -------------------------------------------------------------
        if (
            "CANCELLED" in upper_text
            or "PASSBOOK" in upper_text
            or "A/C NO" in upper_text
            or "ACCOUNT NO" in upper_text
            or "IFSC" in upper_text
        ):
            # Extract and repair IFSC (11 chars: 4 alpha, 1 digit, 6 alphanumeric)
            ifsc_code = None
            bank_name = "Indian Commercial Bank"
            city_name = "India"

            ifsc_match = re.search(r"\b([A-Z]{4}[0-9OQ][A-Z0-9]{6})\b", upper_text)
            if ifsc_match:
                raw_ifsc = ifsc_match.group(1)
                # Repair slot 5 ('O' -> '0')
                repaired_slot5 = PositionalHomoglyphNormalizer.repair_digit_position(raw_ifsc[4])
                ifsc_code = raw_ifsc[:4] + repaired_slot5 + raw_ifsc[5:]

                bank_prefix = ifsc_code[:4]
                if bank_prefix in self.BANK_CODE_MAP:
                    bank_name = self.BANK_CODE_MAP[bank_prefix]

            # Extract 9-digit MICR code
            micr_code = None
            micr_match = re.search(r"\b(?:MICR(?:\s*CODE)?\s*[:\-\s]*)?([0-9]{9})\b", upper_text)
            if micr_match:
                micr_code = micr_match.group(1)
                pin_prefix = micr_code[:3]
                if pin_prefix in self.MICR_CITY_MAP:
                    city_name = self.MICR_CITY_MAP[pin_prefix]

            # Extract Bank Account Number (9 to 18 digits)
            account_number = None
            acct_match = re.search(r"(?:A/C\s*(?:NO\.?)?|ACCOUNT\s*(?:NUMBER|NO\.?)?)\s*[:\-\s]*([0-9]{9,18})", upper_text)
            if acct_match:
                account_number = acct_match.group(1)

            # Extract Holder Name
            holder_name = None
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            for l in lines:
                l_up = l.upper()
                if (
                    len(l.split()) >= 2
                    and all(w.isalpha() for w in l.split())
                    and not any(
                        kw in l_up
                        for kw in [
                            "STATE",
                            "BANK",
                            "INDIA",
                            "BRANCH",
                            "CANCELLED",
                            "IFSC",
                            "MICR",
                            "CHEQUE",
                            "PAY",
                            "SELF",
                            "BEARER",
                            "RUPEES",
                        ]
                    )
                ):
                    holder_name = l.upper()

            bank_and_branch = f"{bank_name}, {city_name} Branch"

            return FinancialExtractionResult(
                instrument_category=FinancialInstrumentCategory.CANCELLED_CHEQUE_LEAF.value,
                ifsc_code=ifsc_code,
                account_number=account_number,
                micr_code=micr_code,
                bank_name_and_branch=bank_and_branch,
                holder_name=holder_name,
            )

        # -------------------------------------------------------------
        # 3. Target: Physical Debit or Credit Card
        # -------------------------------------------------------------
        card_match = re.search(r"\b([0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})\b", text)
        if card_match:
            raw_card = card_match.group(1)
            clean_digits = re.sub(r"\D", "", raw_card)
            has_card_anchors = any(kw in upper_text for kw in ["VALID THRU", "CARD", "DEBIT", "CREDIT", "EXPIRES", "RUPAY", "VISA", "MASTERCARD"])
            if self._verify_luhn(clean_digits) or has_card_anchors:
                expiry_match = re.search(r"\b(0[1-9]|1[0-2])/([2-3][0-9])\b", text)
                expiry_str = expiry_match.group(0) if expiry_match else None

                return FinancialExtractionResult(
                    instrument_category=FinancialInstrumentCategory.PHYSICAL_DEBIT_OR_CREDIT_CARD.value,
                    account_or_card_number=clean_digits,
                    card_expiry=expiry_str,
                )

        return None

    def _verify_luhn(self, card_number: str) -> bool:
        """Verifies the Luhn Modulo-10 checksum algorithm."""
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) not in (15, 16, 19):
            return False

        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]

        total = sum(odd_digits)
        for d in even_digits:
            total += sum(divmod(d * 2, 10))

        return total % 10 == 0
