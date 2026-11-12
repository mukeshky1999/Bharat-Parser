"""
Single INR amount parser (REVIEW_FINDINGS C-10).

Handles western grouping (1,500,000) and Indian lakh/crore grouping (15,00,000), an optional
currency prefix (Rs / Rs. / INR / ₹), and decimals. Anything that is not exactly an amount is
rejected (returns None) instead of being silently mangled: "500 for 2 items" is not 5002.
"""
from __future__ import annotations

import re
from typing import Optional

# Digits with optional group separators: 1,234 / 12,34,567 / 1234567 ; then optional paise.
_NUMBER = r"(?:\d{1,3}(?:,\d{2,3})+|\d+)(?:\.\d{1,2})?"

# Currency-prefixed amount inside free text (SMS, notes, carved strings). Group 1 = the number.
AMOUNT_VALID_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:rs\.?|inr|₹|amt\.?)\s*[:\-]?\s*({_NUMBER})(?![\d]|,\d)",
    re.IGNORECASE,
)

_FULL_RE = re.compile(rf"^\s*(?:(?:rs\.?|inr|₹)\s*)?(-?{_NUMBER})\s*(?:/-)?\s*(?:dr|cr)?\.?\s*$", re.IGNORECASE)


def to_float(number_text: str) -> float:
    """Converts a matched number (group separators allowed) to float."""
    return float(number_text.replace(",", ""))


def parse_amount(text: object) -> Optional[float]:
    """Parses a whole value as an INR amount. Returns None if it is not exactly one amount."""
    if text is None:
        return None
    if isinstance(text, (int, float)):
        return float(text)
    m = _FULL_RE.match(str(text))
    if not m:
        return None
    return to_float(m.group(1))


def find_amounts(text: str) -> list[float]:
    """All currency-prefixed amounts in free text."""
    return [to_float(m.group(1)) for m in AMOUNT_VALID_RE.finditer(text or "")]
