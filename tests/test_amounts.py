"""INR amount parsing (REVIEW_FINDINGS C-10)."""
import pandas as pd
import pytest

from src.core.amounts import AMOUNT_VALID_RE, find_amounts, parse_amount
from parsers.heuristic_engine import clean_amount_series
from src.dlt.sms_grammar import FinancialSMSGrammarParser


@pytest.mark.parametrize("text,expected", [
    ("Rs.500", 500.0), ("Rs. 500", 500.0), ("₹1,234.50", 1234.5), ("INR 2000", 2000.0),
    ("Rs 1,00,000", 100000.0), ("Rs.1,50,000.00", 150000.0), ("12,34,567.8", 1234567.8),
    ("1,500,000", 1500000.0), ("500.00 Dr", 500.0), ("1240", 1240.0),
])
def test_parse_amount_accepts(text, expected):
    assert parse_amount(text) == expected


@pytest.mark.parametrize("text", ["500 for 2 items", "INR 2000 on 12 Jan", "abc", "", "1,2", "5 0 0"])
def test_parse_amount_rejects(text):
    assert parse_amount(text) is None


def test_find_amounts_in_text():
    assert find_amounts("Rs.1500.00 debited, bal Rs 1,00,000") == [1500.0, 100000.0]
    assert find_amounts("call 1930 now") == []


def test_series_cleaning_is_strict():
    out = clean_amount_series(pd.Series(["Rs.500", "500 for 2 items", "INR 2000 on 12 Jan", "1,00,000"]))
    assert out.iloc[0] == 500.0
    assert pd.isna(out.iloc[1]) and pd.isna(out.iloc[2])
    assert out.iloc[3] == 100000.0


def test_sms_grammar_amounts_not_truncated():
    p = FinancialSMSGrammarParser()
    for body, expected in [
        ("Rs.1500.00 debited from A/c XX1234", 1500.0),
        ("INR 25000 credited to A/c XX1234", 25000.0),
        ("Rs 1240 sent via UPI", 1240.0),
    ]:
        res = p.parse_sms(body)
        assert float(res.amount_inr_decimal) == expected, body
