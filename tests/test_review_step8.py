"""Review step 8: a regular expression cannot freeze the search."""
import time

import pandas as pd
import pytest

from parsers import case_search
from parsers.ui_fts5_paginator import CaseUIPaginatorStore

pytestmark = pytest.mark.skipif(case_search._regex is None, reason="the regex package is not installed")


@pytest.fixture
def store(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Application": ["WhatsApp", "WhatsApp"],
        "Message_Body": ["a" * 20000, "hello world"],
        "Sender_Name": ["x", "y"],
    }), evidence_item="EV-001")
    return s


@pytest.mark.parametrize("pattern", [r"((a+))+$", r"(a|aa)*c", r"(a?){25}a{25}c"])
def test_catastrophic_patterns_stop_with_a_reason(store, monkeypatch, pattern):
    monkeypatch.setattr(case_search, "CELL_TIME_LIMIT_S", 0.3)
    t0 = time.monotonic()
    try:
        r = store.search(pattern, mode="regex", tables=["chats"])
    except case_search.SearchError:
        return                                   # refused up front is also acceptable
    assert time.monotonic() - t0 < 10                      # bounded, whatever the pattern does
    if not r["complete"]:
        assert "too long" in r["stopped_reason"] and r["total_is_exact"] is False


def test_a_slow_pattern_is_stopped_and_says_so(store, monkeypatch):
    monkeypatch.setattr(case_search, "CELL_TIME_LIMIT_S", 0.3)
    r = store.search(r"(a?){25}a{25}c", mode="regex", tables=["chats"])
    assert r["complete"] is False and "too long" in r["stopped_reason"] and r["total_is_exact"] is False


def test_ordinary_patterns_still_work(store):
    r = store.search(r"hel+o", mode="regex", tables=["chats"])
    assert r["complete"] is True and r["total"] == 1


def test_keyword_search_names_the_tables_it_could_not_search(store):
    r = store.search("hello", mode="keyword", tables=["chats", "notifications"])
    assert "notifications" in r["tables_not_searched"] and "chats" not in r["tables_not_searched"]
