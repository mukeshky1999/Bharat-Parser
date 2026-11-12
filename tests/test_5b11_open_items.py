"""Phase 5B.11: the small open items (L-08 NULL direction flag, Q-2b chunk boundary, R-16 LevelDB CRC, Q-1 amount unit)."""
import os
import sqlite3

import pytest

from parsers.enterprise_1tb_chat_and_container_engine import (
    parse_whatsapp_full_forensics, parse_zangi_database, _flag, _direction)


def test_flag_reads_only_zero_and_one():
    assert [_flag(None), _flag(0), _flag(1), _flag(2), _flag("x"), _flag("1")] == [None, 0, 1, None, None, 1]
    assert [_direction(None), _direction(0), _direction(1)] == ["Unknown", "Incoming", "Outgoing"]


def test_whatsapp_null_from_me_is_unknown(tmp_path):
    db = str(tmp_path / "msgstore.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, key_id TEXT, chat_row_id INTEGER, sender_jid_row_id INTEGER, "
              "from_me INTEGER, text_data TEXT, message_type INTEGER, timestamp INTEGER)")
    c.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
    c.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
    c.execute("INSERT INTO jid VALUES (1, '919876543210@s.whatsapp.net')")
    c.execute("INSERT INTO chat VALUES (1, 1)")
    c.execute("INSERT INTO message VALUES (1, 'A', 1, 1, NULL, 'null flag', 0, 1700000000000)")
    c.execute("INSERT INTO message VALUES (2, 'B', 1, 1, 0, 'in', 0, 1700000001000)")
    c.execute("INSERT INTO message VALUES (3, 'C', 1, 1, 1, 'out', 0, 1700000002000)")
    c.commit(); c.close()
    df, _ = parse_whatsapp_full_forensics(db)
    by = {r["Message_Body"]: r for _, r in df.iterrows()}
    assert by["null flag"]["Direction"] == "Unknown"
    assert by["null flag"]["Sender_Identifier"] == "Unknown" and by["null flag"]["Recipient_Identifier"] == "Unknown"
    assert by["null flag"]["Delivery_Status"] == "Unknown"
    assert by["in"]["Direction"] == "Incoming" and by["in"]["Recipient_Identifier"] == "Owner"
    assert by["out"]["Direction"] == "Outgoing" and by["out"]["Sender_Identifier"] == "Owner"


def test_zangi_null_is_outgoing_unknown(tmp_path):
    db = str(tmp_path / "zangi.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender_number TEXT, body TEXT, is_outgoing INTEGER, date INTEGER)")
    c.execute("INSERT INTO messages VALUES (1, '10-2345-6789', 'x', NULL, 1700000000000)")
    c.commit(); c.close()
    df, _ = parse_zangi_database(db)
    assert df.iloc[0]["Direction"] == "Unknown"
