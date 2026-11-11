"""
Tests for Phase 5, Module 5.2: The Telegram & Signal Deep Decoders
(Telegram cache4.db TL-Schema Binary Deserializer, Multi-Account Discovery,
Secret Chats & Signal Signal.sqlite / signal.db Disappearing & Edited Message Engine).
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

import json
import os
from pathlib import Path
import sqlite3
import struct
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.telegram_signal.models import (
    PlatformFamily,
    PeerType,
    LocalRoleInGroup,
    ThreadClassification,
    MessagingPeerRecord,
    MessagingMessageRecord,
)
from src.telegram_signal.tl_deserializer import (
    TLStreamReader,
    decode_tl_user,
    decode_tl_message,
)
from src.telegram_signal.telegram_decoder import (
    TelegramDatabaseDecoder,
    discover_telegram_accounts,
)
from src.telegram_signal.signal_decoder import (
    SignalDatabaseDecoder,
)
from src.telegram_signal.engine import TelegramSignalEngine


def _encode_tl_string(s: str) -> bytes:
    """Encodes a string using Telegram TL length prefix and 4-byte alignment."""
    raw = s.encode("utf-8")
    l = len(raw)
    if l < 254:
        header = bytes([l]) + raw
    else:
        header = bytes([254, l & 0xFF, (l >> 8) & 0xFF, (l >> 16) & 0xFF]) + raw
    pad = (4 - (len(header) % 4)) % 4
    return header + (b"\x00" * pad)


# ---------------------------------------------------------------------------
# Test 1: Telegram TL-Schema 4-Byte Aligned String & users.data Phone Unpacker
# ---------------------------------------------------------------------------

def test_telegram_tl_stream_reader_and_user_data_unpacker():
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Validates TL primitive stream reader 4-byte alignment advancing by exactly 16 bytes
    for a 12-byte phone number string, and unpacks TL_user binary blob to extract
    phone_number_e164 = '+919876543210' and username_handle = '@vikram_hawala'.
    """
    # 1. Test standalone TLStreamReader 4-byte padding behavior
    phone_str = "919876543210"
    encoded_phone = _encode_tl_string(phone_str)
    # 1 byte length (0x0C = 12) + 12 string bytes = 13 bytes -> padded to 16 bytes
    assert len(encoded_phone) == 16
    assert encoded_phone == b"\x0c919876543210\x00\x00\x00"

    reader = TLStreamReader(encoded_phone)
    extracted_str = reader.read_tl_string()
    assert extracted_str == phone_str
    assert reader.cursor == 16  # Advances cursor by exactly 16 bytes!

    # 2. Build synthetic TL_user binary blob
    # constructor_id: 0x215c4438
    # flags: (1 << 1) [first_name] | (1 << 2) [last_name] | (1 << 3) [username] | (1 << 4) [phone] = 30
    constructor_id = 0x215c4438
    flags = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4)
    user_id = 1234567890

    tl_blob = (
        struct.pack("<IIQ", constructor_id, flags, user_id)
        + _encode_tl_string("Vikram")
        + _encode_tl_string("Singh")
        + _encode_tl_string("vikram_hawala")
        + _encode_tl_string("919876543210")
    )

    # Decode using decode_tl_user
    parsed_user = decode_tl_user(tl_blob)
    assert parsed_user["user_id"] == 1234567890
    assert parsed_user["first_name"] == "Vikram"
    assert parsed_user["last_name"] == "Singh"
    assert parsed_user["username"] == "vikram_hawala"
    assert parsed_user["phone"] == "919876543210"

    # 3. Test SQLite users table parsing
    tmp_db_path = Path("./.workspace_tmp/test_tg_users.db")
    tmp_db_path.parent.mkdir(parents=True, exist_ok=True)
    if tmp_db_path.exists():
        tmp_db_path.unlink()

    conn = sqlite3.connect(tmp_db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, status INT, data BLOB)")
    cur.execute(
        "INSERT INTO users (uid, name, status, data) VALUES (?, ?, ?, ?)",
        (user_id, "Vikram;;;Singh;;;vikram_hawala", 0, tl_blob),
    )
    conn.commit()
    conn.close()

    decoder = TelegramDatabaseDecoder()
    peers = decoder.extract_peers(str(tmp_db_path), account_slot_name="account0_primary", app_instance_id=1)
    assert len(peers) == 1
    peer = peers[0]

    assert peer.platform_family == PlatformFamily.TELEGRAM
    assert peer.native_peer_id == str(user_id)
    assert peer.phone_number_e164 == "+919876543210"
    assert peer.username_handle == "@vikram_hawala"
    assert peer.display_or_group_name == "Vikram Singh"

    if tmp_db_path.exists():
        tmp_db_path.unlink()


# ---------------------------------------------------------------------------
# Test 2: Telegram Multi-Account (account1) & Saved Messages Vault
# ---------------------------------------------------------------------------

def test_telegram_multi_account_and_saved_messages_vault():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Discovers secondary multi-account slot (/files/account1/cache4.db and userconfig1.xml),
    extracts the self owner user profile (self_user_id = 5566778899),
    and correctly labels thread uid == 5566778899 as SAVED_MESSAGES_SELF_VAULT.
    """
    base_tg_dir = Path("./.workspace_tmp/test_tg_multiaccount")
    import shutil
    if base_tg_dir.exists():
        shutil.rmtree(base_tg_dir, ignore_errors=True)
    files_dir = base_tg_dir / "files" / "account1"
    prefs_dir = base_tg_dir / "shared_prefs"
    files_dir.mkdir(parents=True, exist_ok=True)
    prefs_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create userconfig1.xml with self_user_id
    config_xml = prefs_dir / "userconfig1.xml"
    config_xml.write_text(
        '<map><long name="clientUserId" value="5566778899"/><string name="user">dummy</string></map>',
        encoding="utf-8",
    )

    # 2. Build TL_message blob
    constructor_msg = 0x38116eed
    flags_msg = 256  # has_from_id
    msg_id = 101
    peer_user_const = 0x595c107c
    from_peer = struct.pack("<IQ", peer_user_const, 5566778899)
    to_peer = struct.pack("<IQ", peer_user_const, 5566778899)
    date = 1700000000
    text_data = _encode_tl_string("BIP39: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    tl_msg_blob = struct.pack("<III", constructor_msg, flags_msg, msg_id) + from_peer + to_peer + struct.pack("<I", date) + text_data

    # 3. Create cache4.db inside account1/
    db_path = files_dir / "cache4.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE dialogs (did INTEGER PRIMARY KEY, date INT, unread_count INT, last_mid INT)")
    cur.execute("CREATE TABLE messages_v2 (mid INTEGER PRIMARY KEY, uid INTEGER, read_state INT, send_state INT, date INT, data BLOB, out INT, ttl INT, media INT, replydata BLOB, imp INT, mention INT)")
    cur.execute("CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, status INT, data BLOB)")
    cur.execute("CREATE TABLE chats (uid INTEGER PRIMARY KEY, name TEXT, data BLOB)")

    cur.execute("INSERT INTO dialogs VALUES (5566778899, 1700000000, 0, 101)")
    cur.execute("INSERT INTO messages_v2 (mid, uid, read_state, send_state, date, data, out, ttl) VALUES (101, 5566778899, 1, 0, 1700000000, ?, 1, 0)", (tl_msg_blob,))
    conn.commit()
    conn.close()

    # 4. Discover accounts and parse
    accounts = discover_telegram_accounts(str(base_tg_dir))
    assert len(accounts) >= 1
    acc = [a for a in accounts if a["account_slot_name"] == "account1"][0]
    assert acc["self_user_id"] == 5566778899

    decoder = TelegramDatabaseDecoder()
    messages = decoder.extract_messages(
        db_path=str(db_path),
        account_slot_name="account1",
        self_user_id=5566778899,
        app_instance_id=1,
        source_vfs_file_id=201,
    )

    assert len(messages) == 1
    msg = messages[0]
    assert msg.thread_or_dialog_id == "5566778899"
    assert msg.thread_classification == ThreadClassification.SAVED_MESSAGES_SELF_VAULT
    assert "BIP39: abandon abandon" in (msg.message_text or "")


# ---------------------------------------------------------------------------
# Test 3: Signal Message Edit Revision & Disappearing Message Recovery
# ---------------------------------------------------------------------------

def test_signal_message_edit_revision_and_disappearing_recovery():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Parses Signal database (signal.db / Signal.sqlite) linking original pre-edit
    message rows into the latest revision row's pre_edit_or_diff_json,
    and recovers an expired disappearing message (expires_in = 30000).
    """
    tmp_sig_path = Path("./.workspace_tmp/test_signal.db")
    tmp_sig_path.parent.mkdir(parents=True, exist_ok=True)
    if tmp_sig_path.exists():
        tmp_sig_path.unlink()

    conn = sqlite3.connect(tmp_sig_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE recipient (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            e164 TEXT,
            aci TEXT,
            pni TEXT,
            username TEXT,
            system_joined_name TEXT,
            profile_joined_name TEXT,
            group_id TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE thread (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            from_recipient_id INTEGER,
            to_recipient_id INTEGER,
            date_sent INTEGER NOT NULL,
            date_received INTEGER,
            body TEXT,
            expires_in INTEGER DEFAULT 0,
            expire_started INTEGER DEFAULT 0,
            view_once INTEGER DEFAULT 0,
            latest_revision_id INTEGER,
            original_message_id INTEGER,
            revision_number INTEGER DEFAULT 0
        )
    """)

    # Insert Recipient & Thread
    cur.execute("""
        INSERT INTO recipient (_id, e164, aci, system_joined_name, profile_joined_name)
        VALUES (1, '+919876543210', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'Suspect One', 'Vikram')
    """)
    cur.execute("INSERT INTO thread (_id, recipient_id) VALUES (1, 1)")

    # Message 10: Original Pre-Edit message
    cur.execute("""
        INSERT INTO message (_id, thread_id, from_recipient_id, date_sent, body, latest_revision_id, revision_number)
        VALUES (10, 1, 1, 1700000000000, 'Send 5 BTC to bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 11, 0)
    """)

    # Message 11: Final Edited Revision
    cur.execute("""
        INSERT INTO message (_id, thread_id, from_recipient_id, date_sent, body, latest_revision_id, original_message_id, revision_number)
        VALUES (11, 1, 1, 1700000060000, 'Send 5 documents', NULL, 10, 1)
    """)

    # Message 12: Expired Disappearing Message
    cur.execute("""
        INSERT INTO message (_id, thread_id, from_recipient_id, date_sent, body, expires_in, expire_started)
        VALUES (12, 1, 1, 1700000120000, 'Self destructing secret instructions', 30000, 1700000120000)
    """)

    conn.commit()
    conn.close()

    decoder = SignalDatabaseDecoder()
    messages = decoder.extract_messages(
        db_path=str(tmp_sig_path),
        app_instance_id=1,
        source_vfs_file_id=301,
    )

    assert len(messages) >= 2
    # Verify edit history linkage
    edited_msg = [m for m in messages if m.native_message_id == "11"][0]
    assert edited_msg.is_edited_or_past_revision == 1
    assert edited_msg.pre_edit_or_diff_json is not None
    assert "Send 5 BTC to bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" in edited_msg.pre_edit_or_diff_json

    # Verify disappearing timer
    disappearing_msg = [m for m in messages if m.native_message_id == "12"][0]
    assert disappearing_msg.ttl_disappearing_seconds == 30

    if tmp_sig_path.exists():
        tmp_sig_path.unlink()


# ---------------------------------------------------------------------------
# Test 4: Master SQLite Database Export & Schema Compliance
# ---------------------------------------------------------------------------

def test_telegram_signal_master_sqlite_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 7 & 8.
    Exports decoded Telegram and Signal accounts, peers, and messages into
    telegram_and_signal_engine.sqlite and validates schema and constraints.
    """
    tmp_export_path = Path("./.workspace_tmp/telegram_and_signal_engine.sqlite")
    if tmp_export_path.exists():
        tmp_export_path.unlink()

    engine = TelegramSignalEngine()

    # Register Peer
    peer = MessagingPeerRecord(
        platform_family=PlatformFamily.TELEGRAM,
        app_instance_id=1,
        account_slot_name="account0_primary",
        peer_type=PeerType.USER_CONTACT,
        native_peer_id="1234567890",
        secondary_uuid_or_pni=None,
        username_handle="@crypto_king_99",
        phone_number_e164="+919876543210",
        display_or_group_name="Vikram Singh",
        local_role_in_group=LocalRoleInGroup.NOT_APPLICABLE,
        is_scam_or_fake_flagged=0,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )
    engine.register_peers([peer])

    # Register Message
    msg = MessagingMessageRecord(
        app_instance_id=1,
        account_slot_name="account0_primary",
        source_vfs_file_id=401,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        thread_or_dialog_id="1234567890",
        thread_classification=ThreadClassification.DIRECT_1ON1_CHAT,
        native_message_id="555",
        direction="INCOMING_RECEIVED",
        sender_peer_id="1234567890",
        sender_display_and_handle="Vikram Singh (@crypto_king_99)",
        message_text="Meeting at midnight for cash drop",
        is_edited_or_past_revision=0,
        pre_edit_or_diff_json=None,
        forwarded_from_info_json=None,
        reply_to_msg_id=None,
        ttl_disappearing_seconds=0,
        is_view_once_media=0,
        media_attachment_json=None,
        inline_bot_buttons_json=None,
        sent_utc_ns=1700000000000000000,
        sent_utc_iso="2023-11-14T22:13:20.000000Z",
    )
    engine.register_messages([msg])

    # Export
    exported = engine.export_to_master_db(str(tmp_export_path))
    assert os.path.exists(exported)

    conn = sqlite3.connect(exported)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    assert "messaging_accounts_and_peers_directory" in tables
    assert "telegram_and_signal_messages_ledger" in tables

    # Query Peer
    cur.execute("SELECT platform_family, native_peer_id, phone_number_e164, username_handle FROM messaging_accounts_and_peers_directory")
    p_row = cur.fetchone()
    assert p_row[0] == PlatformFamily.TELEGRAM.value
    assert p_row[1] == "1234567890"
    assert p_row[2] == "+919876543210"
    assert p_row[3] == "@crypto_king_99"

    # Query Message
    cur.execute("SELECT thread_classification, native_message_id, message_text FROM telegram_and_signal_messages_ledger")
    m_row = cur.fetchone()
    assert m_row[0] == ThreadClassification.DIRECT_1ON1_CHAT.value
    assert m_row[1] == "555"
    assert m_row[2] == "Meeting at midnight for cash drop"

    conn.close()
    if tmp_export_path.exists():
        tmp_export_path.unlink()
