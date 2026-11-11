"""
Test Suite: Phase 5, Module 5.3 — High-OpSec, Decentralized & Privacy Messengers Deep Decoder.
Covers:
  - Sub-Engine 5.3A: Session (Oxen Onion-Routed, 66-hex Session IDs, SOGS Open Group servers).
  - Sub-Engine 5.3B: SimpleX Chat (Zero-ID Pairwise Queues, item_deleted = 1, WAL recovery, smp:// relays).
  - Sub-Engine 5.3C: Zangi 10-digit virtual numbers & XMPP Conversations OMEMO fingerprints.
  - Sub-Engine 5.3D: Cross-App Out-of-Band Covert Handle Cross-Linker and Master SQLite Export.
Complies with Phase 5 Module 5.3 Specification and AGENTS.md Constitution.
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
from src.high_opsec.models import (
    OpSecPlatformName,
    IdentityRole,
    MessageDirection,
    CovertInvitePlatform,
    OpSecIdentityRecord,
    OpSecMessageRecord,
    CovertInviteDiscoveryRecord,
    is_valid_session_id,
    is_valid_threema_id,
    is_valid_zangi_number,
    is_valid_matrix_id,
    is_valid_simplex_invite,
)
from src.high_opsec.session_decoder import SessionDecoder
from src.high_opsec.simplex_decoder import SimpleXDecoder
from src.high_opsec.privacy_messengers_decoder import PrivacyMessengersDecoder
from src.high_opsec.cross_app_hunter import CrossAppCovertHandleHunter
from src.high_opsec.engine import HighOpSecMessengersEngine


# ---------------------------------------------------------------------------
# Test 1: Session 66-hex ID Validation & SOGS Open Group Decoder
# ---------------------------------------------------------------------------

def test_session_66hex_id_validation_and_sogs_open_group():
    """
    Test 1: Acceptance Test 1 from Spec Section 7.1.
    Verifies that Sub-Engine 5.3A unwraps Session preferences, validates
    the 66-character '05...' Session ID, extracts 1-on-1 private messages,
    and extracts Open Group (SOGS) server URL and room token.
    """
    base_dir = Path("./.workspace_tmp/test_session_sandbox")
    prefs_dir = base_dir / "shared_prefs"
    dbs_dir = base_dir / "databases"
    prefs_dir.mkdir(parents=True, exist_ok=True)
    dbs_dir.mkdir(parents=True, exist_ok=True)

    session_id_owner = "05112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01"
    session_id_sender = "05a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01"

    assert is_valid_session_id(session_id_owner)
    assert is_valid_session_id(session_id_sender)
    assert not is_valid_session_id("04a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01")
    assert not is_valid_session_id("05short")

    # 1. Create network.loki.messenger_preferences.xml
    xml_path = prefs_dir / "network.loki.messenger_preferences.xml"
    xml_content = f"""<map>
        <string name="pref_local_number">{session_id_owner}</string>
        <string name="user_public_key">{session_id_owner}</string>
        <string name="pref_database_unencrypted_secret">00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff</string>
    </map>"""
    xml_path.write_text(xml_content, encoding="utf-8")

    # 2. Create SQLite session.db
    db_path = dbs_dir / "session.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE recipient (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            signal_profile_name TEXT,
            system_display_name TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE thread (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_ids TEXT NOT NULL,
            snippet TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE loki_public_chat_database (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_url TEXT NOT NULL,
            room_token TEXT NOT NULL,
            name TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            address TEXT NOT NULL,
            date INTEGER NOT NULL,
            date_sent INTEGER,
            body TEXT,
            type INTEGER,
            expires_in INTEGER DEFAULT 0
        )
    """)

    # Insert remote contact
    cur.execute(
        "INSERT INTO recipient (address, signal_profile_name, system_display_name) VALUES (?, ?, ?)",
        (session_id_sender, "CryptoViper", "Hawala Coordinator"),
    )
    # Insert open group (SOGS)
    cur.execute(
        "INSERT INTO loki_public_chat_database (server_url, room_token, name) VALUES (?, ?, ?)",
        ("https://open.getsession.org/hawala", "room_token_alpha", "Hawala OTC Exchange"),
    )
    # Insert direct 1-on-1 message
    cur.execute(
        "INSERT INTO sms (thread_id, address, date, date_sent, body, type, expires_in) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, session_id_sender, 1700000000000, 1700000000000, "Send 50,000 USDT to OTC desk", 2, 86400),
    )
    conn.commit()
    conn.close()

    # 3. Decode with SessionDecoder
    decoder = SessionDecoder()
    identities, messages = decoder.decode_sandbox(
        sandbox_path=str(base_dir),
        app_instance_id=1,
        source_vfs_file_id=501,
    )

    assert len(identities) >= 2  # Owner + Contact + SOGS Group
    owner_rec = [i for i in identities if i.identity_role == IdentityRole.LOCAL_DEVICE_OWNER][0]
    assert owner_rec.primary_crypto_handle == session_id_owner

    sogs_rec = [i for i in identities if i.identity_role == IdentityRole.OPEN_COMMUNITY_SERVER][0]
    assert sogs_rec.server_or_relay_url == "https://open.getsession.org/hawala"
    assert sogs_rec.display_or_nickname == "Hawala OTC Exchange"

    assert len(messages) == 1
    msg = messages[0]
    assert msg.sender_crypto_handle == session_id_sender
    assert msg.message_body_text == "Send 50,000 USDT to OTC desk"
    assert msg.ephemeral_ttl_seconds == 86400
    assert msg.app_platform_name == OpSecPlatformName.SESSION


# ---------------------------------------------------------------------------
# Test 2: SimpleX Chat Pairwise Queues, item_deleted = 1 & WAL Recovery
# ---------------------------------------------------------------------------

def test_simplex_chat_pairwise_queues_and_wal_deleted_recovery():
    """
    Test 2: Acceptance Test 2 from Spec Section 7.2.
    Verifies that Sub-Engine 5.3B extracts SimpleX pairwise queues from agent.db,
    detects item_deleted = 1 in chat_items, and recovers pre-deletion message
    text from the uncheckpointed WAL frame with HISTORICAL_COMMITTED_RECORD.
    """
    base_dir = Path("./.workspace_tmp/test_simplex_sandbox")
    dbs_dir = base_dir / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    chat_db_path = dbs_dir / "simplex_v1_chat.db"
    agent_db_path = dbs_dir / "simplex_v1_agent.db"

    for p in [chat_db_path, agent_db_path]:
        if p.exists():
            p.unlink()

    # 1. Setup agent.db (SMP relay queues)
    conn_ag = sqlite3.connect(agent_db_path)
    cur_ag = conn_ag.cursor()
    cur_ag.execute("""
        CREATE TABLE snd_connections (
            conn_id INTEGER PRIMARY KEY,
            contact_id INTEGER NOT NULL,
            relay_server_url TEXT NOT NULL,
            queue_id TEXT NOT NULL
        )
    """)
    cur_ag.execute(
        "INSERT INTO snd_connections VALUES (1, 101, 'smp://relay.darknet-node.org:5223/queue_sec18', 'q_abc123')"
    )
    conn_ag.commit()
    conn_ag.close()

    # 2. Setup chat.db with WAL mode
    conn_ch = sqlite3.connect(chat_db_path)
    cur_ch = conn_ch.cursor()
    cur_ch.execute("PRAGMA journal_mode = WAL")
    cur_ch.execute("""
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            local_display_name TEXT NOT NULL,
            full_name TEXT,
            incognito INTEGER DEFAULT 0
        )
    """)
    cur_ch.execute("""
        CREATE TABLE contacts (
            contact_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            local_display_name TEXT NOT NULL
        )
    """)
    cur_ch.execute("""
        CREATE TABLE chat_items (
            chat_item_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            chat_dir INTEGER NOT NULL,
            item_ts INTEGER NOT NULL,
            item_text TEXT,
            item_content TEXT,
            item_deleted INTEGER DEFAULT 0,
            item_edited INTEGER DEFAULT 0,
            timed_ttl INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    cur_ch.execute("INSERT INTO users VALUES (1, 'ViperLocal', 'Stealth Operator', 1)")
    cur_ch.execute("INSERT INTO contacts VALUES (101, 1, 'Delivery Courier 7')")

    # Step 2a: Insert committed message
    cur_ch.execute(
        "INSERT INTO chat_items VALUES (1, 1, 101, 0, 1700000000000, 'Drop package at Sector 18', '{\"type\":\"text\",\"text\":\"Drop package at Sector 18\"}', 0, 0, 0, '2023-11-14T22:13:20Z')"
    )
    conn_ch.commit()

    # Step 2b: Update message to deleted (item_deleted = 1, item_text = '')
    cur_ch.execute(
        "UPDATE chat_items SET item_deleted = 1, item_text = '' WHERE chat_item_id = 1"
    )
    conn_ch.commit()
    conn_ch.close()

    # 3. Decode with SimpleXDecoder
    decoder = SimpleXDecoder()
    identities, messages = decoder.decode_sandbox(
        sandbox_path=str(base_dir),
        app_instance_id=2,
        source_vfs_file_id=502,
    )

    assert len(identities) >= 2
    # Verify SMP relay queue association
    contact_id = [i for i in identities if i.primary_crypto_handle == "contact_101"][0]
    assert contact_id.server_or_relay_url == "smp://relay.darknet-node.org:5223/queue_sec18"
    assert contact_id.display_or_nickname == "Delivery Courier 7"

    assert len(messages) >= 1
    # Check that deleted message was captured with was_marked_deleted_in_db = 1
    del_msg = [m for m in messages if m.was_marked_deleted_in_db == 1][0]
    assert "Drop package at Sector 18" in (del_msg.message_body_text or "")
    assert del_msg.app_platform_name == OpSecPlatformName.SIMPLEX_CHAT


# ---------------------------------------------------------------------------
# Test 3: Zangi Virtual Numbers & XMPP OMEMO Decoder
# ---------------------------------------------------------------------------

def test_zangi_virtual_numbers_and_xmpp_omemo_decoder():
    """
    Test 3: Acceptance Test 3 from Spec Section 5.1 & 5.4.
    Validates Zangi 10-digit virtual numbers (10-4829-1049) and call logs,
    and XMPP Conversations OMEMO identities and federated JID messages.
    """
    base_dir = Path("./.workspace_tmp/test_privacy_messengers")
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Zangi virtual number validation
    assert is_valid_zangi_number("10-4829-1049")
    assert is_valid_zangi_number("99-1234-5678")
    assert not is_valid_zangi_number("+919876543210")
    assert not is_valid_zangi_number("1234")

    # 2. Setup Zangi Database
    zangi_db = base_dir / "zangi_chat.db"
    if zangi_db.exists():
        zangi_db.unlink()
    conn_z = sqlite3.connect(zangi_db)
    cur_z = conn_z.cursor()
    cur_z.execute("""
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY,
            zangi_number TEXT NOT NULL,
            name TEXT
        )
    """)
    cur_z.execute("""
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_zangi TEXT NOT NULL,
            receiver_zangi TEXT NOT NULL,
            body TEXT,
            timestamp INTEGER NOT NULL
        )
    """)
    cur_z.execute("INSERT INTO contacts VALUES (1, '10-4829-1049', 'Mule Handler Delhi')")
    cur_z.execute(
        "INSERT INTO messages VALUES (1, 'conv_101', '10-4829-1049', '10-9999-8888', 'ATM withdrawal successful', 1700000000000)"
    )
    conn_z.commit()
    conn_z.close()

    # 3. Setup XMPP Conversations Database (eu.siacs.conversations)
    xmpp_db = base_dir / "history"
    if xmpp_db.exists():
        xmpp_db.unlink()
    conn_x = sqlite3.connect(xmpp_db)
    cur_x = conn_x.cursor()
    cur_x.execute("""
        CREATE TABLE accounts (
            uuid TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            server TEXT NOT NULL
        )
    """)
    cur_x.execute("""
        CREATE TABLE conversations (
            uuid TEXT PRIMARY KEY,
            accountUuid TEXT NOT NULL,
            contactJid TEXT NOT NULL
        )
    """)
    cur_x.execute("""
        CREATE TABLE messages (
            uuid TEXT PRIMARY KEY,
            conversationUuid TEXT NOT NULL,
            timeSent INTEGER NOT NULL,
            body TEXT,
            encryption INTEGER,
            fingerprint TEXT
        )
    """)
    cur_x.execute("""
        CREATE TABLE identities (
            accountUuid TEXT NOT NULL,
            jid TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            own INTEGER
        )
    """)

    cur_x.execute("INSERT INTO accounts VALUES ('acc-1', 'vendor_escrow', 'exploit.im')")
    cur_x.execute("INSERT INTO conversations VALUES ('conv-1', 'acc-1', 'buyer@jabber.calyxinstitute.org')")
    cur_x.execute(
        "INSERT INTO messages VALUES ('m-1', 'conv-1', 1700000000000, 'Escrow released for batch #89', 1, 'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01')"
    )
    cur_x.execute(
        "INSERT INTO identities VALUES ('acc-1', 'vendor_escrow@exploit.im', 'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01', 1)"
    )
    conn_x.commit()
    conn_x.close()

    # 4. Decode using PrivacyMessengersDecoder
    decoder = PrivacyMessengersDecoder()
    identities_z, messages_z = decoder.decode_zangi(str(zangi_db), app_instance_id=3)
    assert len(identities_z) >= 1
    assert identities_z[0].primary_crypto_handle == "10-4829-1049"
    assert identities_z[0].app_platform_name == OpSecPlatformName.ZANGI
    assert len(messages_z) >= 1
    assert messages_z[0].message_body_text == "ATM withdrawal successful"

    identities_x, messages_x = decoder.decode_xmpp_conversations(str(xmpp_db), app_instance_id=4)
    assert len(identities_x) >= 1
    assert identities_x[0].primary_crypto_handle == "vendor_escrow@exploit.im"
    assert "a1b2c3d4" in identities_x[0].public_key_or_omemo_fp
    assert identities_x[0].app_platform_name == OpSecPlatformName.XMPP_CONVERSATIONS
    assert len(messages_x) >= 1
    assert messages_x[0].message_body_text == "Escrow released for batch #89"


# ---------------------------------------------------------------------------
# Test 4: Out-of-Band Covert Handle Cross-Linker & Master SQLite Export
# ---------------------------------------------------------------------------

def test_cross_app_hunter_and_master_sqlite_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 6 & 7.3.
    Verifies that CrossAppCovertHandleHunter extracts Session IDs, SimpleX invite links,
    Threema IDs, and Zangi numbers from foreign chat strings (WhatsApp, SMS, Notes),
    and exports all 3 tables to high_opsec_messengers_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/high_opsec_messengers_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    hunter = CrossAppCovertHandleHunter()

    foreign_records = [
        {
            "text": "Delete WhatsApp and message me on Session: 05f8e7d6c5b4a39281706f5e4d3c2b1a0987654321fedcba0987654321fedcba",
            "source": "WhatsApp msgstore.db (Chat with +919876543210)",
            "timestamp": "2023-11-14T22:15:00.000000Z",
        },
        {
            "text": "Connect on SimpleX: https://simplex.chat/contact#/?v=2-7&smp=smp%3A%2F%2Frelay.darknet.org%2Fabc",
            "source": "SMS mmssms.db (Sender: VK-SBIINB)",
            "timestamp": "2023-11-14T22:16:00.000000Z",
        },
        {
            "text": "Backup Threema ID link: https://threema.id/ABCD1234",
            "source": "iOS Notes NoteStore.sqlite",
            "timestamp": "2023-11-14T22:17:00.000000Z",
        },
        {
            "text": "Call me on Zangi number 10-4829-1049 for the cash",
            "source": "Telegram cache4.db",
            "timestamp": "2023-11-14T22:18:00.000000Z",
        },
    ]

    discovered_links = hunter.scan_records(foreign_records)
    assert len(discovered_links) == 4

    p_map = {d.target_opsec_platform: d for d in discovered_links}
    assert CovertInvitePlatform.SESSION_ID_05 in p_map
    assert p_map[CovertInvitePlatform.SESSION_ID_05].extracted_handle_or_uri == "05f8e7d6c5b4a39281706f5e4d3c2b1a0987654321fedcba0987654321fedcba"

    assert CovertInvitePlatform.SIMPLEX_INVITE_URI in p_map
    assert "simplex.chat/contact" in p_map[CovertInvitePlatform.SIMPLEX_INVITE_URI].extracted_handle_or_uri

    assert CovertInvitePlatform.THREEMA_ID_LINK in p_map
    assert "threema.id/ABCD1234" in p_map[CovertInvitePlatform.THREEMA_ID_LINK].extracted_handle_or_uri

    assert CovertInvitePlatform.ZANGI_NUMBER in p_map
    assert p_map[CovertInvitePlatform.ZANGI_NUMBER].extracted_handle_or_uri == "10-4829-1049"

    # Export to master SQLite database
    sample_identities = [
        OpSecIdentityRecord(
            app_platform_name=OpSecPlatformName.SESSION,
            app_instance_id=1,
            identity_role=IdentityRole.LOCAL_DEVICE_OWNER,
            primary_crypto_handle="05112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01",
            display_or_nickname="Session Owner",
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        )
    ]
    sample_messages = [
        OpSecMessageRecord(
            app_platform_name=OpSecPlatformName.SESSION,
            app_instance_id=1,
            source_vfs_file_id=501,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            thread_identifier="thread_1",
            direction="INCOMING_RECEIVED",
            sender_crypto_handle="05a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01",
            message_body_text="Test message",
            sent_utc_ns=1700000000000000000,
            sent_utc_iso="2023-11-14T22:13:20.000000Z",
        )
    ]

    engine = HighOpSecMessengersEngine()
    engine.export_to_sqlite(
        identities=sample_identities,
        messages=sample_messages,
        covert_links=discovered_links,
        output_db_path=str(export_db_path),
    )

    # Validate Tables in high_opsec_messengers_engine.sqlite
    assert export_db_path.exists()
    conn_out = sqlite3.connect(export_db_path)
    cur_out = conn_out.cursor()

    cur_out.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur_out.fetchall()}
    assert "opsec_messenger_identities_and_relays" in tables
    assert "opsec_messenger_messages_ledger" in tables
    assert "cross_app_opsec_invite_links_discovered" in tables

    cur_out.execute("SELECT COUNT(*) FROM opsec_messenger_identities_and_relays")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM opsec_messenger_messages_ledger")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM cross_app_opsec_invite_links_discovered")
    assert cur_out.fetchone()[0] == 4

    conn_out.close()
