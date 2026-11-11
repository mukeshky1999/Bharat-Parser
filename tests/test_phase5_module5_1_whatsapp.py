"""
Tests for Phase 5, Module 5.1: The WhatsApp Ecosystem Deep Decoder
(msgstore.db, wa.db, ChatStorage.sqlite, @lid Unmasking, Revoked Message Recovery,
Linked Companion Devices & Modded APK Anti-Revoke Tables).
Complies with Section 3 & 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

import json
import os
from pathlib import Path
import sqlite3
import zlib
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.whatsapp.models import (
    IdentityType,
    MessageDirection,
    MessageTypeCategory,
    WhatsAppIdentityRecord,
    WhatsAppMessageRecord,
    WhatsAppCompanionDeviceRecord,
)
from src.whatsapp.decoder import (
    WhatsAppDatabaseDecoder,
    build_unified_identity_directory,
    unmask_lid,
)
from src.whatsapp.recovery import (
    reconstruct_revoked_messages,
    merge_historical_crypt15_backup,
)
from src.whatsapp.engine import WhatsAppEcosystemEngine
from src.crypto.whatsapp import derive_crypt15_key


@pytest.fixture
def tmp_wa_dir():
    """Isolated temporary directory inside ./.workspace_tmp/ for WhatsApp testing."""
    import shutil
    test_dir = Path("./.workspace_tmp/test_phase5_module5_1_whatsapp")
    if test_dir.exists():
        shutil.rmtree(test_dir, ignore_errors=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir
    if test_dir.exists():
        shutil.rmtree(test_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 1: @lid to Phone Number Unmasking & Push Name Attribution
# ---------------------------------------------------------------------------

def test_whatsapp_lid_unmasking_and_identity_resolution(tmp_wa_dir):
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Validates building the unified JID <-> LID identity dictionary, unmasking
    privacy @lid identifiers (164829104928172@lid -> +919876543210), and attaching
    the self-assigned Push Name ('~ Hawala King') from wa.db wa_contacts.
    """
    msgstore_path = tmp_wa_dir / "msgstore.db"
    wa_db_path = tmp_wa_dir / "wa.db"

    # 1. Setup msgstore.db
    conn_m = sqlite3.connect(msgstore_path)
    cur_m = conn_m.cursor()
    cur_m.execute("""
        CREATE TABLE jid (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            server TEXT NOT NULL,
            agent INTEGER DEFAULT 0,
            device INTEGER DEFAULT 0,
            type INTEGER DEFAULT 0,
            raw_string TEXT NOT NULL
        )
    """)
    cur_m.execute("""
        CREATE TABLE jid_map (
            lid_row_id INTEGER NOT NULL,
            jid_row_id INTEGER NOT NULL
        )
    """)
    cur_m.execute("""
        CREATE TABLE chat (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid_row_id INTEGER NOT NULL,
            subject TEXT,
            created_timestamp INTEGER
        )
    """)
    cur_m.execute("""
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_row_id INTEGER NOT NULL,
            from_me INTEGER NOT NULL,
            key_id TEXT NOT NULL,
            sender_jid_row_id INTEGER,
            status INTEGER,
            timestamp INTEGER NOT NULL,
            received_timestamp INTEGER,
            message_type INTEGER NOT NULL,
            text_data TEXT,
            starred INTEGER DEFAULT 0,
            lookup_tables INTEGER DEFAULT 0,
            orig_flags INTEGER DEFAULT 0
        )
    """)

    # Insert JIDs: 10 = Group, 12 = Phone JID, 50 = Privacy LID
    cur_m.execute("INSERT INTO jid (_id, user, server, raw_string) VALUES (10, '120363048291048291', 'g.us', '120363048291048291@g.us')")
    cur_m.execute("INSERT INTO jid (_id, user, server, raw_string) VALUES (12, '919876543210', 's.whatsapp.net', '919876543210@s.whatsapp.net')")
    cur_m.execute("INSERT INTO jid (_id, user, server, raw_string) VALUES (50, '164829104928172', 'lid', '164829104928172@lid')")

    # Insert jid_map mapping LID (50) -> Phone JID (12)
    cur_m.execute("INSERT INTO jid_map (lid_row_id, jid_row_id) VALUES (50, 12)")

    # Insert chat: Group
    cur_m.execute("INSERT INTO chat (_id, jid_row_id, subject) VALUES (1, 10, 'Mule Coordination Gang')")

    # Insert message sent by LID (50) inside the group
    cur_m.execute("""
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (1, 1, 0, '3EB077112233', 50, 1700000000000, 0, 'Transfer ₹5,00,000 to safe account')
    """)
    conn_m.commit()
    conn_m.close()

    # 2. Setup wa.db
    conn_w = sqlite3.connect(wa_db_path)
    cur_w = conn_w.cursor()
    cur_w.execute("""
        CREATE TABLE wa_contacts (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid TEXT NOT NULL,
            lid TEXT,
            display_name TEXT,
            wa_name TEXT,
            number TEXT,
            status TEXT,
            unseen_msg_count INTEGER
        )
    """)
    cur_w.execute("""
        INSERT INTO wa_contacts (jid, lid, display_name, wa_name, number, status)
        VALUES ('919876543210@s.whatsapp.net', '164829104928172@lid', 'Vikram Contacts', '~ Hawala King', '919876543210', 'Always busy')
    """)
    conn_w.commit()
    conn_w.close()

    # 3. Parse with WhatsAppDatabaseDecoder
    decoder = WhatsAppDatabaseDecoder()
    identities = decoder.extract_identities(msgstore_path=str(msgstore_path), wa_db_path=str(wa_db_path), app_instance_id=1)
    messages = decoder.extract_messages(msgstore_path=str(msgstore_path), app_instance_id=1, source_vfs_file_id=101)

    # 4. Verify Identity Unmasking
    assert len(identities) >= 2
    # Find LID record
    lid_records = [i for i in identities if i.linked_lid_string == "164829104928172@lid"]
    assert len(lid_records) == 1
    lid_record = lid_records[0]
    assert lid_record.phone_jid_string == "919876543210@s.whatsapp.net"
    assert lid_record.extracted_phone_e164 == "+919876543210"
    assert lid_record.remote_profile_push_name == "~ Hawala King"

    # 5. Verify Message Attribution
    assert len(messages) == 1
    msg = messages[0]
    assert msg.chat_jid == "120363048291048291@g.us"
    assert msg.sender_raw_lid == "164829104928172@lid"
    assert msg.sender_resolved_phone_jid == "+919876543210"
    assert "~ Hawala King" in (msg.sender_push_and_saved_name or "")
    assert msg.message_text_or_caption == "Transfer ₹5,00,000 to safe account"


# ---------------------------------------------------------------------------
# Test 2: Quoted-Reply Revoked Message Reconstruction
# ---------------------------------------------------------------------------

def test_whatsapp_quoted_reply_revoked_message_reconstruction(tmp_wa_dir):
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Tests recovery of a 'Delete for Everyone' revoked message (type 15, text_data=NULL)
    using the surviving quote in message_quoted attached to a reply message.
    """
    msgstore_path = tmp_wa_dir / "msgstore_revoked.db"
    conn = sqlite3.connect(msgstore_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE jid (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            server TEXT NOT NULL,
            agent INTEGER DEFAULT 0,
            device INTEGER DEFAULT 0,
            type INTEGER DEFAULT 0,
            raw_string TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE chat (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            jid_row_id INTEGER NOT NULL,
            subject TEXT,
            created_timestamp INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_row_id INTEGER NOT NULL,
            from_me INTEGER NOT NULL,
            key_id TEXT NOT NULL,
            sender_jid_row_id INTEGER,
            status INTEGER,
            timestamp INTEGER NOT NULL,
            received_timestamp INTEGER,
            message_type INTEGER NOT NULL,
            text_data TEXT,
            starred INTEGER DEFAULT 0,
            lookup_tables INTEGER DEFAULT 0,
            orig_flags INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE message_quoted (
            message_row_id INTEGER NOT NULL,
            key_id TEXT NOT NULL,
            sender_jid_row_id INTEGER,
            text_data TEXT
        )
    """)

    # Insert direct chat JID
    cur.execute("INSERT INTO jid (_id, user, server, raw_string) VALUES (1, '919811223344', 's.whatsapp.net', '919811223344@s.whatsapp.net')")
    cur.execute("INSERT INTO chat (_id, jid_row_id, subject) VALUES (1, 1, NULL)")

    # Message 100: Sent, then revoked by sender (type 15, text_data = NULL)
    cur.execute("""
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (100, 1, 0, '3EB09988', 1, 1700000010000, 15, NULL)
    """)

    # Message 101: Reply to Message 100 with surviving quote
    cur.execute("""
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (101, 1, 1, '3EB09989', 1, 1700000070000, 0, 'OK done')
    """)
    cur.execute("""
        INSERT INTO message_quoted (message_row_id, key_id, sender_jid_row_id, text_data)
        VALUES (101, '3EB09988', 1, 'Delete this account number 0123456789 after transfer')
    """)

    conn.commit()
    conn.close()

    decoder = WhatsAppDatabaseDecoder()
    messages = decoder.extract_messages(msgstore_path=str(msgstore_path), app_instance_id=1, source_vfs_file_id=102)

    # Run revoked message reconstruction
    reconstructed = reconstruct_revoked_messages(messages, msgstore_path=str(msgstore_path))

    # Find Message 100
    revoked_msg = [m for m in reconstructed if m.message_key_id == "3EB09988"][0]

    assert revoked_msg.is_revoked_deleted_for_everyone == 1
    assert revoked_msg.message_type_category == MessageTypeCategory.REVOKED_DELETED_FOR_EVERYONE
    assert revoked_msg.recovered_pre_revoke_or_edit_text == "Delete this account number 0123456789 after transfer"
    assert revoked_msg.recovery_classification == ResidualConfidence.RECONSTRUCTED_RECORD
    assert revoked_msg.recovery_source_detail == "QUOTED_REPLY_SURVIVOR"


# ---------------------------------------------------------------------------
# Test 3: .crypt15 Rolling Backup Historical Diff-Recovery
# ---------------------------------------------------------------------------

def test_whatsapp_crypt15_rolling_backup_diff_recovery(tmp_wa_dir):
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Deletes an entire chat from the live msgstore.db while leaving it inside
    a rolling .crypt15 backup file. Decrypts the backup via Module 2.2 and
    merges the missing messages into the master ledger tagged as CRYPT15_ROLLING_BACKUP_DIFF.
    """
    live_db_path = tmp_wa_dir / "msgstore_live.db"
    backup_db_path = tmp_wa_dir / "msgstore_backup_plain.db"
    crypt15_path = tmp_wa_dir / "msgstore-2026-11-04.1.db.crypt15"

    # 1. Setup base schema helper
    def create_wa_schema(db_path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, agent INT, device INT, type INT, raw_string TEXT)")
        cur.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INT, subject TEXT, created_timestamp INT)")
        cur.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INT, from_me INT, key_id TEXT, sender_jid_row_id INT, status INT, timestamp INT, received_timestamp INT, message_type INT, text_data TEXT, starred INT, lookup_tables INT, orig_flags INT)")
        conn.commit()
        return conn

    # Setup live DB with only 1 message (Message A)
    conn_live = create_wa_schema(live_db_path)
    cur_l = conn_live.cursor()
    cur_l.execute("INSERT INTO jid VALUES (1, '919876543210', 's.whatsapp.net', 0, 0, 0, '919876543210@s.whatsapp.net')")
    cur_l.execute("INSERT INTO chat VALUES (1, 1, 'Regular Chat', 1700000000000)")
    cur_l.execute("INSERT INTO message VALUES (1, 1, 1, 'MSG_A', 1, 0, 1700000000000, 1700000000000, 0, 'Hello friend', 0, 0, 0)")
    conn_live.commit()
    conn_live.close()

    # Setup backup DB with Message A AND Message B (Message B was deleted in live)
    conn_bkp = create_wa_schema(backup_db_path)
    cur_b = conn_bkp.cursor()
    cur_b.execute("INSERT INTO jid VALUES (1, '919876543210', 's.whatsapp.net', 0, 0, 0, '919876543210@s.whatsapp.net')")
    cur_b.execute("INSERT INTO jid VALUES (2, '919999988888', 's.whatsapp.net', 0, 0, 0, '919999988888@s.whatsapp.net')")
    cur_b.execute("INSERT INTO chat VALUES (1, 1, 'Regular Chat', 1700000000000)")
    cur_b.execute("INSERT INTO chat VALUES (2, 2, 'Deleted Incriminating Chat', 1699900000000)")
    cur_b.execute("INSERT INTO message VALUES (1, 1, 1, 'MSG_A', 1, 0, 1700000000000, 1700000000000, 0, 'Hello friend', 0, 0, 0)")
    cur_b.execute("INSERT INTO message VALUES (2, 2, 0, 'MSG_B', 2, 0, 1699900000000, 1699900000000, 0, 'Secret cash delivery meeting at warehouse', 0, 0, 0)")
    conn_bkp.commit()
    conn_bkp.close()

    # 2. Encrypt backup_db_path into a real .crypt15 file
    root_key = os.urandom(32)
    k_enc = derive_crypt15_key(root_key)
    iv = os.urandom(16)
    proto_body = bytes([0x12, 0x10]) + iv
    header = bytes([len(proto_body)]) + proto_body

    plain_db_bytes = backup_db_path.read_bytes()
    compressed = zlib.compress(plain_db_bytes)
    aesgcm = AESGCM(k_enc)
    ct_and_tag = aesgcm.encrypt(iv, compressed, None)
    ciphertext = ct_and_tag[:-16]
    gcm_tag = ct_and_tag[-16:]
    dummy_md5 = os.urandom(16)

    crypt15_path.write_bytes(header + ciphertext + gcm_tag + dummy_md5)

    # 3. Extract live messages first
    decoder = WhatsAppDatabaseDecoder()
    live_messages = decoder.extract_messages(msgstore_path=str(live_db_path), app_instance_id=1, source_vfs_file_id=103)
    assert len(live_messages) == 1
    assert live_messages[0].message_key_id == "MSG_A"

    # 4. Merge rolling backup
    merged_messages = merge_historical_crypt15_backup(
        live_messages=live_messages,
        crypt15_path=str(crypt15_path),
        root_key_32=root_key,
        app_instance_id=1,
        source_vfs_file_id=104,
    )

    # 5. Verify that MSG_B was recovered
    assert len(merged_messages) == 2
    msg_b = [m for m in merged_messages if m.message_key_id == "MSG_B"][0]
    assert msg_b.message_text_or_caption == "Secret cash delivery meeting at warehouse"
    assert msg_b.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD
    assert msg_b.recovery_source_detail == "CRYPT15_ROLLING_BACKUP_DIFF"


# ---------------------------------------------------------------------------
# Test 4: Companion Devices Audit, Modded Anti-Revoke & Master SQLite Export
# ---------------------------------------------------------------------------

def test_whatsapp_companion_devices_and_master_sqlite_export(tmp_wa_dir):
    """
    Test 4: Acceptance Test 4 from Spec Section 7 & 8.
    Audits linked companion devices (WhatsApp Web / Desktop), modded APK anti-revoke tables,
    and exports all records into whatsapp_ecosystem_engine.sqlite.
    Verifies schema integrity, table structure, and constraint validation.
    """
    db_export_path = tmp_wa_dir / "whatsapp_ecosystem_engine.sqlite"
    if db_export_path.exists():
        db_export_path.unlink()

    engine = WhatsAppEcosystemEngine()

    # 1. Register Identities
    ident = WhatsAppIdentityRecord(
        app_instance_id=1,
        jid_row_id=12,
        phone_jid_string="919876543210@s.whatsapp.net",
        linked_lid_string="164829104928172@lid",
        extracted_phone_e164="+919876543210",
        address_book_display_name="Vikram Boss",
        remote_profile_push_name="~ Hawala King",
        status_about_text="Available for hawala deals",
        identity_type=IdentityType.USER,
    )
    engine.register_identities([ident])

    # 2. Register Messages
    msg = WhatsAppMessageRecord(
        app_instance_id=1,
        source_vfs_file_id=101,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        recovery_source_detail="LIVE_ACTIVE_TABLE",
        chat_jid="120363048291048291@g.us",
        chat_display_title="Mule Coordination Gang",
        message_key_id="3EB077112233",
        direction=MessageDirection.INCOMING_RECEIVED,
        sender_resolved_phone_jid="+919876543210",
        sender_raw_lid="164829104928172@lid",
        sender_push_and_saved_name="Vikram Boss (~ Hawala King)",
        message_type_category=MessageTypeCategory.TEXT,
        message_text_or_caption="Transfer ₹5,00,000 to safe account",
        is_revoked_deleted_for_everyone=0,
        recovered_pre_revoke_or_edit_text=None,
        quoted_parent_key_id=None,
        quoted_parent_text_preview=None,
        forwarding_hop_score=0,
        ephemeral_timer_seconds=0,
        media_metadata_json=None,
        reactions_json=json.dumps([{"sender": "+919876543210", "emoji": "👍", "timestamp": 1700000005000}]),
        sent_utc_ns=1700000000000000000,
        sent_utc_iso="2023-11-14T22:13:20.000000Z",
        delivered_utc_iso="2023-11-14T22:13:21.000000Z",
        read_blue_tick_utc_iso="2023-11-14T22:13:25.000000Z",
    )
    engine.register_messages([msg])

    # 3. Register Companion Devices (WhatsApp Web / Desktop)
    comp1 = WhatsAppCompanionDeviceRecord(
        app_instance_id=1,
        companion_device_jid="919876543210:12@s.whatsapp.net",
        companion_os_and_browser="Windows (Chrome)",
        paired_login_utc_iso="2023-11-10T10:00:00.000000Z",
        last_active_utc_iso="2023-11-14T22:30:00.000000Z",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )
    comp2 = WhatsAppCompanionDeviceRecord(
        app_instance_id=1,
        companion_device_jid="919876543210:15@s.whatsapp.net",
        companion_os_and_browser="Mac OS (Desktop)",
        paired_login_utc_iso="2023-11-05T08:00:00.000000Z",
        last_active_utc_iso="2023-11-12T14:15:00.000000Z",
        recovery_classification=ResidualConfidence.HISTORICAL_COMMITTED_RECORD,
    )
    engine.register_companion_devices([comp1, comp2])

    # 4. Export to Master Database
    exported_path = engine.export_to_master_db(str(db_export_path))
    assert os.path.exists(exported_path)

    # 5. Query and Verify Tables & Constraints
    conn = sqlite3.connect(exported_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    assert "whatsapp_identities_and_lid_map" in tables
    assert "whatsapp_messages_master_ledger" in tables
    assert "whatsapp_companion_devices_audit" in tables

    # Verify identities row
    cur.execute("SELECT phone_jid_string, linked_lid_string, extracted_phone_e164, remote_profile_push_name FROM whatsapp_identities_and_lid_map")
    id_row = cur.fetchone()
    assert id_row[0] == "919876543210@s.whatsapp.net"
    assert id_row[1] == "164829104928172@lid"
    assert id_row[2] == "+919876543210"
    assert id_row[3] == "~ Hawala King"

    # Verify message row
    cur.execute("SELECT message_key_id, sender_resolved_phone_jid, message_text_or_caption, reactions_json FROM whatsapp_messages_master_ledger")
    msg_row = cur.fetchone()
    assert msg_row[0] == "3EB077112233"
    assert msg_row[1] == "+919876543210"
    assert msg_row[2] == "Transfer ₹5,00,000 to safe account"
    assert "👍" in msg_row[3]

    # Verify companion devices rows
    cur.execute("SELECT companion_os_and_browser, recovery_classification FROM whatsapp_companion_devices_audit ORDER BY companion_uid")
    comp_rows = cur.fetchall()
    assert len(comp_rows) == 2
    assert comp_rows[0][0] == "Windows (Chrome)"
    assert comp_rows[0][1] == ResidualConfidence.ORIGINAL_RECORD.value
    assert comp_rows[1][0] == "Mac OS (Desktop)"
    assert comp_rows[1][1] == ResidualConfidence.HISTORICAL_COMMITTED_RECORD.value

    conn.close()
