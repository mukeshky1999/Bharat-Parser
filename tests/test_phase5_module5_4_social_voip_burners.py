"""
Test Suite: Phase 5, Module 5.4 — Mainstream Social, Cross-Border VoIP & Virtual Burner Number Decoders.
Covers:
  - Sub-Engine 5.4A: Meta Ecosystem (Instagram Direct 16-digit us timestamps, quoted replies; FB Messenger MSYS).
  - Sub-Engine 5.4B: Snapchat Arroyo Protobuf decoding & UUID join; Discord Simple Cache & Snowflake math.
  - Sub-Engine 5.4C: Cross-Border VoIP (Botim, IMO, WeChat, LINE, Viber).
  - Sub-Engine 5.4D: Virtual Burner Numbers (+1 / +44) & Local Messenger Account OTP Bridge.
Complies with Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
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
from src.social_voip.models import (
    SocialPlatform,
    SocialAccountRole,
    SocialMessageDirection,
    SocialContentCategory,
    SocialAccountRecord,
    SocialMessageRecord,
    BurnerBridgeRecord,
    discord_snowflake_to_unix_ms,
    format_utc_iso_us,
    format_utc_iso_ms,
)
from src.social_voip.meta_decoder import MetaDecoder
from src.social_voip.snapchat_discord_decoder import SnapchatDiscordDecoder
from src.social_voip.cross_border_voip_decoder import CrossBorderVoIPDecoder
from src.social_voip.burner_bridge import BurnerBridge
from src.social_voip.engine import SocialVoIPBurnerEngine


# ---------------------------------------------------------------------------
# Test 1: Instagram 16-Digit Microsecond Timestamp & Quoted-Reply Recovery
# ---------------------------------------------------------------------------

def test_instagram_microsecond_timestamp_and_unsent_quoted_reply():
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Verifies that Sub-Engine 5.4A parses direct_<user_id>.db, converts the 16-digit
    Unix microsecond timestamp 1762348800123456 to ISO-8601 UTC with microsecond
    precision ('2025-11-05T13:20:00.123456Z'), and recovers parent message text
    from the embedded replied_to_message JSON even if the parent was unsent.
    """
    base_dir = Path("./.workspace_tmp/test_instagram_sandbox")
    dbs_dir = base_dir / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    db_path = dbs_dir / "direct_178414.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE threads (
            thread_id TEXT PRIMARY KEY,
            viewer_id TEXT NOT NULL,
            named TEXT,
            last_activity_time INTEGER,
            thread_info TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE messages (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL,
            thread_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            message_type TEXT,
            text TEXT,
            message TEXT
        )
    """)

    thread_info_json = json.dumps({
        "recipients": [
            {"pk": "178414", "username": "local_suspect", "full_name": "Target Suspect"},
            {"pk": "998877", "username": "hawala_boss", "full_name": "Dubai Master"}
        ]
    })
    cur.execute(
        "INSERT INTO threads VALUES ('th_direct_1', '178414', 'Hawala Dubai Chat', 1762348800123456, ?)",
        (thread_info_json,),
    )

    msg_payload = {
        "text": "Done, cash collected",
        "replied_to_message": {
            "user_id": "998877",
            "text": "Send the OTP to +971501234567"
        }
    }
    cur.execute("""
        INSERT INTO messages (message_id, thread_id, sender_id, timestamp, message_type, text, message)
        VALUES ('msg_101', 'th_direct_1', '178414', 1762348800123456, 'text', 'Done, cash collected', ?)
    """, (json.dumps(msg_payload),))

    conn.commit()
    conn.close()

    # Decode with MetaDecoder
    decoder = MetaDecoder()
    accounts, messages = decoder.decode_instagram_database(str(db_path), app_instance_id=1, source_vfs_file_id=601)

    assert len(accounts) >= 2
    owner_rec = [a for a in accounts if a.native_platform_id == "178414"][0]
    assert owner_rec.username_or_handle == "local_suspect"

    assert len(messages) == 1
    msg = messages[0]
    assert msg.platform_name == SocialPlatform.INSTAGRAM
    assert msg.native_message_id == "msg_101"
    assert msg.message_text == "Done, cash collected"
    assert msg.quoted_reply_text == "Send the OTP to +971501234567"
    assert msg.sent_utc_iso == "2025-11-05T13:20:00.123456Z"
    assert msg.sent_utc_ns == 1762348800123456000


# ---------------------------------------------------------------------------
# Test 2: Snapchat arroyo.db Binary Protobuf Chat & UUID Join Test
# ---------------------------------------------------------------------------

def test_snapchat_arroyo_protobuf_and_uuid_join():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Parses Snapchat arroyo.db conversation_message where sender_id is a 16-byte binary UUID,
    joins with main.db Friend.userId to resolve the @username handle, and decodes the
    nested Protocol Buffer message_content to extract plaintext chat text.
    """
    base_dir = Path("./.workspace_tmp/test_snapchat_sandbox")
    dbs_dir = base_dir / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    main_db_path = dbs_dir / "main.db"
    arroyo_db_path = dbs_dir / "arroyo.db"

    for p in [main_db_path, arroyo_db_path]:
        if p.exists():
            p.unlink()

    # 1. Setup main.db with Friend table
    conn_m = sqlite3.connect(main_db_path)
    cur_m = conn_m.cursor()
    cur_m.execute("""
        CREATE TABLE Friend (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId TEXT NOT NULL,
            username TEXT NOT NULL,
            displayName TEXT
        )
    """)
    # Target UUID: 00112233-4455-6677-8899-aabbccddeeff
    sender_uuid_str = "00112233-4455-6677-8899-aabbccddeeff"
    sender_uuid_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    cur_m.execute("INSERT INTO Friend (userId, username, displayName) VALUES (?, 'dealer_snap', 'Street Vendor')", (sender_uuid_str,))
    conn_m.commit()
    conn_m.close()

    # 2. Build binary Protobuf payload for Snapchat message:
    # Field 4: Length-delimited sub-message
    #   Field 1: Length-delimited string "Meet near station"
    chat_text = "Meet near station".encode("utf-8")
    sub_field_tag = (1 << 3) | 2  # field 1, length-delimited
    sub_pb = bytes([sub_field_tag, len(chat_text)]) + chat_text
    outer_field_tag = (4 << 3) | 2  # field 4, length-delimited
    pb_payload = bytes([outer_field_tag, len(sub_pb)]) + sub_pb

    # 3. Setup arroyo.db with conversation_message
    conn_a = sqlite3.connect(arroyo_db_path)
    cur_a = conn_a.cursor()
    cur_a.execute("""
        CREATE TABLE conversation_message (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_conversation_id TEXT NOT NULL,
            server_message_id TEXT NOT NULL,
            sender_id BLOB NOT NULL,
            creation_timestamp INTEGER NOT NULL,
            content_type INTEGER NOT NULL,
            message_content BLOB NOT NULL
        )
    """)
    cur_a.execute("""
        INSERT INTO conversation_message (client_conversation_id, server_message_id, sender_id, creation_timestamp, content_type, message_content)
        VALUES ('conv_snap_1', 'mid_snap_99', ?, 1700000000000, 1, ?)
    """, (sender_uuid_bytes, pb_payload))
    conn_a.commit()
    conn_a.close()

    # Decode with SnapchatDiscordDecoder
    decoder = SnapchatDiscordDecoder()
    accounts, messages = decoder.decode_snapchat_sandbox(str(base_dir), app_instance_id=2, source_vfs_file_id=602)

    assert len(accounts) >= 1
    assert accounts[0].username_or_handle == "dealer_snap"

    assert len(messages) == 1
    msg = messages[0]
    assert msg.platform_name == SocialPlatform.SNAPCHAT
    assert "@dealer_snap" in (msg.sender_id_and_handle or "")
    assert msg.message_text == "Meet near station"
    assert msg.content_category == SocialContentCategory.TEXT


# ---------------------------------------------------------------------------
# Test 3: Discord Simple Cache (*_0) API JSON & Snowflake Math Test
# ---------------------------------------------------------------------------

def test_discord_simple_cache_and_snowflake_timestamp_math():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Verifies Twitter/Discord 64-bit Snowflake timestamp computation:
      Unix Milliseconds = (Snowflake_ID >> 22) + 1420070400000
    and harvests message JSON payloads from simulated Discord HTTP Simple Cache (*_0) files.
    """
    # 1. Verify Snowflake ID timestamp computation
    # Spec example: Snowflake ID "1303377185623048192"
    snowflake_id = 1303377185623048192
    computed_ms = discord_snowflake_to_unix_ms(snowflake_id)
    # Expected: (1303377185623048192 >> 22) + 1420070400000 = 1730816400000 ms
    assert computed_ms == 1730816400000

    # 2. Setup Discord Simple Cache directory structure
    base_dir = Path("./.workspace_tmp/test_discord_sandbox")
    cache_dir = base_dir / "cache" / "Cache_Data"
    cache_dir.mkdir(parents=True, exist_ok=True)

    api_messages = [
        {
            "id": "1303377185623048192",
            "channel_id": "999888777666555444",
            "content": "Deploy the crypto drainer script on staging",
            "timestamp": "2024-11-05T14:20:00.000000+00:00",
            "author": {
                "id": "111222333444555666",
                "username": "drainer_lead",
                "global_name": "ZeroDay Exploit",
                "bot": False
            },
            "attachments": []
        }
    ]

    cache_file = cache_dir / "c1a2b3d4_0"
    raw_cache_payload = {
        "request_url": "https://discord.com/api/v9/channels/999888777666555444/messages?limit=50",
        "body_json": api_messages
    }
    cache_file.write_text(json.dumps(raw_cache_payload), encoding="utf-8")

    decoder = SnapchatDiscordDecoder()
    accounts, messages = decoder.decode_discord_sandbox(str(base_dir), app_instance_id=3, source_vfs_file_id=603)

    assert len(accounts) >= 1
    acc = accounts[0]
    assert acc.username_or_handle == "drainer_lead"
    assert acc.platform_name == SocialPlatform.DISCORD

    assert len(messages) == 1
    msg = messages[0]
    assert msg.platform_name == SocialPlatform.DISCORD
    assert msg.native_message_id == "1303377185623048192"
    assert msg.message_text == "Deploy the crypto drainer script on staging"
    assert msg.sent_utc_ns == 1730816400000000000


# ---------------------------------------------------------------------------
# Test 4: Burner Number (+1) to Local Telegram Account OTP Bridge Test
# ---------------------------------------------------------------------------

def test_burner_number_to_local_telegram_otp_bridge_and_master_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 8.4.
    Extracts virtual number +14158901234 from TextNow database, intercepts the
    registration OTP ('Telegram code: 44912'), correlates with a local Telegram
    account profile registered to '14158901234', and validates master SQLite export.
    """
    base_dir = Path("./.workspace_tmp/test_burner_sandbox")
    base_dir.mkdir(parents=True, exist_ok=True)

    textnow_db = base_dir / "textnow_data.db"
    if textnow_db.exists():
        textnow_db.unlink()

    # 1. Setup TextNow SQLite database
    conn = sqlite3.connect(textnow_db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE user (
            id INTEGER PRIMARY KEY,
            username TEXT,
            phone_number TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            contact_value TEXT,
            message_text TEXT,
            date INTEGER,
            message_direction INTEGER
        )
    """)

    cur.execute("INSERT INTO user VALUES (1, 'anon_mule_1', '+14158901234')")
    cur.execute("""
        INSERT INTO messages VALUES (1, 'Telegram', 'Telegram code: 44912', 1700000000000, 1)
    """)
    conn.commit()
    conn.close()

    # 2. Local Telegram Accounts Directory to cross-reference
    local_messenger_accounts = [
        {
            "platform": "TELEGRAM",
            "account_slot": "account1",
            "phone_e164": "+14158901234",
            "user_id": 5566778899,
            "username": "dark_vendor"
        }
    ]

    # 3. Process Burner Bridge
    bridge = BurnerBridge()
    burner_records = bridge.process_burner_database(
        db_path=str(textnow_db),
        app_name="TextNow",
        app_instance_id=4,
        local_messenger_accounts=local_messenger_accounts
    )

    assert len(burner_records) == 1
    rec = burner_records[0]
    assert rec.burner_app_name == "TextNow"
    assert rec.assigned_virtual_number == "+14158901234"
    assert rec.intercepted_otp_service == "TELEGRAM"
    assert rec.intercepted_otp_code == "44912"
    assert rec.is_linked_to_local_messenger == 1
    assert "Telegram Slot account1" in (rec.linked_messenger_details or "")

    # 4. Master SQLite Export Validation
    export_db = Path("./.workspace_tmp/social_voip_and_burner_engine.sqlite")
    if export_db.exists():
        export_db.unlink()

    sample_accounts = [
        SocialAccountRecord(
            platform_name=SocialPlatform.BOTIM,
            app_instance_id=5,
            account_role=SocialAccountRole.REMOTE_CONTACT_OR_FRIEND,
            native_platform_id="botim_user_971",
            username_or_handle="dubai_handler",
            linked_phone_e164="+971501234567",
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        )
    ]
    sample_messages = [
        SocialMessageRecord(
            platform_name=SocialPlatform.BOTIM,
            app_instance_id=5,
            source_vfs_file_id=605,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            thread_or_channel_id="botim_th_1",
            native_message_id="bmsg_1",
            direction="INCOMING_RECEIVED",
            sender_id_and_handle="+971501234567",
            content_category=SocialContentCategory.TEXT,
            message_text="Hawala cash delivered to Al Rigga",
            sent_utc_ns=1700000000000000000,
            sent_utc_iso="2023-11-14T22:13:20.000000Z",
        )
    ]

    engine = SocialVoIPBurnerEngine()
    engine.export_to_sqlite(
        accounts=sample_accounts,
        messages=sample_messages,
        burner_records=burner_records,
        output_db_path=str(export_db),
    )

    assert export_db.exists()
    conn_out = sqlite3.connect(export_db)
    cur_out = conn_out.cursor()

    cur_out.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur_out.fetchall()}
    assert "social_and_voip_accounts_directory" in tables
    assert "social_and_voip_messages_ledger" in tables
    assert "virtual_burner_numbers_and_otp_bridge" in tables

    cur_out.execute("SELECT COUNT(*) FROM social_and_voip_accounts_directory")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM social_and_voip_messages_ledger")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM virtual_burner_numbers_and_otp_bridge")
    assert cur_out.fetchone()[0] == 1

    conn_out.close()
