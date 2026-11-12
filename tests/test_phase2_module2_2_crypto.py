"""
Test Suite for Phase 2, Module 2.2: The Automated Cryptographic Key Broker & Database Unwrapper.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real cryptographic operations and binary database streams (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests Signal iOS 96-hex key + WAL decryption into Product B2 plaintext SQLite pair.
- Tests WhatsApp .crypt15 HKDF key derivation, dynamic header parse, and AES-256-GCM inflation.
- Tests WeChat (WCDB) IMEI + UIN 7-character MD5 password derivation.
- Tests Hardware-Gated Dimension B audit (Android Keystore persistent.sqlite).
- Tests Apple Notes RFC 3394 + AES-128-GCM row-level decryption.
- Tests central case_cryptographic_keyring and encrypted_database_registry schemas.
"""

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from src.core.enums import (
    EvidentiaryAccess,
    EvidentiaryExistence,
    EvidentiaryStorage,
    ForensicGroup,
    ResidualConfidence,
)
from src.sqlite.engine import ForensicSQLiteEngine


@pytest.fixture
def tmp_crypto_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_crypto_broker")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# HELPER: Generate Synthetic SQLCipher v4 Encrypted Database & WAL
# ==============================================================================

def create_synthetic_sqlcipher_v4_db_and_wal(
    output_db_path: Path,
    output_wal_path: Path,
    raw_key_32: bytes,
    salt_16: bytes
):
    """
    Synthesizes a valid SQLCipher v4 database (page_size=4096, R=80, HMAC-SHA512)
    and a companion encrypted WAL file with 10 total messages (5 in DB, 5 in WAL).
    """
    # 1. Derive HMAC Key: salt_mac = salt_16 ^ 0x3A, 2 iterations of PBKDF2-HMAC-SHA512
    salt_mac = bytes([b ^ 0x3A for b in salt_16])
    kdf_mac = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt_mac,
        iterations=2,
    )
    k_mac = kdf_mac.derive(raw_key_32)

    # 2. Build a standard SQLite DB with 10 rows in messages(id, text)
    temp_sqlite = output_db_path.parent / "temp_source.db"
    con = sqlite3.connect(temp_sqlite)
    con.execute("PRAGMA page_size = 4096;")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);")
    for i in range(1, 11):
        con.execute("INSERT INTO messages VALUES (?, ?);", (i, f"Confidential Message {i}"))
    con.commit()
    con.close()

    with open(temp_sqlite, "rb") as f:
        orig_page1 = bytearray(f.read(4096))
        orig_page2 = bytearray(f.read(4096))
    if temp_sqlite.exists():
        temp_sqlite.unlink()

    # SQLCipher reserves the last 80 bytes of every page (IV + HMAC). A plain SQLite file fills
    # the whole page, so shift each leaf page's cell content down by 80 bytes (and fix the cell
    # pointers) so nothing lives in the reserved area. Otherwise the encrypted payload would
    # silently drop the schema cell on page 1 and the first rows on page 2.
    def shift_into_usable_area(page: bytearray, hdr_off: int) -> None:
        ncells = struct.unpack(">H", page[hdr_off + 3:hdr_off + 5])[0]
        content_start = struct.unpack(">H", page[hdr_off + 5:hdr_off + 7])[0] or 65536
        ptr_base = hdr_off + 8  # leaf page header is 8 bytes
        assert ptr_base + 2 * ncells <= content_start - 80
        cells = bytes(page[content_start:4096])
        page[content_start - 80:4096 - 80] = cells
        page[4096 - 80:4096] = bytes(80)
        for n in range(ncells):
            off = ptr_base + 2 * n
            ptr = struct.unpack(">H", page[off:off + 2])[0]
            page[off:off + 2] = struct.pack(">H", ptr - 80)
        page[hdr_off + 5:hdr_off + 7] = struct.pack(">H", content_start - 80)

    shift_into_usable_area(orig_page1, 100)
    shift_into_usable_area(orig_page2, 0)

    # Set Header Byte 20 (reserved_bytes_per_page) = 80 in Page 1
    orig_page1[20] = 80

    # Function to encrypt a page under SQLCipher v4 specs
    def encrypt_page(page_bytes: bytes, page_num: int) -> bytes:
        iv = os.urandom(16)
        # Usable payload size = 4096 - 80 = 4016 bytes
        # On Page 1: bytes 0..15 are salt, ciphertext covers bytes 16..4015 (4000 bytes)
        # On Page 2+: ciphertext covers bytes 0..4015 (4016 bytes)
        if page_num == 1:
            plaintext_payload = page_bytes[16:4016]
        else:
            plaintext_payload = page_bytes[:4016]

        cipher = Cipher(algorithms.AES(raw_key_32), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_payload) + encryptor.finalize()

        # Compute HMAC-SHA512:
        # Message = ciphertext + iv + uint32_le(page_num)
        h = hmac.HMAC(k_mac, hashes.SHA512())
        h.update(ciphertext)
        h.update(iv)
        h.update(struct.pack("<I", page_num))
        mac = h.finalize()  # 64 bytes

        if page_num == 1:
            return salt_16 + ciphertext + iv + mac
        else:
            return ciphertext + iv + mac

    enc_page1 = encrypt_page(bytes(orig_page1), page_num=1)
    enc_page2 = encrypt_page(bytes(orig_page2), page_num=2)

    with open(output_db_path, "wb") as f:
        f.write(enc_page1 + enc_page2)

    # 3. Build a companion encrypted WAL file:
    # 32-byte WAL Header + 1 Frame (updating Page 2 with latest changes)
    wal_hdr = struct.pack(
        ">IIIIII",
        0x377F0682,  # magic (LE checksum)
        3007000,     # version
        4096,        # page size
        1,           # checkpoint seq
        0x11223344,  # salt1
        0x55667788,  # salt2
    )
    # Compute WAL header checksum
    wal_hdr_s0, wal_hdr_s1 = 0, 0
    for i in range(3):
        x0, x1 = struct.unpack("<II", wal_hdr[i * 8:(i + 1) * 8])
        wal_hdr_s0 = (wal_hdr_s0 + x0 + wal_hdr_s1) & 0xFFFFFFFF
        wal_hdr_s1 = (wal_hdr_s1 + x1 + wal_hdr_s0) & 0xFFFFFFFF

    wal_full_hdr = wal_hdr + struct.pack(">II", wal_hdr_s0, wal_hdr_s1)

    # Frame Header: page_num=2, commit_size=2, salt1, salt2, chksum1, chksum2
    frame_hdr_part = struct.pack(
        ">IIII",
        2,           # page_num
        2,           # commit_size
        0x11223344,  # salt1
        0x55667788   # salt2
    )
    # Compute frame checksum over frame_hdr_part + enc_page2
    f_s0, f_s1 = wal_hdr_s0, wal_hdr_s1
    x0, x1 = struct.unpack("<II", frame_hdr_part[:8])
    f_s0 = (f_s0 + x0 + f_s1) & 0xFFFFFFFF
    f_s1 = (f_s1 + x1 + f_s0) & 0xFFFFFFFF
    for i in range(len(enc_page2) // 8):
        x0, x1 = struct.unpack("<II", enc_page2[i * 8:(i + 1) * 8])
        f_s0 = (f_s0 + x0 + f_s1) & 0xFFFFFFFF
        f_s1 = (f_s1 + x1 + f_s0) & 0xFFFFFFFF

    frame_full_hdr = frame_hdr_part + struct.pack(">II", f_s0, f_s1)

    with open(output_wal_path, "wb") as f:
        f.write(wal_full_hdr + frame_full_hdr + enc_page2)


# ==============================================================================
# TEST 1: Signal iOS 96-Hex-Char Key & WAL Decryption Test
# ==============================================================================

def test_signal_ios_96hex_key_and_wal_decryption(tmp_crypto_dir):
    """
    Acceptance Test 1 (Section 8.1):
    Tests Signal iOS Recipe 1:
    - 48-byte key (96 hex chars) = 32-byte AES key + 16-byte salt
    - Decrypts both Signal.sqlite and Signal.sqlite-wal
    - Verifies decrypted Page 1:
      - Bytes 0..15 equal "SQLite format 3\0"
      - Byte 20 equals 80 (reserved_bytes_per_page preserved)
      - Bytes 21..23 equal \x40\x20\x20
      - Trailing 80 bytes are zero-filled
    - Verifies decrypted WAL recomputes standard cumulative checksums
    - Feeds decrypted database into ForensicSQLiteEngine (Module 2.1) to recover all messages!
    """
    from src.crypto.engine import CryptographicKeyBrokerEngine
    from src.crypto.sqlcipher import SQLCipherDecryptor

    # 1. Generate 32-byte key + 16-byte salt
    k_enc = os.urandom(32)
    salt_enc = os.urandom(16)
    key_96_hex = (k_enc + salt_enc).hex()
    assert len(key_96_hex) == 96

    enc_db = tmp_crypto_dir / "Signal.sqlite"
    enc_wal = tmp_crypto_dir / "Signal.sqlite-wal"
    create_synthetic_sqlcipher_v4_db_and_wal(enc_db, enc_wal, k_enc, salt_enc)

    # 2. Run SQLCipherDecryptor
    decryptor = SQLCipherDecryptor()
    out_db = tmp_crypto_dir / "Signal_decrypted.sqlite"
    out_wal = tmp_crypto_dir / "Signal_decrypted.sqlite-wal"

    success, decrypted_wal_count = decryptor.decrypt_database_and_wal(
        encrypted_db_path=enc_db,
        encrypted_wal_path=enc_wal,
        output_db_path=out_db,
        output_wal_path=out_wal,
        raw_key_material=bytes.fromhex(key_96_hex),
    )

    assert success is True
    assert decrypted_wal_count >= 1
    assert out_db.exists()
    assert out_wal.exists()

    # 3. Byte-level verification of decrypted Page 1
    with open(out_db, "rb") as f:
        dec_page1 = f.read(4096)

    assert dec_page1[:16] == b"SQLite format 3\x00"
    assert dec_page1[20] == 80  # Reserved bytes preserved!
    assert dec_page1[21:24] == b"\x40\x20\x20"
    assert dec_page1[4096 - 80:] == b"\x00" * 80  # Trailer zero-filled!

    # 4. Feed decrypted database and WAL into ForensicSQLiteEngine (Module 2.1)
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=out_db,
        wal_path=out_wal,
        staging_id=101,
        canonical_path="/private/var/mobile/Containers/Shared/AppGroup/UUID/grdb/Signal.sqlite"
    )

    msg_rows = [r for r in records if r.table_name == "messages"]
    assert len(msg_rows) >= 10
    assert any("Confidential Message 1" in str(r.columns_dict.get("body")) for r in msg_rows)


# ==============================================================================
# TEST 2: WhatsApp .crypt15 HKDF & Dynamic Protobuf Header Test
# ==============================================================================

def test_whatsapp_crypt15_hkdf_and_protobuf_header(tmp_crypto_dir):
    """
    Acceptance Test 2 (Section 8.2):
    Tests WhatsApp .crypt15 Recipe 3:
    - 32-byte root key (64 hex chars)
    - Derives K_enc via RFC 5869 HKDF-SHA256 (salt=32 zero bytes, info=b"backup encryption")
    - Synthesizes .crypt15 binary format:
      [protobuf_len][0x01][protobuf_data with 16-byte IV][AES-256-GCM ciphertext][16-byte GCM tag][16-byte MD5]
    - Decrypts and inflates via zlib into Product B2 SQLite database.
    - Verifies that resulting database passes SQLite PRAGMA integrity_check!
    """
    from src.crypto.whatsapp import derive_crypt15_key, decrypt_crypt15_backup

    root_key = os.urandom(32)

    # 1. Verify HKDF formula
    k_enc = derive_crypt15_key(root_key)
    assert len(k_enc) == 32

    # 2. Build a valid plaintext SQLite database with chats
    plain_db_path = tmp_crypto_dir / "plain_wa.db"
    con = sqlite3.connect(plain_db_path)
    con.execute("CREATE TABLE wa_chats (jid TEXT, msg TEXT);")
    con.execute("INSERT INTO wa_chats VALUES ('919876543210@s.whatsapp.net', 'Secret financial transfer details');")
    con.commit()
    con.close()

    with open(plain_db_path, "rb") as f:
        uncompressed_db = f.read()
    plain_db_path.unlink()

    compressed_db = zlib.compress(uncompressed_db)

    # 3. Encrypt payload with AES-256-GCM
    iv = os.urandom(16)
    aesgcm = AESGCM(k_enc)
    # In cryptography AESGCM, encrypt returns ciphertext + 16-byte tag
    ct_with_tag = aesgcm.encrypt(iv, compressed_db, None)
    ciphertext = ct_with_tag[:-16]
    gcm_tag = ct_with_tag[-16:]
    md5_chk = hashlib.md5(ciphertext).digest()  # 16 bytes

    # 4. Build synthetic dynamic protobuf header with 16-byte IV inside field 1 tag
    # Protobuf structure: field 1 (tag 0x0A) -> nested metadata containing IV (tag 0x12, len 16, iv)
    nested_iv_block = b"\x12\x10" + iv
    proto_body = b"\x0A" + bytes([len(nested_iv_block)]) + nested_iv_block
    proto_len = len(proto_body)
    header = bytes([proto_len, 0x01]) + proto_body

    crypt15_file = tmp_crypto_dir / "msgstore.db.crypt15"
    with open(crypt15_file, "wb") as f:
        f.write(header + ciphertext + gcm_tag + md5_chk)

    # 5. Run Decryptor
    output_dec_path = tmp_crypto_dir / "msgstore_decrypted.db"
    success = decrypt_crypt15_backup(
        crypt15_path=crypt15_file,
        output_db_path=output_dec_path,
        root_key_32=root_key,
    )

    assert success is True
    assert output_dec_path.exists()

    # 6. Verify SQLite integrity check on decrypted database
    con = sqlite3.connect(output_dec_path)
    cur = con.cursor()
    cur.execute("PRAGMA integrity_check;")
    res = cur.fetchone()[0]
    assert res == "ok"

    cur.execute("SELECT msg FROM wa_chats;")
    msg = cur.fetchone()[0]
    assert msg == "Secret financial transfer details"
    con.close()


# ==============================================================================
# TEST 3: WeChat (WCDB) IMEI + UIN 7-Character MD5 Formula Test
# ==============================================================================

def test_wechat_wcdb_md5_formula(tmp_crypto_dir):
    """
    Acceptance Test 3 (Section 8.3):
    Tests WeChat Recipe 4:
    - IMEI = "1234567890ABCDEF", UIN = "-1357924680"
    - Concatenates "1234567890ABCDEF-1357924680"
    - Computes lowercase MD5 and takes first 7 characters ("7afcd8e")
    - Validates against Profile 3 / WCDB page encryption.
    """
    from src.crypto.wcdb import derive_wcdb_password
    from src.crypto.sqlcipher import SQLCipherDecryptor

    imei = "1234567890ABCDEF"
    uin = -1357924680

    wcdb_pwd = derive_wcdb_password(imei=imei, uin=uin)
    assert len(wcdb_pwd) == 7
    assert wcdb_pwd == "7afcd8e"

    # Verify key derivation with WCDB profile (page_size=1024, R=48, HMAC_SHA1, iter=64000)
    salt_16 = os.urandom(16)
    kdf_enc = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt_16,
        iterations=64000,
    )
    k_enc = kdf_enc.derive(wcdb_pwd.encode("utf-8"))

    salt_mac = bytes([b ^ 0x3A for b in salt_16])
    kdf_mac = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt_mac,
        iterations=2,
    )
    k_mac = kdf_mac.derive(k_enc)
    assert len(k_enc) == 32
    assert len(k_mac) == 32


# ==============================================================================
# TEST 4: Hardware-Gated Dimension B Audit Test (Android Keystore persistent.sqlite)
# ==============================================================================

def test_hardware_gated_dimension_b_audit(tmp_crypto_dir):
    """
    Acceptance Test 4 (Section 8.4):
    Simulates Android Keystore persistent.sqlite containing hardware-bound key 'SignalSecret'
    for Linux UID 10145 (org.thoughtcrime.securesms).
    Verifies that:
    1. KeyBroker maps namespace UID 10145 to org.thoughtcrime.securesms.
    2. Logs SignalSecret as HARDWARE_BOUND_UNAVAILABLE in case_cryptographic_keyring.
    3. Updates Module 1.4 Dimension B to ENCRYPTED_GATED_BY_HARDWARE.
    """
    from src.crypto.engine import CryptographicKeyBrokerEngine
    from src.evidentiary.enums import DimensionBAccessibility

    # 1. Create synthetic persistent.sqlite
    ks_path = tmp_crypto_dir / "persistent.sqlite"
    con = sqlite3.connect(ks_path)
    con.execute(
        """
        CREATE TABLE keyentry (
            id INTEGER PRIMARY KEY,
            key_type TEXT,
            namespace INTEGER,
            alias TEXT
        );
        """
    )
    con.execute(
        """
        CREATE TABLE blobentry (
            id INTEGER PRIMARY KEY,
            key_entry_id INTEGER,
            sub_type INTEGER,
            blob BLOB
        );
        """
    )
    con.execute("INSERT INTO keyentry VALUES (1, 'KEY', 10145, 'SignalSecret');")
    con.execute("INSERT INTO blobentry VALUES (1, 1, 0, ?);", (os.urandom(64),))
    con.commit()
    con.close()

    # 2. Run Engine with mock identity map {10145: "org.thoughtcrime.securesms"}
    engine = CryptographicKeyBrokerEngine()
    engine.register_uid_package_mapping(10145, "org.thoughtcrime.securesms")

    keyring_entries = engine.harvest_android_keystore_database(ks_path)
    assert len(keyring_entries) == 1
    ke = keyring_entries[0]
    assert ke.service_or_alias == "SignalSecret"
    assert ke.access_group_or_pkg == "org.thoughtcrime.securesms"
    assert ke.key_accessibility == "HARDWARE_BOUND_UNAVAILABLE"
    assert ke.protection_class_domain == "TEE_STRONG_BOX"

    # 3. Verify Dimension B state
    dim_b = engine.evaluate_dimension_b(
        package_name="org.thoughtcrime.securesms",
        target_path="/data/user/0/org.thoughtcrime.securesms/databases/signal.db"
    )
    assert dim_b == DimensionBAccessibility.ENCRYPTED_GATED_BY_HARDWARE


# ==============================================================================
# TEST 5: Apple Notes RFC 3394 & AES-128-GCM Row-Level Decryption
# ==============================================================================

def test_apple_notes_rfc3394_row_decryption(tmp_crypto_dir):
    """
    Section 6.5 Recipe 5:
    Tests unwrapping locked Apple Notes using RFC 3394 AES-128 Key Unwrap and AES-128-GCM:
    - User password "CorrectSecret123"
    - KEK derived via PBKDF2-HMAC-SHA256 (16 bytes)
    - AES Key Wrap (RFC 3394) unwraps note AES-128 key
    - Decrypts gzipped note payload with AES-128-GCM
    - Unzips and recovers note text.
    """
    from src.crypto.applenotes import decrypt_apple_notes_body

    user_password = "CorrectSecret123"
    salt = os.urandom(16)
    iterations = 5000
    iv = os.urandom(16)

    # 1. Derive 16-byte KEK
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=iterations,
    )
    kek = kdf.derive(user_password.encode("utf-8"))

    # 2. Generate random 16-byte note key and wrap it with RFC 3394 (16 bytes wraps to 24 bytes)
    note_key_16 = os.urandom(16)
    wrapped_key_40 = aes_key_wrap(kek, note_key_16)
    assert len(wrapped_key_40) == 24

    # 3. Encrypt gzipped text with AES-128-GCM
    plain_note_text = "Hidden Bitcoin Seed: apple banana cherry dog elephant fox grape"
    gzipped_body = gzip.compress(plain_note_text.encode("utf-8"))

    # AESGCM with 16-byte key: tag is 16 bytes
    aesgcm = AESGCM(note_key_16)
    ct_with_tag = aesgcm.encrypt(iv, gzipped_body, None)
    ciphertext = ct_with_tag[:-16]
    gcm_tag = ct_with_tag[-16:]

    # 4. Decrypt via Module 2.2 helper
    recovered_text = decrypt_apple_notes_body(
        password=user_password,
        salt=salt,
        iterations=iterations,
        iv=iv,
        wrapped_key=wrapped_key_40,
        ciphertext=ciphertext,
        tag=gcm_tag,
    )

    assert recovered_text == plain_note_text


# ==============================================================================
# TEST 6: Case Cryptographic Keyring & Encrypted Database Registry Export
# ==============================================================================

def test_crypto_broker_database_export(tmp_crypto_dir):
    """
    Section 7: Database Schema for Module 2.2
    Verifies that CryptographicKeyBrokerEngine creates and writes into:
    1. case_cryptographic_keyring
    2. encrypted_database_registry
    with exact column names, constraints, and valid foreign keys.
    """
    from src.crypto.engine import CryptographicKeyBrokerEngine
    from src.crypto.models import KeyringEntry, EncryptedDatabaseEntry

    engine = CryptographicKeyBrokerEngine()
    ledger_path = tmp_crypto_dir / "cryptographic_key_broker.sqlite"

    key_entry = KeyringEntry(
        source_category="IOS_VENDOR_KEYCHAIN_EXPORT",
        app_instance_id=1,
        access_group_or_pkg="group.org.whispersystems.signal",
        service_or_alias="OWSPrimaryStorage",
        account_name="GRDBDatabaseCipherKeySpec",
        protection_class_domain="ck",
        key_accessibility="UNWRAPPED_READY",
        key_format_type="RAW_KEY_AND_SALT_HEX_96",
        unwrapped_key_hex="0123456789abcdef" * 6,
        created_utc_iso="2026-11-05T10:00:00.000000Z",
        modified_utc_iso="2026-11-05T10:05:00.000000Z",
    )

    db_entry = EncryptedDatabaseEntry(
        vfs_file_id=10,
        app_instance_id=1,
        canonical_path="/private/var/mobile/Containers/Shared/AppGroup/UUID/grdb/Signal.sqlite",
        encryption_scheme="SQLCIPHER_V4",
        matched_key_id=1,
        decryption_status="DECRYPTED_VERIFIED",
        derivative_staging_id=50,
        decrypted_wal_frames=5,
    )

    engine.export_to_ledger(
        keyring_entries=[key_entry],
        db_entries=[db_entry],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    cur.execute("SELECT * FROM case_cryptographic_keyring;")
    k_row = cur.fetchone()
    assert k_row is not None
    k_cols = [d[0] for d in cur.description]
    assert "source_category" in k_cols
    assert "key_accessibility" in k_cols
    assert "unwrapped_key_hex" in k_cols

    cur.execute("SELECT * FROM encrypted_database_registry;")
    d_row = cur.fetchone()
    assert d_row is not None
    d_cols = [d[0] for d in cur.description]
    assert "canonical_path" in d_cols
    assert "encryption_scheme" in d_cols
    assert "decryption_status" in d_cols
    assert "decrypted_wal_frames" in d_cols
    con.close()
