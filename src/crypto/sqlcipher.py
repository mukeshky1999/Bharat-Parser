"""
Universal Page-Level SQLCipher (v1-v4) & WCDB Decryption Engine.
Adheres strictly to Specification Section 5.
"""

import hmac as py_hmac
import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.sqlite.wal import compute_wal_checksum

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SQLCipherProfile:
    """Cryptographic configuration profile for SQLCipher / WCDB databases."""
    name: str
    page_size: int
    reserve_size: int
    hmac_algorithm: str  # "SHA512", "SHA1", "NONE"
    kdf_algorithm: str   # "SHA512", "SHA1"
    kdf_iterations: int


@dataclass
class DecryptionReport:
    """What was checked while decrypting, so the caller can state it. Nothing here is inferred."""
    profile: str = ""
    # True when the profile has a per-page HMAC and every page was checked against it.
    mac_checked: bool = False
    db_pages: int = 0
    # Database pages whose HMAC did not match. They are written as decrypted but are NOT authenticated.
    db_pages_failed_mac: List[int] = field(default_factory=list)
    wal_frames_total: int = 0
    wal_frames_written: int = 0
    # Frames after the first bad one are not written: SQLite itself stops reading a WAL there.
    wal_frames_rejected: int = 0
    wal_stop_reason: str = ""
    failure: str = ""


def _page_mac_ok(page: bytes, page_no: int, prof: "SQLCipherProfile", k_mac: bytes) -> Optional[bool]:
    """True/False for the page's HMAC; None when the profile has no HMAC."""
    if prof.hmac_algorithm == "NONE":
        return None
    R = prof.reserve_size
    mac_len = 64 if prof.hmac_algorithm == "SHA512" else 32
    start = 16 if page_no == 1 else 0
    ciphertext = page[start:prof.page_size - R]
    iv = page[prof.page_size - R:prof.page_size - R + 16]
    expected = page[prof.page_size - R + 16:prof.page_size - R + 16 + mac_len]
    h = hmac.HMAC(k_mac, hashes.SHA512() if prof.hmac_algorithm == "SHA512" else hashes.SHA1())
    h.update(ciphertext)
    h.update(iv)
    h.update(struct.pack("<I", page_no))
    return py_hmac.compare_digest(h.finalize()[:mac_len], expected)


STANDARD_PROFILES: List[SQLCipherProfile] = [
    # Profile 1: SQLCipher v4 Default
    SQLCipherProfile(
        name="SQLCipher v4 (4096 / SHA512)",
        page_size=4096,
        reserve_size=80,
        hmac_algorithm="SHA512",
        kdf_algorithm="SHA512",
        kdf_iterations=256000,
    ),
    # Profile 2: SQLCipher v3 / WCDB Default
    SQLCipherProfile(
        name="SQLCipher v3 / WCDB (1024 / SHA1)",
        page_size=1024,
        reserve_size=48,
        hmac_algorithm="SHA1",
        kdf_algorithm="SHA1",
        kdf_iterations=64000,
    ),
    # Profile 3: SQLCipher v4 Alternative (1024 page size)
    SQLCipherProfile(
        name="SQLCipher v4 (1024 / SHA512)",
        page_size=1024,
        reserve_size=80,
        hmac_algorithm="SHA512",
        kdf_algorithm="SHA512",
        kdf_iterations=256000,
    ),
    # Profile 4: SQLCipher v3 Alternative (4096 page size)
    SQLCipherProfile(
        name="SQLCipher v3 (4096 / SHA1)",
        page_size=4096,
        reserve_size=48,
        hmac_algorithm="SHA1",
        kdf_algorithm="SHA1",
        kdf_iterations=64000,
    ),
    # Profile 5: Fast WCDB / SQLCipher v2
    SQLCipherProfile(
        name="SQLCipher v2 / Fast WCDB (1024 / SHA1 / 4000)",
        page_size=1024,
        reserve_size=48,
        hmac_algorithm="SHA1",
        kdf_algorithm="SHA1",
        kdf_iterations=4000,
    ),
    # Profile 6: SQLCipher v1 / Legacy No-HMAC
    SQLCipherProfile(
        name="SQLCipher v1 (1024 / No-HMAC)",
        page_size=1024,
        reserve_size=16,
        hmac_algorithm="NONE",
        kdf_algorithm="SHA1",
        kdf_iterations=4000,
    ),
]


class SQLCipherDecryptor:
    """Decrypts SQLCipher databases and companion WAL files at the raw page level."""

    def __init__(self):
        self.active_profile: Optional[SQLCipherProfile] = None
        self.last_report: DecryptionReport = DecryptionReport()

    def derive_keys(
        self,
        raw_key_material: Union[bytes, str],
        salt_enc: bytes,
        profile: SQLCipherProfile
    ) -> Tuple[bytes, bytes]:
        """
        Derives the 32-byte encryption key (K_enc) and 32-byte HMAC key (K_mac).
        Handles:
        - 48-byte raw key (32 bytes K_enc + 16 bytes salt)
        - 32-byte raw AES key
        - UTF-8 Passphrase
        """
        if isinstance(raw_key_material, str):
            key_bytes = raw_key_material.encode("utf-8")
        else:
            key_bytes = raw_key_material

        # Case 1: 48-byte raw key + salt blob (e.g. Signal iOS 96 hex chars)
        if len(key_bytes) == 48:
            k_enc = key_bytes[:32]
            actual_salt = key_bytes[32:48]
        # Case 2: 32-byte direct AES key
        elif len(key_bytes) == 32 and not isinstance(raw_key_material, str):
            k_enc = key_bytes
            actual_salt = salt_enc
        # Case 3: Passphrase (requires PBKDF2)
        else:
            actual_salt = salt_enc
            hash_algo = hashes.SHA512() if profile.kdf_algorithm == "SHA512" else hashes.SHA1()
            kdf_enc = PBKDF2HMAC(
                algorithm=hash_algo,
                length=32,
                salt=actual_salt,
                iterations=profile.kdf_iterations,
            )
            k_enc = kdf_enc.derive(key_bytes)

        # Derive HMAC Key (K_mac) if HMAC is enabled
        if profile.hmac_algorithm == "NONE":
            k_mac = b""
        else:
            salt_mac = bytes([b ^ 0x3A for b in actual_salt])
            mac_hash = hashes.SHA512() if profile.hmac_algorithm == "SHA512" else hashes.SHA1()
            kdf_mac = PBKDF2HMAC(
                algorithm=mac_hash,
                length=32,
                salt=salt_mac,
                iterations=2,
            )
            k_mac = kdf_mac.derive(k_enc)

        return k_enc, k_mac

    def probe_page1_profile(
        self,
        page1_bytes: bytes,
        raw_key_material: Union[bytes, str]
    ) -> Optional[Tuple[SQLCipherProfile, bytes, bytes]]:
        """
        Tests Page 1 against candidate profiles.
        Returns (matched_profile, k_enc, k_mac) upon successful HMAC and payload fraction verification.
        """
        if len(page1_bytes) < 1024:
            return None

        salt_enc = page1_bytes[:16]

        for prof in STANDARD_PROFILES:
            if len(page1_bytes) < prof.page_size:
                continue

            try:
                k_enc, k_mac = self.derive_keys(raw_key_material, salt_enc, prof)
                page_slice = page1_bytes[:prof.page_size]
                R = prof.reserve_size

                # If HMAC enabled, verify Page 1 HMAC
                if prof.hmac_algorithm != "NONE":
                    mac_len = 64 if prof.hmac_algorithm == "SHA512" else 32
                    page_iv = page_slice[prof.page_size - R:prof.page_size - R + 16]
                    expected_mac = page_slice[prof.page_size - R + 16:prof.page_size - R + 16 + mac_len]

                    # HMAC message: ciphertext (bytes 16..prof.page_size - R) + IV + uint32_le(1)
                    ciphertext = page_slice[16:prof.page_size - R]
                    h = hmac.HMAC(
                        k_mac,
                        hashes.SHA512() if prof.hmac_algorithm == "SHA512" else hashes.SHA1(),
                    )
                    h.update(ciphertext)
                    h.update(page_iv)
                    h.update(struct.pack("<I", 1))
                    calc_mac = h.finalize()

                    # Compare truncated or padded MAC
                    if not py_hmac.compare_digest(calc_mac[:mac_len], expected_mac[:mac_len]):
                        continue
                else:
                    page_iv = page_slice[prof.page_size - R:prof.page_size - R + 16]
                    ciphertext = page_slice[16:prof.page_size - R]

                # Decrypt ciphertext
                cipher = Cipher(algorithms.AES(k_enc), modes.CBC(page_iv))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()

                # Decrypted bytes 16..18 in standard SQLite correspond to bytes 0..2 of decrypted slice
                # Check byte 20 of Page 1 (offset 4 of decrypted slice) and bytes 21..23 (offset 5..7)
                # In Page 1: bytes 0..15 are magic, bytes 16..17 page_size, byte 18 write_version,
                # byte 19 read_version, byte 20 reserved_bytes, bytes 21..23 payload fractions (\x40\x20\x20)
                if len(decrypted) >= 8:
                    payload_fractions = decrypted[5:8]
                    if payload_fractions == b"\x40\x20\x20":
                        self.active_profile = prof
                        return prof, k_enc, k_mac
            except Exception as exc:
                logger.debug("Profile %s probe failed: %s", prof.name, exc)

        return None

    def decrypt_database_and_wal(
        self,
        encrypted_db_path: Union[str, Path],
        encrypted_wal_path: Optional[Union[str, Path]],
        output_db_path: Union[str, Path],
        output_wal_path: Optional[Union[str, Path]],
        raw_key_material: Union[bytes, str],
        forced_profile: Optional[SQLCipherProfile] = None
    ) -> Tuple[bool, int]:
        """
        Decrypts SQLCipher database and companion WAL file into verified plaintext SQLite files.
        Returns (success, decrypted_wal_frames_count).
        """
        enc_db = Path(encrypted_db_path)
        out_db = Path(output_db_path)
        out_db.parent.mkdir(parents=True, exist_ok=True)
        report = self.last_report = DecryptionReport()

        if not enc_db.exists():
            report.failure = "encrypted file not found"
            return False, 0

        with open(enc_db, "rb") as f_in:
            first_chunk = f_in.read(16384)

        probe_result = None
        if forced_profile:
            # A forced profile skips the search over profiles, not the checks: page 1 must still authenticate
            # (or, for a profile without HMAC, decrypt to a plausible SQLite header). A wrong key or profile
            # used to produce a garbage file reported as success.
            salt_enc = first_chunk[:16]
            k_enc, k_mac = self.derive_keys(raw_key_material, salt_enc, forced_profile)
            ok = False
            if len(first_chunk) >= forced_profile.page_size:
                p1 = first_chunk[:forced_profile.page_size]
                mac = _page_mac_ok(p1, 1, forced_profile, k_mac)
                if mac is not False:
                    R1 = forced_profile.reserve_size
                    dec = Cipher(algorithms.AES(k_enc), modes.CBC(p1[forced_profile.page_size - R1:forced_profile.page_size - R1 + 16])).decryptor()
                    plain = dec.update(p1[16:forced_profile.page_size - R1]) + dec.finalize()
                    ok = plain[5:8] == b"\x40\x20\x20"
            if ok:
                probe_result = (forced_profile, k_enc, k_mac)
                self.active_profile = forced_profile
        else:
            probe_result = self.probe_page1_profile(first_chunk, raw_key_material)

        if not probe_result:
            report.failure = "key or profile did not authenticate page 1"
            return False, 0

        profile, k_enc, k_mac = probe_result
        page_size = profile.page_size
        R = profile.reserve_size
        report.profile = profile.name
        report.mac_checked = profile.hmac_algorithm != "NONE"

        # Decrypt Database Page-by-Page
        total_size = enc_db.stat().st_size
        page_count = total_size // page_size

        with open(enc_db, "rb") as f_in, open(out_db, "wb") as f_out:
            for page_num in range(1, page_count + 1):
                f_in.seek((page_num - 1) * page_size)
                p_bytes = f_in.read(page_size)
                if len(p_bytes) < page_size:
                    break

                report.db_pages += 1
                # Pass through all-zero pages
                if all(b == 0 for b in p_bytes):
                    f_out.write(b"\x00" * page_size)
                    continue

                if _page_mac_ok(p_bytes, page_num, profile, k_mac) is False:
                    report.db_pages_failed_mac.append(page_num)

                page_iv = p_bytes[page_size - R:page_size - R + 16]
                cipher = Cipher(algorithms.AES(k_enc), modes.CBC(page_iv))
                decryptor = cipher.decryptor()

                if page_num == 1:
                    ciphertext = p_bytes[16:page_size - R]
                    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()

                    # Assemble Page 1:
                    # Bytes 0..15: "SQLite format 3\0"
                    # Bytes 16..page_size - R: decrypted payload
                    # Byte 20: preserve R
                    # Bytes page_size - R..page_size: zero fill
                    assembled_page = bytearray(b"SQLite format 3\x00" + decrypted_payload + (b"\x00" * R))
                    assembled_page[20] = R
                    f_out.write(bytes(assembled_page))
                else:
                    ciphertext = p_bytes[:page_size - R]
                    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()
                    assembled_page = decrypted_payload + (b"\x00" * R)
                    f_out.write(assembled_page)

        # Decrypt Companion WAL if present
        decrypted_wal_frames = 0
        if encrypted_wal_path and output_wal_path:
            enc_wal = Path(encrypted_wal_path)
            out_wal = Path(output_wal_path)

            if enc_wal.exists() and enc_wal.stat().st_size >= 32:
                decrypted_wal_frames = self._decrypt_wal_frames(
                    enc_wal=enc_wal,
                    out_wal=out_wal,
                    k_enc=k_enc,
                    page_size=page_size,
                    reserve_size=R,
                    profile=profile,
                    k_mac=k_mac,
                )

        return True, decrypted_wal_frames

    def _decrypt_wal_frames(
        self,
        enc_wal: Path,
        out_wal: Path,
        k_enc: bytes,
        page_size: int,
        reserve_size: int,
        profile: Optional[SQLCipherProfile] = None,
        k_mac: bytes = b"",
    ) -> int:
        """Decrypts the WAL frame by frame.

        A frame is accepted only if its salts equal the WAL header's and, where the profile has an HMAC, its HMAC
        verifies. At the first frame that fails, writing stops (SQLite also stops reading there) and the rest are
        counted as rejected in ``last_report``. The cumulative checksums in the output file are NEW values computed
        over the decrypted pages; the original checksum chain is not reproduced and was not verified here.
        """
        report = self.last_report
        wal_size = enc_wal.stat().st_size
        frame_size = 24 + page_size
        total_frames = (wal_size - 32) // frame_size
        report.wal_frames_total = max(total_frames, 0)
        if total_frames <= 0:
            return 0

        with open(enc_wal, "rb") as f_in, open(out_wal, "wb") as f_out:
            # 1. 32-byte WAL Header is unencrypted
            wal_hdr = f_in.read(32)
            f_out.write(wal_hdr)
            wal_salts = wal_hdr[16:24]

            # Extract initial cumulative checksum seed and endianness
            magic = struct.unpack(">I", wal_hdr[:4])[0]
            is_be = (magic == 0x377F0683)
            # In SQLite WAL on disk, header checksum is stored as Big-Endian uint32_be
            s0, s1 = struct.unpack(">II", wal_hdr[24:32])

            decrypted_count = 0

            for i in range(1, total_frames + 1):
                f_hdr = f_in.read(24)
                if len(f_hdr) < 24:
                    break

                page_num = struct.unpack(">I", f_hdr[:4])[0]
                frame_payload = f_in.read(page_size)
                if len(frame_payload) < page_size:
                    break

                if f_hdr[8:16] != wal_salts:
                    report.wal_stop_reason = f"frame {i}: salts differ from the WAL header (stale frame from an earlier WAL generation)"
                    break
                if profile is not None and _page_mac_ok(frame_payload, page_num, profile, k_mac) is False:
                    report.wal_stop_reason = f"frame {i}: HMAC does not verify (torn, altered or wrong key)"
                    break

                # Decrypt frame payload
                page_iv = frame_payload[page_size - reserve_size:page_size - reserve_size + 16]
                cipher = Cipher(algorithms.AES(k_enc), modes.CBC(page_iv))
                decryptor = cipher.decryptor()

                if page_num == 1:
                    ciphertext = frame_payload[16:page_size - reserve_size]
                    dec = decryptor.update(ciphertext) + decryptor.finalize()
                    dec_payload = bytearray(b"SQLite format 3\x00" + dec + (b"\x00" * reserve_size))
                    dec_payload[20] = reserve_size
                    decrypted_page = bytes(dec_payload)
                else:
                    ciphertext = frame_payload[:page_size - reserve_size]
                    dec = decryptor.update(ciphertext) + decryptor.finalize()
                    decrypted_page = dec + (b"\x00" * reserve_size)

                # Recompute SQLite WAL cumulative checksum over bytes 0..7 of header + decrypted page
                next_s0, next_s1 = compute_wal_checksum(f_hdr[:8], is_be, s0, s1)
                next_s0, next_s1 = compute_wal_checksum(decrypted_page, is_be, next_s0, next_s1)

                # Update frame header with new cumulative checksum
                updated_hdr = f_hdr[:16] + struct.pack(">II", next_s0, next_s1)
                s0, s1 = next_s0, next_s1

                f_out.write(updated_hdr + decrypted_page)
                decrypted_count += 1

            report.wal_frames_written = decrypted_count
            report.wal_frames_rejected = total_frames - decrypted_count
            return decrypted_count
