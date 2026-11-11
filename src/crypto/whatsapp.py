"""
WhatsApp Local Backup Decryptor (.crypt12, .crypt14, .crypt15).
Adheres strictly to Specification Section 6.3 (Recipe 3).
"""

import hashlib
import hmac as py_hmac
import logging
from pathlib import Path
from typing import Optional, Union
import zlib

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def derive_crypt15_key(root_key_32: bytes) -> bytes:
    """
    Derives the 32-byte AES-GCM encryption key from the WhatsApp .crypt15 root key
    using RFC 5869 HKDF-SHA256 with salt = 0x00 * 32 and info = "backup encryption".
    """
    if len(root_key_32) != 32:
        raise ValueError(f"WhatsApp root key must be 32 bytes, got {len(root_key_32)}")

    salt = b"\x00" * 32
    info = b"backup encryption"

    # HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    h_extract = hmac.HMAC(salt, hashes.SHA256())
    h_extract.update(root_key_32)
    prk = h_extract.finalize()

    # HKDF-Expand: OKM = HMAC-Hash(PRK, info || 0x01)
    h_expand = hmac.HMAC(prk, hashes.SHA256())
    h_expand.update(info + b"\x01")
    k_enc = h_expand.finalize()

    return k_enc[:32]


def extract_crypt15_iv_and_offset(header_bytes: bytes) -> tuple[bytes, int]:
    """
    Extracts the 16-byte IV and ciphertext start offset from the dynamic Protobuf header.
    """
    proto_len = header_bytes[0]
    cursor = 1

    # Check for feature flag byte 0x01
    if len(header_bytes) > 2 and header_bytes[1] == 0x01:
        cursor = 2

    header_end = cursor + proto_len
    proto_body = header_bytes[cursor:header_end]

    # Search for nested IV: tag 0x12 followed by length 0x10 (16 bytes)
    iv = None
    pos = 0
    while pos < len(proto_body) - 17:
        if proto_body[pos] == 0x12 and proto_body[pos + 1] == 0x10:
            iv = proto_body[pos + 2:pos + 18]
            break
        pos += 1

    if not iv:
        # Fallback: scan any 16-byte candidate in header
        if len(proto_body) >= 16:
            iv = proto_body[-16:]
        else:
            raise ValueError("Failed to locate 16-byte IV in .crypt15 protobuf header")

    return iv, header_end


def decrypt_crypt15_backup(
    crypt15_path: Union[str, Path],
    output_db_path: Union[str, Path],
    root_key_32: bytes
) -> bool:
    """
    Decrypts a WhatsApp .crypt15 backup file into a plaintext SQLite database.
    """
    in_path = Path(crypt15_path)
    out_path = Path(output_db_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        return False

    with open(in_path, "rb") as f:
        data = f.read()

    if len(data) < 64:
        return False

    k_enc = derive_crypt15_key(root_key_32)
    iv, ct_start = extract_crypt15_iv_and_offset(data[:512])

    # Ciphertext runs until len(data) - 32
    # The last 32 bytes consist of: 16-byte GCM tag + 16-byte MD5 checksum
    if len(data) < ct_start + 32:
        return False

    ciphertext = data[ct_start:-32]
    gcm_tag = data[-32:-16]

    try:
        aesgcm = AESGCM(k_enc)
        # AESGCM.decrypt expects ciphertext + 16-byte tag
        compressed_payload = aesgcm.decrypt(iv, ciphertext + gcm_tag, None)
        plaintext_db = zlib.decompress(compressed_payload)

        with open(out_path, "wb") as f_out:
            f_out.write(plaintext_db)
        return True
    except Exception as exc:
        logger.debug("Failed .crypt15 decryption or decompression: %s", exc)
        return False


def decrypt_crypt12_or_crypt14_backup(
    crypt_path: Union[str, Path],
    output_db_path: Union[str, Path],
    key_bytes_158: bytes,
    is_crypt14: bool = False
) -> bool:
    """
    Decrypts a WhatsApp .crypt12 or .crypt14 backup using the 158-byte /files/key file.
    The 32-byte AES key sits at bytes 126..157.
    """
    in_path = Path(crypt_path)
    out_path = Path(output_db_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if len(key_bytes_158) < 158:
        return False

    k_aes = key_bytes_158[126:158]

    with open(in_path, "rb") as f:
        data = f.read()

    if not is_crypt14:
        # .crypt12: IV at bytes 51..66, ciphertext from 67 to EOF - 20
        iv = data[51:67]
        ciphertext = data[67:-20]
        tag = data[-20:-4]
    else:
        # .crypt14: dynamic header
        iv, ct_start = extract_crypt15_iv_and_offset(data[:512])
        ciphertext = data[ct_start:-32]
        tag = data[-32:-16]

    try:
        aesgcm = AESGCM(k_aes)
        compressed = aesgcm.decrypt(iv, ciphertext + tag, None)
        plaintext_db = zlib.decompress(compressed)

        with open(out_path, "wb") as f_out:
            f_out.write(plaintext_db)
        return True
    except Exception as exc:
        logger.debug("Failed .crypt12/.crypt14 decryption: %s", exc)
        return False
