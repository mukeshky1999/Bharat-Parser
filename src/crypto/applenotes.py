"""
Apple Notes Row-Level RFC 3394 & AES-128-GCM Decryptor.
Adheres strictly to Specification Section 6.5 (Recipe 5).
"""

import gzip
import logging
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

logger = logging.getLogger(__name__)


def decrypt_apple_notes_body(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int,
    iv: bytes,
    wrapped_key: bytes,
    ciphertext: bytes,
    tag: bytes
) -> str:
    """
    Unwraps and decrypts an encrypted Apple Notes body (ZDATA in NoteStore.sqlite):
    1. Derives 16-byte KEK via PBKDF2-HMAC-SHA256.
    2. Unwraps 16-byte note key from wrapped_key (40 bytes) via RFC 3394 Key Unwrap.
    3. Decrypts ciphertext using AES-128-GCM.
    4. Decompresses gzipped payload into UTF-8 note text.
    """
    pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password

    # 1. Derive KEK (16 bytes)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=iterations,
    )
    kek = kdf.derive(pwd_bytes)

    # 2. Unwrap 16-byte note key (from 40-byte wrapped blob)
    unwrapped = aes_key_unwrap(kek, wrapped_key)
    note_key = unwrapped[:16]

    # 3. Decrypt with AES-128-GCM
    aesgcm = AESGCM(note_key)
    gzipped_payload = aesgcm.decrypt(iv, ciphertext + tag, None)

    # 4. Gunzip
    try:
        decompressed = gzip.decompress(gzipped_payload)
        return decompressed.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("Failed gzip decompression of decrypted note payload: %s", exc)
        return gzipped_payload.decode("utf-8", errors="replace")
