"""
Phase 1 & 2: In-Memory Keystore/Keychain Staging & SQLCipher Decryption Pipeline.
Carves symmetric keys, passphrases, and Android/iOS keysets from iOS keychain-2.db,
Android shared_prefs XMLs, and raw binary files to attempt in-memory decryption
of SQLCipher-protected databases before parsing.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional


class CaseKeyring:
    """Per-case keyring for externally supplied SQLCipher/keystore hints."""

    def __init__(self, case_id: str = "UNSPECIFIED"):
        self.case_id = case_id
        self._keys: Dict[str, bytes] = {}

    def register(self, name: str, raw: str) -> None:
        """
        raw may be hex, base64, or a plaintext passphrase. We store the bytes as-is;
        downstream decryption attempts treat each as a candidate key.
        """
        if not name or raw is None:
            return
        self._keys[str(name)] = str(raw).encode("utf-8", errors="replace")

    def candidates(self) -> Dict[str, bytes]:
        return dict(self._keys)

    def clear(self) -> None:
        self._keys.clear()

    def __len__(self) -> int:
        return len(self._keys)


def attempt_sqlcipher_open(db_path: str, keyring: Optional[CaseKeyring] = None) -> Optional[sqlite3.Connection]:
    """Attempt opening an encrypted database with keys in the keyring in read-only mode."""
    if not os.path.exists(db_path):
        return None
    candidates = keyring.candidates() if keyring else {}
    for name, key_bytes in candidates.items():
        try:
            conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
            conn.execute(f"PRAGMA key = \"x'{key_bytes.hex()}'\";")
            conn.execute("SELECT count(*) FROM sqlite_master;").fetchone()
            return conn
        except sqlite3.DatabaseError:
            continue
    return None


def extract_app_keys_and_decrypt(target_dir: str, bundle_id: str) -> Dict[str, Any]:
    """
    Scans extraction workspaces for iOS keychain-2.db, Android MasterKeys,
    and app-specific SQLCipher passphrases stored in shared_prefs XMLs.
    """
    keys_found: Dict[str, Any] = {}

    for root, _, files in os.walk(target_dir):
        for f in files:
            full_path = os.path.join(root, f)
            f_low = f.lower()

            # 1. Inspect iOS Keychain Database
            if f_low in ('keychain-2.db', 'keychain.db'):
                conn = None
                try:
                    conn = sqlite3.connect(f'file:{os.path.abspath(full_path)}?mode=ro', uri=True)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT agrp, svce, v_Data FROM genp WHERE agrp LIKE ? OR svce LIKE ?",
                        (f'%{bundle_id}%', f'%{bundle_id}%'),
                    )
                    for r in cursor.fetchall():
                        service = str(r[1] or 'iOS_Keychain_Key')
                        raw_blob = r[2]
                        if isinstance(raw_blob, (bytes, bytearray)):
                            keys_found[service] = bytes(raw_blob[:32])
                        elif raw_blob:
                            keys_found[service] = str(raw_blob)
                except Exception:
                    pass
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass

            # 2. Inspect Android SharedPreferences XMLs for SQLCipher keys / seeds
            elif f_low.endswith('.xml'):
                try:
                    with open(full_path, 'rb') as xf:
                        content = xf.read().decode('utf-8', errors='ignore')
                    if '__androidx_security_crypto_encrypted_prefs_key_keyset__' in content:
                        keys_found['Android_EncryptedPrefs_Keyset'] = 'Present'

                    # Extract candidate encryption keys, passphrases, or device seeds
                    for m in re.finditer(
                        r'name="([^"]*(?:key|cipher|secret|pass|seed|token|salt|android_id|uuid)[^"]*)"[^>]*>([^<]{6,256})<',
                        content,
                        re.IGNORECASE,
                    ):
                        k_name, k_val = m.group(1).strip(), m.group(2).strip()
                        keys_found[k_name] = k_val
                        # If Base64 encoded 32-byte key
                        try:
                            dec = base64.b64decode(k_val)
                            if len(dec) in (16, 24, 32):
                                keys_found[f"{k_name}_b64_raw"] = dec
                        except Exception:
                            pass
                except Exception:
                    pass

    return keys_found


def attempt_sqlcipher_decryption(
    encrypted_db_path: str,
    key_candidates: Dict[str, Any] | bytes | str | None = None,
    output_scratch_dir: str = "",
    keyring: Optional[CaseKeyring] = None,
) -> Optional[str]:
    """
    Attempts to decrypt an SQLCipher-protected database in volatile scratchpad memory
    using all discovered candidate keys and SQLCipher v3/v4 parameter profiles.
    If the database is already plaintext SQLite, returns the path directly.
    """
    if not os.path.exists(encrypted_db_path):
        return None

    try:
        with open(encrypted_db_path, 'rb') as f:
            header = f.read(16)
        if header == b'SQLite format 3\x00':
            return encrypted_db_path
    except Exception:
        return None

    candidates: List[bytes | str] = []
    if isinstance(key_candidates, dict):
        for v in key_candidates.values():
            if isinstance(v, (bytes, str)) and v not in ('Present', ''):
                candidates.append(v)
                if isinstance(v, str):
                    candidates.append(hashlib.sha256(v.encode('utf-8')).hexdigest()[:32])
                    candidates.append(hashlib.sha256(v.encode('utf-8')).digest())
    elif isinstance(key_candidates, (bytes, str)):
        candidates.append(key_candidates)

    if keyring:
        for k_bytes in keyring.candidates().values():
            if k_bytes not in candidates:
                candidates.append(k_bytes)

    if not candidates:
        return None

    decrypted_dest = os.path.join(
        output_scratch_dir, f"decrypted_{os.path.basename(encrypted_db_path)}"
    )

    for cand in candidates:
        for cipher_compat in (4, 3):
            conn = None
            try:
                if os.path.exists(decrypted_dest):
                    os.remove(decrypted_dest)
                conn = sqlite3.connect(encrypted_db_path)
                cur = conn.cursor()
                if isinstance(cand, bytes):
                    key_hex = cand.hex()
                    cur.execute(f"PRAGMA key = \"x'{key_hex}'\";")
                else:
                    safe_k = str(cand).replace("'", "''")
                    cur.execute(f"PRAGMA key = '{safe_k}';")

                cur.execute(f"PRAGMA cipher_compatibility = {cipher_compat};")
                cur.execute("SELECT count(*) FROM sqlite_master;")
                safe_dest = decrypted_dest.replace("'", "''")
                cur.execute(f"ATTACH DATABASE '{safe_dest}' AS plaintext KEY '';")
                cur.execute("SELECT sqlcipher_export('plaintext');")
                cur.execute("DETACH DATABASE plaintext;")
                conn.close()
                conn = None

                if os.path.exists(decrypted_dest) and os.path.getsize(decrypted_dest) > 100:
                    with open(decrypted_dest, 'rb') as df:
                        if df.read(16) == b'SQLite format 3\x00':
                            return decrypted_dest
            except Exception:
                continue
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

    return None