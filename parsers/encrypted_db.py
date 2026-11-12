"""Encrypted (SQLCipher) databases in the ingest pipeline (X-10).

What this does and does not do:
- A file with a database extension that has no SQLite header and looks like random data is reported as encrypted.
- It is decrypted only with keys that the examiner supplied or that were found in the evidence itself (key stores and
  preference files). Nothing is guessed: no wordlists, no brute force.
- The decryption runs on the working copy and writes a separate decrypted file. The evidence is not touched.
- Every page and WAL frame is checked against its HMAC (src/crypto/sqlcipher.py). The outcome says how many failed.
- Key material is never logged or stored. A key is identified by its name and the first 8 hex digits of its SHA-256.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import pathlib
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

SQLITE_MAGIC = b"SQLite format 3\x00"
DB_EXTENSIONS = (".db", ".sqlite", ".sqlite3", ".db3", ".sqlitedb")
MAX_CANDIDATES = 100          # keys tried per file; the list is whatever was supplied or found, never generated
MAX_EVIDENCE_PASSPHRASES = 20 # text values found in preference files that are tried as passphrases
_HEX = re.compile(r"^(?:x')?([0-9a-fA-F]+)'?$")

KeyMaterial = Union[bytes, str]


def key_fingerprint(material: KeyMaterial) -> str:
    """Identifies a key in logs without revealing it."""
    raw = material.encode("utf-8") if isinstance(material, str) else bytes(material)
    return hashlib.sha256(raw).hexdigest()[:8]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def encrypted_database_reason(path: str) -> Optional[str]:
    """Why this file is believed to be an encrypted database, or None when it is not (plaintext SQLite, not a
    database file, too small, or not random-looking)."""
    if not path.lower().endswith(DB_EXTENSIONS):
        return None
    try:
        size = os.path.getsize(path)
        if size < 1024:
            return None
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    if head.startswith(SQLITE_MAGIC):
        return None
    e = _entropy(head)
    if e < 7.2:
        return None
    return f"no SQLite header; first {len(head)} bytes have entropy {e:.2f} bits/byte (random-looking, so likely encrypted)"


def normalise_key(raw: KeyMaterial) -> List[Tuple[str, KeyMaterial]]:
    """The ways one supplied value can be read as key material: raw bytes, hex, base64, or a passphrase.

    Each reading is a different interpretation of the same value, not a guess at a different value.
    """
    out: List[Tuple[str, KeyMaterial]] = []
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
        if len(b) in (32, 48):
            out.append(("raw", b))
        try:
            raw = b.decode("utf-8")
        except UnicodeDecodeError:
            return out
    text = str(raw).strip()
    if not text:
        return out
    m = _HEX.match(text)
    if m and len(m.group(1)) in (64, 96):
        try:
            out.append(("hex", bytes.fromhex(m.group(1))))
        except ValueError:
            pass
    try:
        b64 = base64.b64decode(text, validate=True)
        if len(b64) in (32, 48):
            out.append(("base64", b64))
    except (binascii.Error, ValueError):
        pass
    if 4 <= len(text) <= 256:
        out.append(("passphrase", text))
    return out


def build_candidates(supplied: Optional[Dict[str, Any]], carved: Optional[Dict[str, Any]]) -> List[Tuple[str, KeyMaterial]]:
    """(label, key material) for every key the examiner supplied and every one found in the evidence."""
    cands: List[Tuple[str, KeyMaterial]] = []
    seen = set()
    for origin, bag in (("supplied", supplied or {}), ("evidence", carved or {})):
        for name, value in bag.items():
            if value in (None, "", "Present"):
                continue
            for how, material in normalise_key(value):
                ident = (how, material if isinstance(material, bytes) else material.encode("utf-8"))
                if ident in seen:
                    continue
                seen.add(ident)
                cands.append((f"{origin}:{name}:{how}", material))
    # Readings that need no key stretching go first; passphrases cost a 256,000-round PBKDF2 per profile, so they are
    # capped. A key the examiner supplied is never dropped by the cap.
    def _rank(c: Tuple[str, KeyMaterial]) -> Tuple[int, int]:
        is_pass = c[0].endswith(":passphrase")
        return (1 if is_pass else 0, 0 if c[0].startswith("supplied:") else 1)

    cands.sort(key=_rank)
    kept: List[Tuple[str, KeyMaterial]] = []
    evidence_passphrases = 0
    for c in cands:
        if c[0].startswith("evidence:") and c[0].endswith(":passphrase"):
            evidence_passphrases += 1
            if evidence_passphrases > MAX_EVIDENCE_PASSPHRASES:
                continue
        kept.append(c)
    # The cap applies to what the tool found in the evidence. A key the examiner supplied is never cut, however many
    # readings the evidence offers.
    supplied_kept = [c for c in kept if c[0].startswith("supplied:")]
    room = max(0, MAX_CANDIDATES - len(supplied_kept))
    found_kept = [c for c in kept if not c[0].startswith("supplied:")][:room]
    allowed = {id(c) for c in supplied_kept + found_kept}
    return [c for c in kept if id(c) in allowed]


def _opens_as_sqlite(path: str) -> bool:
    try:
        c = sqlite3.connect(pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro", uri=True)
        try:
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return True
        finally:
            c.close()
    except sqlite3.Error:
        return False


def try_decrypt(path: str, out_dir: str, candidates: List[Tuple[str, KeyMaterial]]) -> Dict[str, Any]:
    """Tries each candidate key on the file. Returns an outcome dict:

    status: DECRYPTED | NO_KEY | KEY_FOUND_OUTPUT_UNREADABLE
    out_path, key_label, key_fingerprint, profile, notes (list of caveats), report (dict)
    """
    from src.crypto.sqlcipher import SQLCipherDecryptor

    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(path)
    out_db = os.path.join(out_dir, base)
    wal = path + "-wal"
    out_wal = out_db + "-wal"
    if not candidates:
        return {"status": "NO_KEY", "tried": 0, "notes": ["no key was supplied or found in the evidence"]}

    for label, material in candidates:
        dec = SQLCipherDecryptor()
        try:
            ok, frames = dec.decrypt_database_and_wal(
                path, wal if os.path.exists(wal) else None, out_db, out_wal if os.path.exists(wal) else None, material)
        except Exception as exc:  # a malformed key or file must not stop the ingest
            ok, frames = False, 0
            dec.last_report.failure = f"{type(exc).__name__}: {exc}"
        if not ok:
            continue
        rep = dec.last_report
        notes: List[str] = []
        if rep.db_pages_failed_mac:
            shown = ", ".join(str(p) for p in rep.db_pages_failed_mac[:10])
            more = "" if len(rep.db_pages_failed_mac) <= 10 else f" and {len(rep.db_pages_failed_mac) - 10} more"
            notes.append(f"{len(rep.db_pages_failed_mac)} of {rep.db_pages} database page(s) failed their HMAC "
                         f"(page {shown}{more}); they are decrypted but not authenticated")
        if rep.wal_frames_rejected:
            notes.append(f"{rep.wal_frames_rejected} of {rep.wal_frames_total} WAL frame(s) were not used: {rep.wal_stop_reason}")
        if not rep.mac_checked:
            notes.append("this SQLCipher profile has no per-page HMAC, so pages could not be authenticated")
        if not _opens_as_sqlite(out_db):
            return {"status": "KEY_FOUND_OUTPUT_UNREADABLE", "key_label": label, "key_fingerprint": key_fingerprint(material),
                    "profile": rep.profile, "notes": notes + ["the decrypted file does not open as a SQLite database"],
                    "tried": 0}
        return {
            "status": "DECRYPTED", "out_path": out_db, "wal_path": out_wal if frames else None,
            "key_label": label, "key_fingerprint": key_fingerprint(material), "profile": rep.profile,
            "notes": notes, "report": {
                "db_pages": rep.db_pages, "db_pages_failed_mac": list(rep.db_pages_failed_mac),
                "wal_frames_total": rep.wal_frames_total, "wal_frames_written": rep.wal_frames_written,
                "wal_frames_rejected": rep.wal_frames_rejected, "mac_checked": rep.mac_checked,
            },
        }
    # nothing opened it: do not leave a half-written output behind
    for p in (out_db, out_wal):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    return {"status": "NO_KEY", "tried": len(candidates),
            "notes": [f"{len(candidates)} key reading(s) tried; none authenticated the first page"]}
