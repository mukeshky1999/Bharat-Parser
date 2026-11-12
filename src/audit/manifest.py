"""Hash manifest for the evidence items of a case, with an honest re-verification state.

Unlike a manifest that marks every item "verified" when it is registered, an item here is NOT_REVERIFIED until
`reverify()` has actually re-read the file and compared it.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Dict, List, Optional

NOT_REVERIFIED = "NOT_REVERIFIED"
IDENTICAL = "IDENTICAL"
MODIFIED = "MODIFIED"
UNREADABLE = "UNREADABLE"


@dataclass(frozen=True)
class ManifestItem:
    name: str            # path relative to the evidence root, or exhibit name
    byte_size: int
    sha256: str
    md5: str
    hashed_at_utc: str
    reverified: str = NOT_REVERIFIED
    reverified_at_utc: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def hash_file(path: str) -> tuple[str, str, int]:
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


class HashManifest:
    def __init__(self) -> None:
        self.items: Dict[str, ManifestItem] = {}

    def add_file(self, name: str, path: str) -> ManifestItem:
        sha, md5, size = hash_file(path)
        item = ManifestItem(name=name, byte_size=size, sha256=sha, md5=md5, hashed_at_utc=_utc_now())
        self.items[name] = item
        return item

    def reverify(self, name: str, path: str) -> ManifestItem:
        old = self.items[name]
        try:
            sha, md5, size = hash_file(path)
            state = IDENTICAL if (sha, md5, size) == (old.sha256, old.md5, old.byte_size) else MODIFIED
        except OSError:
            state = UNREADABLE
        item = replace(old, reverified=state, reverified_at_utc=_utc_now())
        self.items[name] = item
        return item

    def merkle_root(self) -> str:
        """Root over items sorted by name. An odd node is carried up unchanged (never duplicated), so
        [a, b, c] and [a, b, c, c] have different roots. Empty manifest: 64 zeros."""
        if not self.items:
            return "0" * 64
        level: List[bytes] = []
        for name in sorted(self.items):
            it = self.items[name]
            leaf = bytearray(b"\x00" + name.encode("utf-8") + b"\x00")
            leaf += bytes.fromhex(it.sha256) + bytes.fromhex(it.md5) + struct.pack(">Q", it.byte_size)
            level.append(hashlib.sha256(bytes(leaf)).digest())
        while len(level) > 1:
            nxt: List[bytes] = []
            for i in range(0, len(level) - 1, 2):
                nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
            if len(level) % 2:
                nxt.append(level[-1])
            level = nxt
        return level[0].hex()
