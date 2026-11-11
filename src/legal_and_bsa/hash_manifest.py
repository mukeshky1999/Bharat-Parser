"""
Hierarchical Cryptographic Hash Manifest & Merkle Root Engine (Sub-Engine 8.3A).
Maintains 3-tier provenance (Tier 1, Tier 2A, Tier 2B, Tier 3) and computes the Case Master Merkle Root.
"""

from datetime import datetime, timezone
import hashlib
import os
import struct
from typing import Optional

from src.legal_and_bsa.models import (
    EvidentiaryHashManifestItem,
    HashTier,
    ImmutabilityStatus,
)


class HierarchicalHashManifestManager:
    """Computes dual SHA-256 + MD5 hashes, tracks multi-tier provenance, and compiles Merkle roots."""

    def __init__(self):
        self.items: list[EvidentiaryHashManifestItem] = []
        self._next_uid: int = 1

    @staticmethod
    def compute_file_hashes(file_path: str) -> tuple[str, str]:
        """Computes streaming SHA-256 (64 hex chars) and MD5 (32 hex chars) of a file on disk."""
        sha256_ctx = hashlib.sha256()
        md5_ctx = hashlib.md5()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(1048576)  # 1 MB read buffer
                if not chunk:
                    break
                sha256_ctx.update(chunk)
                md5_ctx.update(chunk)

        return sha256_ctx.hexdigest().lower(), md5_ctx.hexdigest().lower()

    def register_manifest_item(
        self,
        hash_tier: HashTier,
        canonical_path_or_exhibit_name: str,
        artifact_description: str,
        file_path: str,
        vfs_file_id_or_staging_id: Optional[int] = None,
        parent_manifest_item_uid: Optional[int] = None,
        crypto_unwrap_provenance_note: Optional[str] = None,
    ) -> EvidentiaryHashManifestItem:
        """Computes file hashes and registers an item in the evidentiary manifest."""
        sha256_hex, md5_hex = self.compute_file_hashes(file_path)
        byte_size = os.path.getsize(file_path)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        item = EvidentiaryHashManifestItem(
            manifest_item_uid=self._next_uid,
            hash_tier=hash_tier,
            canonical_path_or_exhibit_name=canonical_path_or_exhibit_name,
            artifact_description=artifact_description,
            byte_size=byte_size,
            sha256_hex=sha256_hex,
            md5_hex=md5_hex,
            blake3_hex=None,
            vfs_file_id_or_staging_id=vfs_file_id_or_staging_id,
            parent_manifest_item_uid=parent_manifest_item_uid,
            crypto_unwrap_provenance_note=crypto_unwrap_provenance_note,
            post_run_reverified_status=ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL,
            hashed_at_utc_iso=now_utc,
        )
        self._next_uid += 1
        self.items.append(item)
        return item

    def register_synthetic_manifest_item(
        self,
        hash_tier: HashTier,
        canonical_path_or_exhibit_name: str,
        artifact_description: str,
        byte_size: int,
        sha256_hex: str,
        md5_hex: str,
        blake3_hex: Optional[str] = None,
        vfs_file_id_or_staging_id: Optional[int] = None,
        parent_manifest_item_uid: Optional[int] = None,
        crypto_unwrap_provenance_note: Optional[str] = None,
    ) -> EvidentiaryHashManifestItem:
        """Registers a synthetic or pre-computed manifest item."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        item = EvidentiaryHashManifestItem(
            manifest_item_uid=self._next_uid,
            hash_tier=hash_tier,
            canonical_path_or_exhibit_name=canonical_path_or_exhibit_name,
            artifact_description=artifact_description,
            byte_size=byte_size,
            sha256_hex=sha256_hex.lower(),
            md5_hex=md5_hex.lower(),
            blake3_hex=blake3_hex,
            vfs_file_id_or_staging_id=vfs_file_id_or_staging_id,
            parent_manifest_item_uid=parent_manifest_item_uid,
            crypto_unwrap_provenance_note=crypto_unwrap_provenance_note,
            post_run_reverified_status=ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL,
            hashed_at_utc_iso=now_utc,
        )
        self._next_uid += 1
        self.items.append(item)
        return item

    def compute_case_merkle_root(self) -> str:
        """Constructs a deterministic SHA-256 Merkle tree over all manifest items."""
        if not self.items:
            return "0" * 64

        # 1. Deterministic sort by (hash_tier ASC, canonical_path_or_exhibit_name ASC)
        sorted_items = sorted(
            self.items,
            key=lambda x: (x.hash_tier.value, x.canonical_path_or_exhibit_name),
        )

        # 2. Compute leaf hashes
        # L_i = SHA256(UTF8(canonical_path) || 0x00 || bytes32(sha256) || bytes16(md5) || uint64_be(byte_size))
        current_level: list[bytes] = []
        for item in sorted_items:
            leaf_payload = bytearray(item.canonical_path_or_exhibit_name.encode("utf-8"))
            leaf_payload.append(0x00)
            leaf_payload.extend(bytes.fromhex(item.sha256_hex))
            leaf_payload.extend(bytes.fromhex(item.md5_hex))
            leaf_payload.extend(struct.pack(">Q", item.byte_size))
            leaf_hash = hashlib.sha256(leaf_payload).digest()
            current_level.append(leaf_hash)

        # 3. Binary Merkle tree reduction bottom-up
        while len(current_level) > 1:
            next_level: list[bytes] = []
            if len(current_level) % 2 != 0:
                # Duplicate last node if odd
                current_level.append(current_level[-1])

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                parent = hashlib.sha256(b"\x01" + left + right).digest()
                next_level.append(parent)

            current_level = next_level

        return current_level[0].hex().lower()
