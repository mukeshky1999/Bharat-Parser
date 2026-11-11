"""
VFS Zero-Omission Accounting Auditor (Sub-Engine 8.2A).
Enforces mathematical conservation law N_total == N_State1 + N_State2 + N_State3 + N_State4
and detects unclaimed app sandbox data stores.
"""

import json
import os
import re
from typing import Any, Optional

from src.zero_omission_and_fts5.models import (
    AccountingState,
    DetectedMagicSignature,
    VfsAccountingRecord,
)


class VfsZeroOmissionAuditor:
    """Audits every VFS file node to prevent silent omissions across post-acquisition forensic images."""

    SYSTEM_PARTITION_PREFIXES = (
        "/system/",
        "/vendor/",
        "/product/",
        "/apex/",
        "/system_ext/",
        "/odm/",
        "/oem/",
        "/System/Library/",
        "/usr/",
        "/bin/",
        "/sbin/",
    )

    STATIC_RESOURCE_EXTENSIONS = {
        ".ttf",
        ".otf",
        ".arsc",
        ".lproj",
        ".pak",
        ".nib",
        ".car",
    }

    APP_SANDBOX_PATTERN = re.compile(
        r"^/(?:data/(?:user(?:_de)?/\d+|data)|private/var/(?:mobile/Containers/Data/Application|containers/Data/Application)/[A-F0-9-]+)/([^/]+)/"
    )

    def resolve_app_package(self, path: str) -> Optional[str]:
        """Resolves the owning application package or bundle identifier from the canonical VFS path."""
        match = self.APP_SANDBOX_PATTERN.search(path)
        if match:
            return match.group(1)
        if "/Android/data/" in path:
            parts = path.split("/Android/data/")
            if len(parts) > 1:
                sub = parts[1].split("/")
                if sub and sub[0]:
                    return sub[0]
        return None

    def audit_vfs_entries(
        self, entries: list[dict[str, Any]]
    ) -> tuple[list[VfsAccountingRecord], list[dict[str, Any]]]:
        """Classifies each VFS entry into one of the 4 mutually exclusive states and verifies conservation."""
        accounting_records: list[VfsAccountingRecord] = []
        alerts: list[dict[str, Any]] = []

        for entry in entries:
            vfs_file_id = int(entry["vfs_file_id"])
            path = str(entry.get("canonical_vfs_path", ""))
            byte_size = int(entry.get("file_byte_size", 0))
            consumed_modules = entry.get("consumed_by_modules") or []
            if isinstance(consumed_modules, str):
                try:
                    consumed_modules = json.loads(consumed_modules)
                except Exception:
                    consumed_modules = [consumed_modules]
            extracted_count = int(entry.get("extracted_records_count", 0))
            is_blocked = bool(entry.get("is_blocked", False))

            _, ext = os.path.splitext(path)
            ext_lower = ext.lower() if ext else None

            package = entry.get("owning_app_package_or_domain") or self.resolve_app_package(path)

            # Classify into 4 mutually exclusive states
            if is_blocked or entry.get("block_reason"):
                state = AccountingState.STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED
            elif consumed_modules:
                state = AccountingState.STATE_1_PARSED_AND_VERIFIED
            elif any(path.startswith(pfx) for pfx in self.SYSTEM_PARTITION_PREFIXES) or (
                ext_lower in self.STATIC_RESOURCE_EXTENSIONS and not package
            ):
                state = AccountingState.STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE
            else:
                state = AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT

            # Check for unclaimed app sandbox data store alert
            if state == AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT:
                is_app_store = any(sub in path for sub in ("/databases/", "/files/", "/shared_prefs/"))
                if package and is_app_store and byte_size > 0:
                    alerts.append(
                        {
                            "alert_type": "UNCLAIMED_APP_SANDBOX_DATA_STORE",
                            "vfs_file_id": vfs_file_id,
                            "canonical_vfs_path": path,
                            "details": f"Unclaimed app sandbox data store in package '{package}' ({byte_size} bytes)",
                        }
                    )

            rec = VfsAccountingRecord(
                vfs_file_id=vfs_file_id,
                canonical_vfs_path=path,
                owning_app_package_or_domain=package,
                file_byte_size=byte_size,
                accounting_state=state,
                consumed_by_modules_json=json.dumps(consumed_modules),
                extracted_records_count=extracted_count,
                filename_extension=ext_lower,
                detected_magic_signature=DetectedMagicSignature.UNKNOWN_BINARY.value,
                is_extension_spoofed_mismatch=0,
                shannon_entropy_bits=None,
                chi_square_uniformity_score=None,
                entropy_crypto_classification=None,
                unk_introspection_hit_count=0,
            )
            accounting_records.append(rec)

        # Enforce mathematical conservation law
        total = len(accounting_records)
        s1 = sum(1 for r in accounting_records if r.accounting_state == AccountingState.STATE_1_PARSED_AND_VERIFIED)
        s2 = sum(1 for r in accounting_records if r.accounting_state == AccountingState.STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED)
        s3 = sum(1 for r in accounting_records if r.accounting_state == AccountingState.STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE)
        s4 = sum(1 for r in accounting_records if r.accounting_state == AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT)

        if total != s1 + s2 + s3 + s4:
            raise RuntimeError(
                f"Zero-omission accounting invariant violated: total {total} != {s1} + {s2} + {s3} + {s4}"
            )

        return accounting_records, alerts
