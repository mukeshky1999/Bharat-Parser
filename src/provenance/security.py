"""
Extended Attributes, Inode Permissions, and Tamper Anomaly Decoder.
Phase 1, Module 1.2, Section 5.
"""

import logging
import plistlib
from typing import Optional, List

logger = logging.getLogger(__name__)


class SecurityMetadataDecoder:
    """Decodes POSIX modes, iOS Protection Classes, SELinux labels, and where-froms URLs."""

    PROTECTION_CLASSES = {
        1: "CLASS_A",  # NSFileProtectionComplete
        2: "CLASS_B",  # NSFileProtectionCompleteUnlessOpen
        3: "CLASS_C",  # NSFileProtectionCompleteUntilFirstUserAuthentication
        4: "CLASS_D",  # NSFileProtectionNone
    }

    def decode_posix_mode(self, mode: int) -> str:
        """Converts an integer inode mode to a canonical octal string (e.g., 0100644)."""
        return f"{mode:07o}"

    def decode_ios_protection_class(self, protection_class: int) -> Optional[str]:
        """Translates iOS NSFileProtection integer into canonical Class A-D enum string."""
        return self.PROTECTION_CLASSES.get(protection_class)

    def check_selinux_tamper(self, label: str, canonical_path: str) -> Optional[str]:
        """
        Inspects Android security.selinux label against known forensic tamper and injection rules.
        """
        lbl_lower = label.lower()

        # Rule 1: Root framework artifacts (Magisk, KernelSU, SuperSU)
        if any(token in lbl_lower for token in ("magisk", "ksu", "_su_", ":su:")) or lbl_lower.endswith("_su"):
            return "ROOT_FRAMEWORK_ARTIFACT"

        # Rule 2: Anomalous unlabeled files in critical system partitions
        system_roots = ("/system/", "/vendor/", "/data/app/")
        if any(canonical_path.startswith(root) for root in system_roots):
            if "unlabeled" in lbl_lower:
                return "ANOMALOUS_UNLABELED_SYSTEM_FILE"

        # Rule 3: ADB or shell injected files inside private application sandboxes
        app_roots = ("/data/data/", "/data/user/")
        if any(canonical_path.startswith(root) for root in app_roots):
            if "shell_data_file" in lbl_lower or "adb_data_file" in lbl_lower:
                return "ADB_OR_SHELL_INJECTED_FILE"

        return None

    def decode_where_froms(self, xattr_bytes: bytes) -> List[str]:
        """Decodes com.apple.metadata:kMDItemWhereFroms binary plist into download source URLs."""
        if not xattr_bytes:
            return []

        try:
            parsed = plistlib.loads(xattr_bytes)
            if isinstance(parsed, list):
                return [str(u) for u in parsed]
            elif isinstance(parsed, dict):
                return [str(v) for v in parsed.values()]
            else:
                return [str(parsed)]
        except Exception as err:
            logger.debug("Failed parsing kMDItemWhereFroms plist: %s", err)
            return []
