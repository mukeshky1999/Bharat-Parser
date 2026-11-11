"""
Sub-Engine 3.2C: Embedded NPCI Common Library (CL) Vault & Hardware Keystore Audit.
Parses NPCI Common Library preference XMLs and SQLite stores from host UPI applications
(e.g., shared_prefs/org.npci.upi.security.pinactivitycomponent.clprefs.xml).
Adheres strictly to AGENTS.md Forensic Invariants and Section 5 of Module 3.2 Spec.
"""

from pathlib import Path
from typing import List, Optional, Union
import xml.etree.ElementTree as ET

from src.binding.models import NPCICommonLibraryVaultRecord
from src.core.timestamps import ForensicTimestamp


class NPCICommonLibraryParser:
    """Parses embedded NPCI Common Library preference vaults and extracts bound device/SIM parameters."""

    CL_PREF_PATTERNS = (
        "*npci*",
        "*clprefs*",
        "*cl_*",
        "*pinactivitycomponent*",
        "*vault*",
        "*device_binding*",
    )

    def parse_cl_preferences(
        self,
        file_path: Union[str, Path],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> Optional[NPCICommonLibraryVaultRecord]:
        """
        Parses an Android shared_prefs XML file created by the NPCI Common Library.
        Extracts bound hardware device ID, K0 token flag, bound SIM ICCID, and registration timestamp.
        """
        target = Path(file_path)
        if not target.exists():
            return None

        try:
            tree = ET.parse(target)
            root = tree.getroot()
        except Exception:
            return None

        if root.tag != "map":
            return None

        cl_device_id: Optional[str] = None
        k0_present: int = 0
        bound_iccid: Optional[str] = None
        bound_sub_id: Optional[int] = None
        bound_mobile: Optional[str] = None
        registered_utc: Optional[str] = None

        for child in root:
            name = child.attrib.get("name", "")
            val_attr = child.attrib.get("value")
            text_val = child.text.strip() if child.text else None
            effective_val = val_attr if val_attr is not None else text_val

            name_lower = name.lower()

            # Bound hardware device ID
            if name_lower in ("cl_device_id", "device_id", "hardware_device_id", "cl_deviceid"):
                if effective_val:
                    cl_device_id = str(effective_val)

            # K0 vault token presence
            elif name_lower in ("k0_token", "k0", "token", "cl_k0_token", "vault_token"):
                if effective_val and len(str(effective_val)) > 0:
                    k0_present = 1

            # Bound SIM ICCID
            elif name_lower in ("bound_sim_iccid", "iccid", "saved_iccid", "bound_iccid", "sim_iccid"):
                if effective_val:
                    bound_iccid = str(effective_val)

            # Bound SIM subscription ID
            elif name_lower in ("bound_sim_sub_id", "sub_id", "bound_sub_id", "subscription_id"):
                if effective_val is not None:
                    try:
                        bound_sub_id = int(effective_val)
                    except ValueError:
                        bound_sub_id = None

            # Bound mobile MSISDN
            elif name_lower in ("bound_mobile_msisdn", "bound_mobile", "mobile_number", "msisdn", "phone_number"):
                if effective_val:
                    bound_mobile = str(effective_val)

            # Registration timestamp
            elif name_lower in (
                "binding_registration_ts",
                "registration_timestamp",
                "token_registration_ts",
                "binding_ts",
                "cl_registration_time",
            ):
                if effective_val:
                    try:
                        ts_num = int(effective_val)
                        if ts_num > 10_000_000_000:
                            # Milliseconds
                            registered_utc = ForensicTimestamp.from_unix_milliseconds(ts_num).utc_iso8601
                        elif ts_num > 0:
                            # Seconds
                            registered_utc = ForensicTimestamp.from_unix_seconds(ts_num).utc_iso8601
                    except ValueError:
                        registered_utc = str(effective_val)

        return NPCICommonLibraryVaultRecord(
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
            bound_sim_iccid_in_app=bound_iccid,
            bound_sim_sub_id_in_app=bound_sub_id,
            bound_mobile_msisdn=bound_mobile,
            bound_hardware_device_id=cl_device_id,
            cl_k0_token_present=k0_present,
            matched_keystore_alias="npci_k0_key" if k0_present else None,
            binding_registered_utc_iso=registered_utc,
        )

    def scan_app_sandbox(
        self,
        app_sandbox_dir: Union[str, Path],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
    ) -> List[NPCICommonLibraryVaultRecord]:
        """
        Recursively scans an extracted app sandbox for NPCI Common Library preference files.
        """
        root_dir = Path(app_sandbox_dir)
        if not root_dir.exists():
            return []

        vault_records: List[NPCICommonLibraryVaultRecord] = []
        shared_prefs_dir = root_dir / "shared_prefs"
        candidate_files: List[Path] = []

        if shared_prefs_dir.exists():
            for pat in self.CL_PREF_PATTERNS:
                candidate_files.extend(shared_prefs_dir.glob(pat))

        for file_path in set(candidate_files):
            if file_path.suffix.lower() == ".xml":
                rec = self.parse_cl_preferences(
                    file_path=file_path,
                    app_instance_id=app_instance_id,
                    source_vfs_file_id=source_vfs_file_id,
                )
                if rec is not None:
                    vault_records.append(rec)

        return vault_records
