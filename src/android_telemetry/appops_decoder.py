"""
Sub-Engine 6.2B: 3-Source Android AppOps & Privacy Sensor Auditor.
Implements the built-in ABX\\x00 (Android Binary XML) deserializer and decodes
/data/system/appops.xml and /data/system/appops/discrete/ (Camera, Mic, Location, Accessibility).
Complies with Section 4 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

from io import BytesIO
import logging
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from src.core.enums import ForensicGroup
from src.android_telemetry.models import (
    AppOpsSourceSubsystem,
    AndroidAppOpRecord,
    unix_ms_to_utc_iso,
)

logger = logging.getLogger(__name__)


class ABXDeserializer:
    """Deserializer for Android Binary XML (ABX\\x00) introduced in Android 12."""

    # Event types (lower 4 bits)
    START_DOCUMENT = 0
    END_DOCUMENT = 1
    START_TAG = 2
    END_TAG = 3
    TEXT = 4
    ATTRIBUTE = 15

    # Data types (upper 4 bits)
    TYPE_NULL = 1
    TYPE_STRING = 2
    TYPE_STRING_INTERNED = 3
    TYPE_BYTES_HEX = 4
    TYPE_BYTES_BASE64 = 5
    TYPE_INT = 6
    TYPE_INT_HEX = 7
    TYPE_LONG = 8
    TYPE_LONG_HEX = 9
    TYPE_FLOAT = 10
    TYPE_DOUBLE = 11
    TYPE_BOOLEAN_TRUE = 12
    TYPE_BOOLEAN_FALSE = 13

    def is_abx(self, data: bytes) -> bool:
        """Returns True if the byte slice starts with ABX\\x00 magic header."""
        return data.startswith(b"ABX\x00")

    def deserialize(self, data: bytes) -> Optional[ET.Element]:
        """Deserializes ABX binary stream into an ElementTree Element root."""
        if not self.is_abx(data):
            return None

        stream = BytesIO(data[4:])  # Skip "ABX\0"
        interned_strings: List[str] = []
        element_stack: List[ET.Element] = []
        root: Optional[ET.Element] = None

        def read_string() -> str:
            raw_len = stream.read(2)
            if len(raw_len) < 2:
                return ""
            s_len = struct.unpack(">H", raw_len)[0]
            s_bytes = stream.read(s_len)
            return s_bytes.decode("utf-8", errors="replace")

        def read_value(d_type: int) -> Any:
            if d_type == self.TYPE_NULL:
                return ""
            elif d_type == self.TYPE_STRING:
                return read_string()
            elif d_type == self.TYPE_STRING_INTERNED:
                raw_idx = stream.read(2)
                if len(raw_idx) < 2:
                    return ""
                idx = struct.unpack(">H", raw_idx)[0]
                if idx == 0xFFFF:
                    new_s = read_string()
                    interned_strings.append(new_s)
                    return new_s
                elif 0 <= idx < len(interned_strings):
                    return interned_strings[idx]
                return ""
            elif d_type in (self.TYPE_INT, self.TYPE_INT_HEX):
                raw = stream.read(4)
                return struct.unpack(">i", raw)[0] if len(raw) == 4 else 0
            elif d_type in (self.TYPE_LONG, self.TYPE_LONG_HEX):
                raw = stream.read(8)
                return struct.unpack(">q", raw)[0] if len(raw) == 8 else 0
            elif d_type == self.TYPE_FLOAT:
                raw = stream.read(4)
                return struct.unpack(">f", raw)[0] if len(raw) == 4 else 0.0
            elif d_type == self.TYPE_DOUBLE:
                raw = stream.read(8)
                return struct.unpack(">d", raw)[0] if len(raw) == 8 else 0.0
            elif d_type == self.TYPE_BOOLEAN_TRUE:
                return "true"
            elif d_type == self.TYPE_BOOLEAN_FALSE:
                return "false"
            return ""

        while True:
            byte_tag = stream.read(1)
            if not byte_tag:
                break
            tag = byte_tag[0]
            event_type = tag & 0x0F
            data_type = tag >> 4

            if event_type == self.START_DOCUMENT:
                continue
            elif event_type == self.END_DOCUMENT:
                break
            elif event_type == self.START_TAG:
                tag_name = read_value(data_type)
                new_elem = ET.Element(str(tag_name))
                if element_stack:
                    element_stack[-1].append(new_elem)
                else:
                    root = new_elem
                element_stack.append(new_elem)
            elif event_type == self.END_TAG:
                if element_stack:
                    element_stack.pop()
            elif event_type == self.ATTRIBUTE:
                attr_name = read_string()
                attr_val = str(read_value(data_type))
                if element_stack:
                    element_stack[-1].set(attr_name, attr_val)
            elif event_type == self.TEXT:
                text_val = str(read_value(data_type))
                if element_stack:
                    element_stack[-1].text = text_val

        return root


class AppOpsDecoder:
    """Decoder for Android AppOps permissions and Discrete Privacy logs."""

    OP_CODE_MAP: Dict[int, str] = {
        0: "0:COARSE_LOCATION",
        1: "1:FINE_LOCATION",
        2: "2:GPS",
        14: "14:READ_SMS",
        16: "16:WRITE_SMS",
        20: "20:RECEIVE_SMS",
        21: "21:RECEIVE_EMERGENCY_SMS",
        22: "22:RECEIVE_MMS",
        24: "24:SYSTEM_ALERT_WINDOW",
        26: "26:CAMERA",
        27: "27:RECORD_AUDIO",
        29: "29:READ_CLIPBOARD",
        30: "30:WRITE_CLIPBOARD",
        41: "41:MONITOR_LOCATION",
        42: "42:MONITOR_HIGH_POWER_LOCATION",
        43: "43:GET_USAGE_STATS",
        45: "45:ACTIVATE_VPN",
        66: "66:REQUEST_INSTALL_PACKAGES",
        70: "70:BIND_ACCESSIBILITY_SERVICE",
    }

    UID_STATE_MAP: Dict[int, str] = {
        100: "TOP",
        200: "FOREGROUND_UI",
        300: "FOREGROUND_UI",
        400: "FOREGROUND_SERVICE",
        500: "FOREGROUND_SERVICE",
        600: "BACKGROUND",
        700: "BACKGROUND",
    }

    def __init__(self) -> None:
        self.abx = ABXDeserializer()

    def _get_root_element(self, file_path: str) -> Optional[ET.Element]:
        """Reads file, automatically checking for ABX binary XML before plain XML."""
        if not os.path.exists(file_path):
            return None

        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return None

        if self.abx.is_abx(data):
            return self.abx.deserialize(data)

        try:
            return ET.fromstring(data)
        except Exception as exc:
            logger.debug("Failed parsing XML %s: %s", file_path, exc)
            return None

    def decode_discrete_appops_file(
        self,
        file_path: str,
        source_vfs_file_id: int = 902,
    ) -> List[AndroidAppOpRecord]:
        """Parses an Android 12-17 discrete AppOps history file."""
        records: List[AndroidAppOpRecord] = []
        root = self._get_root_element(file_path)
        if root is None:
            return records

        # Traverse: <p pn="..."> -> <u ui="..."> -> <o op="..."> -> <a at="..."> -> <e nt="..." nd="..." uf="..."/>
        # Or direct recursive search for <p> and children
        for p_elem in root.iter("p"):
            pkg_name = p_elem.get("pn", "Unknown")

            for u_elem in p_elem.iter("u"):
                raw_ui = u_elem.get("ui")
                linux_uid = int(raw_ui) if raw_ui is not None else None

                for o_elem in u_elem.iter("o"):
                    raw_op = o_elem.get("op")
                    op_code = int(raw_op) if raw_op is not None else 0
                    op_name = self.OP_CODE_MAP.get(op_code, f"{op_code}:OP_{op_code}")

                    for e_elem in o_elem.iter("e"):
                        raw_nt = e_elem.get("nt")
                        raw_nd = e_elem.get("nd")
                        raw_uf = e_elem.get("uf")

                        if not raw_nt:
                            continue

                        nt_ms = int(raw_nt)
                        nd_ms = int(raw_nd) if raw_nd else -1
                        uf_code = int(raw_uf) if raw_uf else 500

                        duration_sec = round(nd_ms / 1000.0, 3) if nd_ms > 0 else 0.0
                        proc_state = self.UID_STATE_MAP.get(uf_code, "FOREGROUND_SERVICE" if uf_code == 500 else f"UID_STATE_{uf_code}")
                        ts_iso = unix_ms_to_utc_iso(nt_ms)

                        rec = AndroidAppOpRecord(
                            source_subsystem=AppOpsSourceSubsystem.APPOPS_DISCRETE_7DAY_HISTORY,
                            source_vfs_file_id=source_vfs_file_id,
                            package_name=pkg_name,
                            linux_uid=linux_uid,
                            op_code_and_name=op_name,
                            process_uid_state=proc_state,
                            access_outcome="ALLOWED_GRANTED",
                            access_timestamp_utc_iso=ts_iso,
                            access_duration_seconds=duration_sec,
                            forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                        )
                        records.append(rec)

        return records

    def decode_appops_xml(
        self,
        file_path: str,
        source_vfs_file_id: int = 902,
    ) -> List[AndroidAppOpRecord]:
        """Parses /data/system/appops.xml summary file."""
        records: List[AndroidAppOpRecord] = []
        root = self._get_root_element(file_path)
        if root is None:
            return records

        for pkg_elem in root.iter("pkg"):
            pkg_name = pkg_elem.get("n", "Unknown")

            for uid_elem in pkg_elem.iter("uid"):
                raw_uid = uid_elem.get("id")
                linux_uid = int(raw_uid) if raw_uid else None

                for op_elem in uid_elem.iter("op"):
                    raw_op = op_elem.get("n")
                    op_code = int(raw_op) if raw_op else 0
                    op_name = self.OP_CODE_MAP.get(op_code, f"{op_code}:OP_{op_code}")

                    for st_elem in op_elem.iter("st"):
                        t_ms = int(st_elem.get("t", 0))
                        r_ms = int(st_elem.get("r", 0))
                        d_ms = int(st_elem.get("d", 0))
                        dur_sec = round(d_ms / 1000.0, 3) if d_ms > 0 else None

                        if t_ms > 0:
                            records.append(
                                AndroidAppOpRecord(
                                    source_subsystem=AppOpsSourceSubsystem.APPOPS_XML_SUMMARY,
                                    source_vfs_file_id=source_vfs_file_id,
                                    package_name=pkg_name,
                                    linux_uid=linux_uid,
                                    op_code_and_name=op_name,
                                    process_uid_state="FOREGROUND_UI",
                                    access_outcome="ALLOWED_GRANTED",
                                    access_timestamp_utc_iso=unix_ms_to_utc_iso(t_ms),
                                    access_duration_seconds=dur_sec,
                                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                                )
                            )
                        if r_ms > 0:
                            records.append(
                                AndroidAppOpRecord(
                                    source_subsystem=AppOpsSourceSubsystem.APPOPS_XML_SUMMARY,
                                    source_vfs_file_id=source_vfs_file_id,
                                    package_name=pkg_name,
                                    linux_uid=linux_uid,
                                    op_code_and_name=op_name,
                                    process_uid_state="BACKGROUND",
                                    access_outcome="REJECTED_DENIED",
                                    access_timestamp_utc_iso=unix_ms_to_utc_iso(r_ms),
                                    access_duration_seconds=dur_sec,
                                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                                )
                            )

        return records
