"""
Data models and canonical enums for Phase 9, Module 9.1:
Core Desktop Workstation Shell, Case Command Center, Virtualized Evidence Grids & Synchronized 3-Pane Hex Layout.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class HexLayerType(str, Enum):
    """The 4 structural highlighting layers of the Synchronized Hex Inspector."""
    LAYER_1_PAGE_OR_WAL_HEADER = "LAYER_1_PAGE_OR_WAL_HEADER"
    LAYER_2_CELL_HEADER = "LAYER_2_CELL_HEADER"
    LAYER_3_COLUMN_PAYLOAD = "LAYER_3_COLUMN_PAYLOAD"
    LAYER_4_SLACK_OR_FREEBLOCK = "LAYER_4_SLACK_OR_FREEBLOCK"


class TimezoneDisplayMode(str, Enum):
    """Persistent 3-mode timezone rendering options for forensic timestamps."""
    DUAL_IST_AND_UTC = "DUAL_IST_AND_UTC"
    IST_PRIMARY_ONLY = "IST_PRIMARY_ONLY"
    UTC_PRIMARY_WITH_DEVICE_RECORDED_TZ = "UTC_PRIMARY_WITH_DEVICE_RECORDED_TZ"


class TagCategoryBadge(str, Enum):
    """Categorical badges for examiner annotations and courtroom exhibit tags."""
    KEY_SMOKING_GUN = "KEY_SMOKING_GUN"
    MULE_ACCOUNT_FREEZE = "MULE_ACCOUNT_FREEZE"
    CONSPIRACY_CHAT = "CONSPIRACY_CHAT"
    ALIBI_PROOF = "ALIBI_PROOF"
    TAMPER_EVIDENCE = "TAMPER_EVIDENCE"


@dataclass
class ByteHighlightSpan:
    """Color-coded byte span within the hex viewer."""
    layer_type: HexLayerType
    start_offset: int
    end_offset: int
    css_color_class: str
    label: str = ""


@dataclass
class HexSliceWindow:
    """4 KB page-aligned binary window slice for streaming hex inspection."""
    base_offset: int
    length: int
    data: bytes = b""


@dataclass
class HexSliceInspectionResult:
    """Synchronized 3-pane hex slice inspection with formatted hex and ascii tokens."""
    cursor_byte_offset: int
    slice_length: int
    hex_tokens: list[str] = field(default_factory=list)
    ascii_tokens: list[str] = field(default_factory=list)
    int32_le: int = 0
    uint32_le: int = 0
    data_interpreter: Optional["DataInterpreterResult"] = None


@dataclass
class DataInterpreterResult:
    """Live 12-format byte conversion panel outputs."""
    int8: int = 0
    uint8: int = 0
    int16_le: int = 0
    int16_be: int = 0
    uint16_le: int = 0
    uint16_be: int = 0
    int32_le: int = 0
    int32_be: int = 0
    uint32_le: int = 0
    uint32_be: int = 0
    int64_le: int = 0
    int64_be: int = 0
    uint64_le: int = 0
    uint64_be: int = 0
    sqlite_varint: int = 0
    leb128_varint: int = 0
    float32_le: float = 0.0
    float32_be: float = 0.0
    float64_le: float = 0.0
    float64_be: float = 0.0
    unix_s_ist_utc: str = ""
    unix_ms_ist_utc: str = ""
    unix_us_ist_utc: str = ""
    cocoa_s_ist_utc: str = ""
    utf8_string: str = ""
    utf16_le_string: str = ""
    hex_string: str = ""


@dataclass
class ViewportVirtualizationState:
    """Fixed-pool viewport window indices for 60 FPS table virtualization."""
    i_first: int
    i_last: int
    row_height: int
    total_rows: int
    mounted_row_count: int


@dataclass
class QuantileMilestone:
    """Quantile milestone checkpoint for O(1) scrollbar thumb seeking."""
    row_index: int
    timestamp_utc_ns: int
    timeline_event_uid: int


@dataclass
class ExaminerBookmarkRecord:
    """Examiner annotation and relied-upon exhibit record for workstation_ui_state.sqlite."""
    target_domain_table: str
    target_record_uid: int
    source_vfs_file_id: int
    tag_category_badge: TagCategoryBadge
    bookmark_uid: Optional[int] = None
    physical_byte_offset: Optional[int] = None
    is_relied_upon_for_sec230_bnss: int = 1
    examiner_narrative_note: Optional[str] = None
    created_by_examiner: str = "Examiner"
    created_at_ist_iso: str = ""


@dataclass
class BiDiInspectionResult:
    """Result of Unicode BiDi control character spoof inspection."""
    has_unicode_bidi_spoof: bool
    rendered_badge_string: str
    spoof_character_details: str
