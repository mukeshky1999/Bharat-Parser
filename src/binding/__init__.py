"""
Phase 3, Module 3.2: NPCI Common Library (CL) & Physical SIM / Hardware Device-Binding Forensics.
Exposes public classes, domain models, and parsers for SIM card attribution,
outbound VMN binding SMS analysis, and NPCI CL vault parsing.
"""

from src.binding.cl_vault import NPCICommonLibraryParser
from src.binding.engine import SIMBindingForensicEngine
from src.binding.models import (
    BindingAttributionVerdict,
    DeviceSIMCardHistoryRecord,
    NPCICommonLibraryVaultRecord,
    SeizureSlotState,
    SIMFormFactor,
    UPIOutboundBindingSMSAudit,
)
from src.binding.sms_audit import OutboundBindingSMSDecoder
from src.binding.telephony import TelephonyProviderDecoder
from src.binding.trojan_detector import GhostSIMBindingTrojanDetector

__all__ = [
    "BindingAttributionVerdict",
    "DeviceSIMCardHistoryRecord",
    "GhostSIMBindingTrojanDetector",
    "NPCICommonLibraryParser",
    "NPCICommonLibraryVaultRecord",
    "OutboundBindingSMSDecoder",
    "SeizureSlotState",
    "SIMBindingForensicEngine",
    "SIMFormFactor",
    "TelephonyProviderDecoder",
    "UPIOutboundBindingSMSAudit",
]
