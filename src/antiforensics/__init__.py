"""
Phase 6 Module 6.5: Anti-Forensics, OS Integrity, Clock Manipulation, Mock GPS & Indian Banking Trojan Engine.
Complies with AGENTS.md Constitution.
"""

from src.antiforensics.models import (
    IntegrityFindingCategory,
    TamperCategory,
    SpoofMethod,
    ThreatCategory,
    OSIntegrityAuditRecord,
    ClockTamperGapRecord,
    LocationSpoofContradictionRecord,
    MalwareThreatRecord,
    extract_telegram_c2,
    parse_ussd_forwarding,
    parse_anydesk_trace_events,
)
from src.antiforensics.integrity_auditor import OSIntegrityAuditor
from src.antiforensics.clock_gap_detector import ClockTamperGapDetector
from src.antiforensics.location_spoof_auditor import LocationSpoofAuditor
from src.antiforensics.malware_auditor import MalwareRemoteAccessAuditor
from src.antiforensics.engine import AntiForensicsEngine

__all__ = [
    "IntegrityFindingCategory",
    "TamperCategory",
    "SpoofMethod",
    "ThreatCategory",
    "OSIntegrityAuditRecord",
    "ClockTamperGapRecord",
    "LocationSpoofContradictionRecord",
    "MalwareThreatRecord",
    "extract_telegram_c2",
    "parse_ussd_forwarding",
    "parse_anydesk_trace_events",
    "OSIntegrityAuditor",
    "ClockTamperGapDetector",
    "LocationSpoofAuditor",
    "MalwareRemoteAccessAuditor",
    "AntiForensicsEngine",
]
