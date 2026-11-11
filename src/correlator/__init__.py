"""
Phase 3, Module 3.5: The 4-Way UTR Correlator, VPA Handle Resolver & Mule-Account Fraud Detector.
Exposes public classes, models, and decoders for multi-layer financial fusion,
Julian-day/Verhoeff disambiguation, balance continuity auditing, and VPA routing.
"""

from src.correlator.engine import FinancialCorrelatorEngine
from src.correlator.fraud_detector import MuleAccountAndFraudDetector
from src.correlator.models import (
    CorroborationLevel,
    CounterpartyCommsCrosslinkRecord,
    FinancialFraudFlagRecord,
    FlagSeverity,
    FraudFlagCategory,
    UnifiedTransactionRecord,
    UTRValidationResult,
    VPAResolutionResult,
)
from src.correlator.utr_validator import NPCIUTRJulianAndVerhoeffValidator
from src.correlator.vpa_resolver import VPARoutingResolver

__all__ = [
    "CorroborationLevel",
    "CounterpartyCommsCrosslinkRecord",
    "FinancialCorrelatorEngine",
    "FinancialFraudFlagRecord",
    "FlagSeverity",
    "FraudFlagCategory",
    "MuleAccountAndFraudDetector",
    "NPCIUTRJulianAndVerhoeffValidator",
    "UnifiedTransactionRecord",
    "UTRValidationResult",
    "VPAResolutionResult",
    "VPARoutingResolver",
]
