"""
Core models, forensic enums, timestamp primitives, and thread-safe SQLite manager.
"""

from src.core.enums import (
    ForensicGroup,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ResidualConfidence,
    FinancialTransactionStatus,
    C2PAValidationState,
)
from src.core.timestamps import ForensicTimestamp
from src.core.sqlite_manager import connect_forensic_sqlite

# Aliases for convenience
FinancialTransactionState = FinancialTransactionStatus
C2paValidationStatus = C2PAValidationState
DualTimestamp = ForensicTimestamp

__all__ = [
    "ForensicGroup",
    "EvidentiaryExistence",
    "EvidentiaryAccess",
    "EvidentiaryStorage",
    "ResidualConfidence",
    "FinancialTransactionStatus",
    "FinancialTransactionState",
    "C2PAValidationState",
    "C2paValidationStatus",
    "ForensicTimestamp",
    "DualTimestamp",
    "connect_forensic_sqlite",
]
