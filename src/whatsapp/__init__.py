"""
Package initialization for Phase 5, Module 5.1:
The WhatsApp Ecosystem Deep Decoder.
"""

from src.whatsapp.models import (
    IdentityType,
    MessageDirection,
    MessageTypeCategory,
    WhatsAppIdentityRecord,
    WhatsAppMessageRecord,
    WhatsAppCompanionDeviceRecord,
)
from src.whatsapp.decoder import (
    WhatsAppDatabaseDecoder,
    build_unified_identity_directory,
    unmask_lid,
)
from src.whatsapp.recovery import (
    reconstruct_revoked_messages,
    merge_historical_crypt15_backup,
)
from src.whatsapp.engine import (
    WhatsAppEcosystemEngine,
)

__all__ = [
    "IdentityType",
    "MessageDirection",
    "MessageTypeCategory",
    "WhatsAppIdentityRecord",
    "WhatsAppMessageRecord",
    "WhatsAppCompanionDeviceRecord",
    "WhatsAppDatabaseDecoder",
    "build_unified_identity_directory",
    "unmask_lid",
    "reconstruct_revoked_messages",
    "merge_historical_crypt15_backup",
    "WhatsAppEcosystemEngine",
]
