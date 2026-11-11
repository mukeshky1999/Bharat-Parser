"""
Package initialization for Phase 5, Module 5.2:
The Telegram & Signal Deep Decoders.
"""

from src.telegram_signal.models import (
    PlatformFamily,
    PeerType,
    LocalRoleInGroup,
    ThreadClassification,
    MessagingPeerRecord,
    MessagingMessageRecord,
)
from src.telegram_signal.tl_deserializer import (
    TLStreamReader,
    decode_tl_user,
    decode_tl_message,
)
from src.telegram_signal.telegram_decoder import (
    TelegramDatabaseDecoder,
    discover_telegram_accounts,
    unpack_dialog_uid,
)
from src.telegram_signal.signal_decoder import (
    SignalDatabaseDecoder,
)
from src.telegram_signal.engine import (
    TelegramSignalEngine,
)

__all__ = [
    "PlatformFamily",
    "PeerType",
    "LocalRoleInGroup",
    "ThreadClassification",
    "MessagingPeerRecord",
    "MessagingMessageRecord",
    "TLStreamReader",
    "decode_tl_user",
    "decode_tl_message",
    "TelegramDatabaseDecoder",
    "discover_telegram_accounts",
    "unpack_dialog_uid",
    "SignalDatabaseDecoder",
    "TelegramSignalEngine",
]
