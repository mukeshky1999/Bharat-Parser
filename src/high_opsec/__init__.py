"""
Phase 5 Module 5.3: High-OpSec, Decentralized & Privacy Messengers Deep Decoder.
"""

from src.high_opsec.models import (
    OpSecPlatformName,
    IdentityRole,
    MessageDirection,
    CovertInvitePlatform,
    OpSecIdentityRecord,
    OpSecMessageRecord,
    CovertInviteDiscoveryRecord,
    is_valid_session_id,
    is_valid_threema_id,
    is_valid_zangi_number,
    is_valid_matrix_id,
    is_valid_simplex_invite,
    is_valid_briar_link,
)
from src.high_opsec.session_decoder import SessionDecoder
from src.high_opsec.simplex_decoder import SimpleXDecoder
from src.high_opsec.privacy_messengers_decoder import PrivacyMessengersDecoder
from src.high_opsec.cross_app_hunter import CrossAppCovertHandleHunter
from src.high_opsec.engine import HighOpSecMessengersEngine

__all__ = [
    "OpSecPlatformName",
    "IdentityRole",
    "MessageDirection",
    "CovertInvitePlatform",
    "OpSecIdentityRecord",
    "OpSecMessageRecord",
    "CovertInviteDiscoveryRecord",
    "is_valid_session_id",
    "is_valid_threema_id",
    "is_valid_zangi_number",
    "is_valid_matrix_id",
    "is_valid_simplex_invite",
    "is_valid_briar_link",
    "SessionDecoder",
    "SimpleXDecoder",
    "PrivacyMessengersDecoder",
    "CrossAppCovertHandleHunter",
    "HighOpSecMessengersEngine",
]
