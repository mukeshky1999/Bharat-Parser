"""
Sub-Engine 6.4D: Global & Indian Dating and Matrimonial App Forensics.
Disambiguates Passport/Travel Mode location spoofing, recovers unmatched peers from SQLite -wal,
and automatically extracts off-platform WhatsApp/Telegram handoffs from chat messages.
Complies with Section 6 of Phase 6 Module 6.4 Specification and AGENTS.md Constitution.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import ForensicGroup, ResidualConfidence
from src.hyperlocal_travel.models import (
    DatingPlatform,
    DatingProfileRole,
    DatingProfileMatchRecord,
    DatingMessageRecord,
    extract_chat_handoffs,
)

logger = logging.getLogger(__name__)


class DatingMatrimonialDecoder:
    """Decoder for 14 Indian and global dating and matrimonial platforms."""

    def parse_profile_record(
        self,
        profile_data: Dict[str, Any],
        source_vfs_file_id: int = 1103,
    ) -> DatingProfileMatchRecord:
        """Parses a dating profile record, detecting Passport location spoofing and unmatched status."""
        plat_val = profile_data.get("platform", DatingPlatform.TINDER)
        if isinstance(plat_val, str):
            plat_name = DatingPlatform(plat_val.upper()) if plat_val.upper() in DatingPlatform.__members__ else DatingPlatform.TINDER
        else:
            plat_name = plat_val

        native_id = str(profile_data.get("native_user_id") or profile_data.get("user_id") or profile_data.get("matrimony_id") or "UNKNOWN")
        display_name = profile_data.get("display_name") or profile_data.get("name")
        age = profile_data.get("age")
        name_age = f"{display_name}, {age}".strip(", ") if (display_name or age) else None

        # GPS & Passport Math
        actual_lat = profile_data.get("actual_lat")
        actual_lon = profile_data.get("actual_lon")
        actual_gps_json = json.dumps({"lat": actual_lat, "lon": actual_lon}) if (actual_lat is not None and actual_lon is not None) else None

        passport_city = profile_data.get("passport_city")
        passport_lat = profile_data.get("passport_lat")
        passport_lon = profile_data.get("passport_lon")

        is_passport = bool(profile_data.get("is_passport_active", False) or profile_data.get("is_traveling", False))

        disp_json = None
        if passport_city or passport_lat is not None:
            disp_json = json.dumps({"city": passport_city, "lat": passport_lat, "lon": passport_lon})
            is_passport = True

        is_recovered = bool(profile_data.get("recovered_from_wal_or_freelist", False) or profile_data.get("was_unmatched_or_deleted", False))
        role = DatingProfileRole.UNMATCHED_OR_BLOCKED_RECOVERED if is_recovered else DatingProfileRole.ACTIVE_MATCH

        matched_iso = profile_data.get("matched_iso") or profile_data.get("matched_or_crossed_utc_iso")

        return DatingProfileMatchRecord(
            platform_name=plat_name,
            app_instance_id=1,
            profile_role=role,
            native_user_or_matrimony_id=native_id,
            display_name_and_age=name_age,
            unlocked_phone_or_social_handles=profile_data.get("unlocked_phone"),
            kyc_trust_score_or_kundli_json=profile_data.get("kyc_trust_score_or_kundli_json"),
            actual_gps_or_crossing_lat_lon=actual_gps_json,
            displayed_passport_city_lat_lon=disp_json,
            is_dating_location_spoofed=1 if is_passport else 0,
            was_unmatched_or_deleted=1 if is_recovered else 0,
            cached_photo_paths_json=profile_data.get("cached_photo_paths_json"),
            matched_or_crossed_utc_iso=str(matched_iso) if matched_iso else None,
            recovery_classification=ResidualConfidence.RESIDUAL_RECORD if is_recovered else ResidualConfidence.ORIGINAL_RECORD,
            forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
        )

    def parse_chat_message(
        self,
        chat_data: Dict[str, Any],
        source_vfs_file_id: int = 1103,
    ) -> DatingMessageRecord:
        """Parses a dating chat message and automatically extracts off-platform handoff handles."""
        plat_val = chat_data.get("platform", DatingPlatform.TINDER)
        if isinstance(plat_val, str):
            plat_name = DatingPlatform(plat_val.upper()) if plat_val.upper() in DatingPlatform.__members__ else DatingPlatform.TINDER
        else:
            plat_name = plat_val

        peer_uid = int(chat_data.get("peer_uid", 1))
        direction = str(chat_data.get("direction", "INCOMING_RECEIVED"))
        msg_text = chat_data.get("message_text") or chat_data.get("message_text_or_prompt")
        handoff = extract_chat_handoffs(str(msg_text or ""))

        sent_iso = str(chat_data.get("sent_iso") or chat_data.get("sent_utc_iso") or "1970-01-01T00:00:00.000000Z")

        return DatingMessageRecord(
            platform_name=plat_name,
            dating_peer_uid=peer_uid,
            source_vfs_file_id=source_vfs_file_id,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            direction=direction,
            message_text_or_prompt=msg_text,
            media_or_shared_pin_json=chat_data.get("media_or_shared_pin_json"),
            extracted_handoff_phone_or_handle=handoff,
            sent_utc_ns=0,
            sent_utc_iso=sent_iso,
            forensic_group=ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS,
        )
