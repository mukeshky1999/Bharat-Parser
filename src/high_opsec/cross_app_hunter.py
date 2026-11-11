"""
Sub-Engine 5.3D: Cross-App Out-of-Band Covert Handle & Invite Link Cross-Linker.
Scans text records across foreign app databases (WhatsApp, Telegram, SMS, Notes, Clipboards)
for 05... Session IDs, SimpleX invite links, Threema links, Briar links, and Zangi numbers.
Complies with Section 2 Mistake 3, Section 6 Table 3, and Section 7.3 of Specification.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from src.high_opsec.models import (
    CovertInvitePlatform,
    CovertInviteDiscoveryRecord,
    is_valid_session_id,
    is_valid_zangi_number,
)

logger = logging.getLogger(__name__)


class CrossAppCovertHandleHunter:
    """Scanner for discovering high-opsec handles and invite links inside foreign records."""

    # Regex patterns
    SESSION_PATTERN = re.compile(r"\b([012]5[0-9a-fA-F]{62,64})\b")
    SIMPLEX_PATTERN = re.compile(r"(https?://simplex\.chat/contact#\S+|smp://\S+)")
    THREEMA_LINK_PATTERN = re.compile(r"(https?://threema\.id/[A-Za-z0-9]{8}\b|threema\.id/[A-Za-z0-9]{8}\b)")
    BRIAR_PATTERN = re.compile(r"(briar://\S+)")
    MATRIX_PATTERN = re.compile(r"(@[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})")
    ZANGI_PATTERN = re.compile(r"\b((?:10|99)-\d{4}-\d{4})\b")

    def scan_text(
        self,
        text: str,
        source_description: str = "Unknown",
        shared_timestamp_iso: Optional[str] = None,
    ) -> List[CovertInviteDiscoveryRecord]:
        """Scans a single string for high-opsec identifiers and invitation links."""
        discoveries: List[CovertInviteDiscoveryRecord] = []
        if not text or not isinstance(text, str):
            return discoveries

        # 1. Session IDs (66-hex)
        for match in self.SESSION_PATTERN.finditer(text):
            val = match.group(1)
            if is_valid_session_id(val):
                discoveries.append(
                    CovertInviteDiscoveryRecord(
                        target_opsec_platform=CovertInvitePlatform.SESSION_ID_05,
                        extracted_handle_or_uri=val,
                        found_in_source_app_and_table=source_description,
                        shared_timestamp_utc_iso=shared_timestamp_iso,
                    )
                )

        # 2. SimpleX Invitation Links
        for match in self.SIMPLEX_PATTERN.finditer(text):
            val = match.group(1)
            discoveries.append(
                CovertInviteDiscoveryRecord(
                    target_opsec_platform=CovertInvitePlatform.SIMPLEX_INVITE_URI,
                    extracted_handle_or_uri=val,
                    found_in_source_app_and_table=source_description,
                    shared_timestamp_utc_iso=shared_timestamp_iso,
                )
            )

        # 3. Threema ID Links
        for match in self.THREEMA_LINK_PATTERN.finditer(text):
            val = match.group(1)
            discoveries.append(
                CovertInviteDiscoveryRecord(
                    target_opsec_platform=CovertInvitePlatform.THREEMA_ID_LINK,
                    extracted_handle_or_uri=val,
                    found_in_source_app_and_table=source_description,
                    shared_timestamp_utc_iso=shared_timestamp_iso,
                )
            )

        # 4. Briar Links
        for match in self.BRIAR_PATTERN.finditer(text):
            val = match.group(1)
            discoveries.append(
                CovertInviteDiscoveryRecord(
                    target_opsec_platform=CovertInvitePlatform.BRIAR_LINK,
                    extracted_handle_or_uri=val,
                    found_in_source_app_and_table=source_description,
                    shared_timestamp_utc_iso=shared_timestamp_iso,
                )
            )

        # 5. Matrix IDs
        for match in self.MATRIX_PATTERN.finditer(text):
            val = match.group(1)
            discoveries.append(
                CovertInviteDiscoveryRecord(
                    target_opsec_platform=CovertInvitePlatform.MATRIX_ID,
                    extracted_handle_or_uri=val,
                    found_in_source_app_and_table=source_description,
                    shared_timestamp_utc_iso=shared_timestamp_iso,
                )
            )

        # 6. Zangi Numbers
        for match in self.ZANGI_PATTERN.finditer(text):
            val = match.group(1)
            if is_valid_zangi_number(val):
                discoveries.append(
                    CovertInviteDiscoveryRecord(
                        target_opsec_platform=CovertInvitePlatform.ZANGI_NUMBER,
                        extracted_handle_or_uri=val,
                        found_in_source_app_and_table=source_description,
                        shared_timestamp_utc_iso=shared_timestamp_iso,
                    )
                )

        return discoveries

    def scan_records(self, records: List[Dict[str, Any]]) -> List[CovertInviteDiscoveryRecord]:
        """Scans a batch of foreign records containing text, source, and timestamp."""
        all_discoveries: List[CovertInviteDiscoveryRecord] = []
        for rec in records:
            txt = rec.get("text", "")
            src = rec.get("source", "Unknown")
            ts = rec.get("timestamp")
            found = self.scan_text(txt, source_description=src, shared_timestamp_iso=ts)
            all_discoveries.extend(found)
        return all_discoveries
