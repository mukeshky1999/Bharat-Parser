"""
Cross-Platform Conversation Hopping ('Follow the Suspect') Timeline Stitcher (Sub-Engine 9.2D).
Fuses interactions across 40+ apps into a unified chronological stream with platform-switch transition banners.
"""

import re
from typing import Any

from src.chat_reconstructor_and_redline.models import PlatformSwitchBanner


class CrossPlatformHoppingStitcher:
    """Merges cross-app events for a resolved suspect into a unified conversational timeline."""

    TOKEN_EXTRACTORS = [
        re.compile(r"\b(05[a-f0-9]{12,64})\b", re.IGNORECASE),  # Session IDs
        re.compile(r"\b[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b"),  # UPI VPAs
        re.compile(r"\b\d{12}\b"),  # 12-digit UTRs
        re.compile(r"\b[6-9]\d{9}\b"),  # Indian 10-digit mobile
    ]

    def _extract_fallback_token(self, text: str) -> str | None:
        """Attempts to extract handoff tokens from raw message text."""
        if not text:
            return None
        for pat in self.TOKEN_EXTRACTORS:
            match = pat.search(text)
            if match:
                return match.group(0)
        return None

    def _format_time_delta(self, seconds: int) -> str:
        """Formats time difference into compact human-readable string."""
        if seconds < 60:
            return f"+{seconds}s"
        elif seconds < 3600:
            mins = seconds // 60
            secs = seconds % 60
            if secs > 0:
                return f"+{mins}m {secs}s"
            return f"+{mins}m"
        else:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            if mins > 0:
                return f"+{hours}h {mins}m"
            return f"+{hours}h"

    def stitch_chronological_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[PlatformSwitchBanner]]:
        """Sorts multi-app events chronologically and generates platform-switch banners."""
        if not events:
            return [], []

        sorted_events = sorted(events, key=lambda e: int(e.get("timestamp_utc_ns", 0)))
        stitched_stream: list[dict[str, Any]] = []
        banners: list[PlatformSwitchBanner] = []

        prev_event: dict[str, Any] | None = None

        for event in sorted_events:
            curr_platform = str(event.get("platform", "Unknown"))

            if prev_event is not None:
                prev_platform = str(prev_event.get("platform", "Unknown"))
                if curr_platform != prev_platform:
                    prev_ts = int(prev_event.get("timestamp_utc_ns", 0))
                    curr_ts = int(event.get("timestamp_utc_ns", 0))
                    delta_seconds = max(0, (curr_ts - prev_ts) // 1_000_000_000)
                    fmt_delta = self._format_time_delta(delta_seconds)

                    # Look for explicit handoff token in previous event, then current event, then text
                    handoff = (
                        prev_event.get("handoff_token")
                        or self._extract_fallback_token(str(prev_event.get("text", "")))
                        or event.get("handoff_token")
                        or self._extract_fallback_token(str(event.get("text", "")))
                    )

                    banner_text = (
                        f"⚡ PLATFORM SWITCH DETECTED ({fmt_delta}): "
                        f"[{prev_platform}] ──> [{curr_platform}]"
                    )
                    if handoff:
                        banner_text += f" [Handoff: {handoff}]"

                    banner = PlatformSwitchBanner(
                        previous_platform=prev_platform,
                        current_platform=curr_platform,
                        time_delta_seconds=delta_seconds,
                        formatted_time_delta=fmt_delta,
                        rendered_banner_text=banner_text,
                        handoff_token=str(handoff) if handoff else None,
                    )
                    banners.append(banner)
                    stitched_stream.append({"is_banner": True, "banner_data": banner})

            stitched_stream.append(event)
            prev_event = event

        return stitched_stream, banners
