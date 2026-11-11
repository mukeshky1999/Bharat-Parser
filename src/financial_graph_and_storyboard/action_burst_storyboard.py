"""
5-Swimlane 60-Second Action-Burst Behavioral Storyboard (Sub-Engine 9.3C).
Plots synchronized micro-timelines across Physical, Foreground, Telecom, Financial, and Visual subsystems,
proving active human-in-the-loop execution and binding events to Pane 3 hex byte offsets.
"""

from typing import Any

from src.financial_graph_and_storyboard.models import (
    ActionBurstStoryboardView,
    StoryboardEventPill,
    SwimlaneType,
)


class ActionBurstStoryboardEngine:
    """Renders second-by-second synchronized swimlanes and detects human operation."""

    SWIMLANE_ORDER = [
        SwimlaneType.PHYSICAL_AND_BIOMETRIC_STATE,
        SwimlaneType.OS_FOREGROUND_AND_SENSOR_APPOPS,
        SwimlaneType.TELECOM_OTP_AND_RADIO_ANCHOR,
        SwimlaneType.FINANCIAL_AND_CRYPTO_EXECUTION,
        SwimlaneType.VISUAL_SCREENSHOT_AND_CHAT_HANDOFF,
    ]

    def build_storyboard_view(
        self,
        story_uid: int,
        story_title: str,
        raw_events: list[dict[str, Any]],
        idle_gap_threshold_sec: int = 120,
    ) -> ActionBurstStoryboardView:
        """Assembles 5-swimlane micro-timeline with idle-gap folding and human-in-the-loop verdict."""
        swimlanes: dict[SwimlaneType, list[StoryboardEventPill]] = {
            lane: [] for lane in self.SWIMLANE_ORDER
        }

        if not raw_events:
            return ActionBurstStoryboardView(
                story_uid=story_uid,
                story_title=story_title,
                human_in_the_loop_verdict="[Verdict Badge: NO EVENTS RECORDED]",
                swimlanes=swimlanes,
            )

        sorted_events = sorted(
            raw_events, key=lambda e: int(e.get("timestamp_utc_ns", 0))
        )
        min_ts = int(sorted_events[0].get("timestamp_utc_ns", 0))

        has_biometric_or_hand_tilt = False
        has_foreground_app = False
        has_otp_read = False
        has_financial_debit = False

        idle_gap_markers: list[dict[str, Any]] = []
        prev_ts = min_ts

        for raw in sorted_events:
            ts = int(raw.get("timestamp_utc_ns", 0))
            lane = raw.get("swimlane")
            if isinstance(lane, str):
                lane = SwimlaneType(lane)

            delta_sec = (ts - prev_ts) / 1_000_000_000.0
            if delta_sec > idle_gap_threshold_sec:
                idle_gap_markers.append(
                    {
                        "start_ts_ns": prev_ts,
                        "end_ts_ns": ts,
                        "gap_seconds": delta_sec,
                        "marker_text": f"// [{int(delta_sec // 60)}m Idle Gap Folded] //",
                    }
                )

            # Compute pixel offset (20px per second)
            rel_sec = (ts - min_ts) / 1_000_000_000.0
            x_offset = rel_sec * 20.0

            pill = StoryboardEventPill(
                event_uid=int(raw.get("event_uid", 0)),
                swimlane=lane,
                timestamp_utc_ns=ts,
                title=str(raw.get("title", "")),
                details=str(raw.get("details", "")),
                source_vfs_file_id=int(raw.get("source_vfs_file_id", 0)),
                physical_byte_offset=raw.get("physical_byte_offset"),
                x_offset_px=x_offset,
            )
            swimlanes[lane].append(pill)

            # Check indicators for human-in-the-loop execution
            if lane == SwimlaneType.PHYSICAL_AND_BIOMETRIC_STATE:
                if any(k in pill.title.lower() for k in ["biometric", "faceid", "portrait", "keyguard"]):
                    has_biometric_or_hand_tilt = True
            elif lane == SwimlaneType.OS_FOREGROUND_AND_SENSOR_APPOPS:
                if "resumed" in pill.title.lower() or "infocus" in pill.details.lower():
                    has_foreground_app = True
            elif lane == SwimlaneType.TELECOM_OTP_AND_RADIO_ANCHOR:
                if "otp" in pill.details.lower() or "sms" in pill.title.lower():
                    has_otp_read = True
            elif lane == SwimlaneType.FINANCIAL_AND_CRYPTO_EXECUTION:
                has_financial_debit = True

            prev_ts = ts

        # Determine human-in-the-loop verdict
        if has_biometric_or_hand_tilt and has_foreground_app and has_financial_debit:
            verdict = (
                "[Verdict Badge: VERIFIED HUMAN-IN-THE-LOOP EXECUTION — "
                "Defeats Remote Hack / Trojan Defense]"
            )
        elif has_financial_debit and not has_biometric_or_hand_tilt:
            verdict = (
                "[Verdict Badge: ANOMALOUS BACKGROUND EXECUTION — "
                "Consistent with Remote Trojan / Screen Overlay Drain]"
            )
        else:
            verdict = "[Verdict Badge: GENERAL BEHAVIORAL BURST DETECTED]"

        return ActionBurstStoryboardView(
            story_uid=story_uid,
            story_title=story_title,
            human_in_the_loop_verdict=verdict,
            swimlanes=swimlanes,
            idle_gap_markers=idle_gap_markers,
        )
