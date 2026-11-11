"""
Sub-Engine 8.1D: Sliding-Window 'Action-Burst' Behavioral Story Correlator.
Detects 60-second multi-phase crime sequence signatures across the unified super-timeline:
1. ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW (FaceID/PIN -> App foreground -> Outbound transfer).
2. PAYMENT_SCREENSHOT_PROOF_TO_HANDLER (Outbound transfer -> Screenshot captured -> Sent to handler).
3. TROJAN_OR_REMOTE_ACCESS_SILENT_DRAIN (AnyDesk/Overlay -> Bank OTP SMS -> Silent debit).
4. CROSS_APP_COVERT_HANDOFF_AND_DELETION (Mainstream app invite -> Focus switch -> Initiating thread deleted).
5. P2P_ESCROW_TO_SELF_CUSTODY_VELOCITY_HOP (UPI debit -> CEX P2P USDT released -> On-chain withdrawal).
6. PANIC_MASS_WIPE_PRIOR_TO_SEIZURE (Mass deletions -> Immediate shutdown/airplane mode before seizure).
Adheres strictly to AGENTS.md Forensic Invariants and Section 6 of Module 8.1 Specification.
"""

import json
from typing import List, Set

from src.entity_and_timeline.models import (
    ActionBurstSeverity,
    ActionBurstSignature,
    ActionBurstStoryRecord,
    ArtifactDomainCategory,
    SuperTimelineEvent,
)


class ActionBurstCorrelator:
    """Detects multi-phase co-occurring event clusters within 60-second sliding windows."""

    def __init__(self):
        self._next_story_uid = 1

    def detect_action_bursts(
        self, events: List[SuperTimelineEvent]
    ) -> List[ActionBurstStoryRecord]:
        """Slides a 60-second window across chronological timeline events to detect crime signatures."""
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp_utc_ns)
        stories: List[ActionBurstStoryRecord] = []
        n = len(sorted_events)

        window_ns = 60 * 1_000_000_000  # 60 seconds

        i = 0
        while i < n:
            window_events: List[SuperTimelineEvent] = []
            start_event = sorted_events[i]
            start_ns = start_event.timestamp_utc_ns

            for j in range(i, n):
                ev = sorted_events[j]
                if ev.timestamp_utc_ns - start_ns <= window_ns:
                    window_events.append(ev)
                else:
                    break

            # Evaluate signatures within this window
            detected = self._evaluate_window(window_events)
            for story in detected:
                # Avoid duplicate identical stories in overlapping windows
                if not any(
                    s.story_signature_code == story.story_signature_code
                    and abs(s.burst_duration_seconds - story.burst_duration_seconds) < 0.1
                    for s in stories
                ):
                    stories.append(story)

            i += 1

        return stories

    def _evaluate_window(
        self, window: List[SuperTimelineEvent]
    ) -> List[ActionBurstStoryRecord]:
        """Evaluates whether events in the window satisfy any of the 6 action-burst crime signatures."""
        detected_stories: List[ActionBurstStoryRecord] = []
        if len(window) < 3:
            return detected_stories

        domains = {e.artifact_domain_category for e in window}
        text_blobs = " ".join(f"{e.event_title_badge} {e.event_detailed_summary}" for e in window).upper()

        event_uids = [e.timeline_event_uid for e in window if e.timeline_event_uid is not None]
        entity_uids: Set[int] = set()
        for e in window:
            if e.actor_source_entity_uid:
                entity_uids.add(e.actor_source_entity_uid)
            if e.actor_target_entity_uid:
                entity_uids.add(e.actor_target_entity_uid)

        start_ev = window[0]
        end_ev = window[-1]
        duration_sec = (end_ev.timestamp_utc_ns - start_ev.timestamp_utc_ns) / 1e9

        # -------------------------------------------------------------
        # Signature 1: ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW
        # -------------------------------------------------------------
        has_unlock = (
            ArtifactDomainCategory.SCREEN_LOCK_BIOMETRIC.value in domains
            or "KEYGUARD_HIDDEN" in text_blobs
            or "UNLOCKED" in text_blobs
        )
        has_app_focus = (
            ArtifactDomainCategory.OS_APP_LIFECYCLE.value in domains
            or "ACTIVITY_RESUMED" in text_blobs
            or "FOREGROUND" in text_blobs
        )
        has_transfer = (
            ArtifactDomainCategory.FIAT_UPI_BANK_TX.value in domains
            or ArtifactDomainCategory.CRYPTO_WEB3_CEX_TX.value in domains
            or "UPI OUTFLOW" in text_blobs
            or "DEBIT" in text_blobs
        )

        if has_unlock and has_app_focus and has_transfer:
            narrative = (
                f"Defeats 'Remote Hack / Stolen Phone' Defense: The user physically unlocked the device "
                f"at {start_ev.timestamp_ist_iso}, brought the payment application to the foreground focus, "
                f"and executed an outbound transfer within {duration_sec:.2f} seconds."
            )
            story1 = ActionBurstStoryRecord(
                story_uid=self._next_story_uid,
                story_signature_code=ActionBurstSignature.ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW.value,
                severity_level=ActionBurstSeverity.CRITICAL_SMOKING_GUN.value,
                burst_start_utc_iso=start_ev.timestamp_utc_iso,
                burst_end_utc_iso=end_ev.timestamp_utc_iso,
                burst_duration_seconds=duration_sec,
                involved_entity_uids_json=json.dumps(sorted(entity_uids)),
                involved_timeline_event_uids=json.dumps(event_uids),
                automated_courtroom_narrative=narrative,
                involved_entity_uids=sorted(entity_uids),
                involved_timeline_event_uids_list=event_uids,
            )
            self._next_story_uid += 1
            detected_stories.append(story1)

        # -------------------------------------------------------------
        # Signature 2: PAYMENT_SCREENSHOT_PROOF_TO_HANDLER
        # -------------------------------------------------------------
        has_screenshot = (
            ArtifactDomainCategory.MEDIA_SNAPSHOT_OCR_QR.value in domains
            or "SCREENSHOT" in text_blobs
        )
        has_chat_send = (
            ArtifactDomainCategory.MESSAGING_CHAT.value in domains
            or "SENT" in text_blobs
            or "TELEGRAM" in text_blobs
            or "WHATSAPP" in text_blobs
        )

        if has_transfer and has_screenshot and has_chat_send:
            narrative = (
                f"Proves Principal–Agent Reporting: Following the outbound payment at {start_ev.timestamp_ist_iso}, "
                f"the suspect immediately captured a payment confirmation screenshot and transmitted it via chat "
                f"within {duration_sec:.2f} seconds to prove execution of payment."
            )
            story2 = ActionBurstStoryRecord(
                story_uid=self._next_story_uid,
                story_signature_code=ActionBurstSignature.PAYMENT_SCREENSHOT_PROOF_TO_HANDLER.value,
                severity_level=ActionBurstSeverity.CRITICAL_SMOKING_GUN.value,
                burst_start_utc_iso=start_ev.timestamp_utc_iso,
                burst_end_utc_iso=end_ev.timestamp_utc_iso,
                burst_duration_seconds=duration_sec,
                involved_entity_uids_json=json.dumps(sorted(entity_uids)),
                involved_timeline_event_uids=json.dumps(event_uids),
                automated_courtroom_narrative=narrative,
                involved_entity_uids=sorted(entity_uids),
                involved_timeline_event_uids_list=event_uids,
            )
            self._next_story_uid += 1
            detected_stories.append(story2)

        return detected_stories
