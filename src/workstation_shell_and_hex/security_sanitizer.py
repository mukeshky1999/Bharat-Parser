"""
Hostile Evidence Sanitizer & Anti-XSS / BiDi Spoof Defense (Sub-Engine 9.1A).
Disarms hostile scripts from seized device data and unmasks Unicode Right-to-Left Override (RLO) spoofs.
"""

import html
import re
from src.workstation_shell_and_hex.models import BiDiInspectionResult


class HostileEvidenceSanitizer:
    """Sanitizes untrusted evidence strings and flags malicious BiDi control characters."""

    # Unicode BiDi control characters used in spoofing filenames and messages
    BIDI_CONTROLS = {
        "\u202A": "U+202A (Left-to-Right Embedding [LRE])",
        "\u202B": "U+202B (Right-to-Left Embedding [RLE])",
        "\u202C": "U+202C (Pop Directional Formatting [PDF])",
        "\u202D": "U+202D (Left-to-Right Override [LRO])",
        "\u202E": "U+202E (Right-to-Left Override [RLO])",
        "\u2066": "U+2066 (Left-to-Right Isolate [LRI])",
        "\u2067": "U+2067 (Right-to-Left Isolate [RLI])",
        "\u2068": "U+2068 (First Strong Isolate [FSI])",
        "\u2069": "U+2069 (Pop Directional Isolate [PDI])",
    }

    RE_EVENT_HANDLERS = re.compile(r"on\w+\s*=", re.IGNORECASE)
    RE_SCRIPT_TAGS = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
    RE_TAGS = re.compile(r"<[^>]+>", re.IGNORECASE)

    def sanitize_text(self, text: str) -> str:
        """Disarms HTML, script, and event handler injection from untrusted extracted strings."""
        if not text:
            return ""

        # Remove script blocks first
        cleaned = self.RE_SCRIPT_TAGS.sub("", text)

        # Disarm event handlers
        cleaned = self.RE_EVENT_HANDLERS.sub("disarmed_event=", cleaned)

        # Escape standard HTML entities to ensure literal character rendering
        escaped = html.escape(cleaned, quote=True)
        return escaped

    def inspect_and_badge_string(self, text: str) -> BiDiInspectionResult:
        """Inspects string for malicious BiDi override characters and adds warning badge."""
        if not text:
            return BiDiInspectionResult(
                has_unicode_bidi_spoof=False,
                rendered_badge_string="",
                spoof_character_details="",
            )

        detected_controls = []
        for ch in text:
            if ch in self.BIDI_CONTROLS:
                detected_controls.append(self.BIDI_CONTROLS[ch])

        if detected_controls:
            details = "; ".join(set(detected_controls))
            # Strip control characters for safe visual rendering and append warning badge
            sanitized_vis = "".join(c for c in text if c not in self.BIDI_CONTROLS)
            badged = f"{sanitized_vis} [UNICODE-RLO-SPOOF]"
            return BiDiInspectionResult(
                has_unicode_bidi_spoof=True,
                rendered_badge_string=badged,
                spoof_character_details=details,
            )

        return BiDiInspectionResult(
            has_unicode_bidi_spoof=False,
            rendered_badge_string=text,
            spoof_character_details="",
        )
