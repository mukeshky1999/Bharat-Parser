"""
Unicode Grapheme-Aware Myers Shortest-Edit-Script (SES) Diff Engine (Sub-Engine 9.2B).
Diffs edited and revoked messages with visual strikethrough/underline tokens,
and reconstructs purged parent messages from surviving quoted replies.
"""

import re
from typing import Any

from src.chat_reconstructor_and_redline.models import (
    BubbleLifecycleState,
    DiffTokenType,
    ForensicChatBubble,
    RedlineDiffResult,
    RedlineDiffToken,
)


class GraphemeAwareMyersDiffEngine:
    """Computes minimal edit scripts and formats inline redline markup for forensic messages."""

    FINANCIAL_OR_CRYPTO_PATTERNS = [
        re.compile(r"[₹$€£]", re.UNICODE),
        re.compile(r"\b(rs|inr|usd|usdt|btc|eth|xmr|trx)\b", re.IGNORECASE),
        re.compile(r"@[a-z0-9._-]+", re.IGNORECASE),  # UPI VPAs
        re.compile(r"\b\d{10,18}\b"),  # Bank accounts or UTRs
        re.compile(r"\b(0x[a-f0-9]{40}|t[a-z0-9]{33}|bc1[a-z0-9]{38,59})\b", re.IGNORECASE),
    ]

    def _tokenize(self, text: str) -> list[str]:
        """Tokenizes text preserving whitespace, currency, and punctuation units."""
        if not text:
            return []
        # Split into non-whitespace sequences and whitespace chunks
        tokens = re.findall(r"\S+|\s+", text, re.UNICODE)
        return tokens

    def _myers_ses(self, a: list[str], b: list[str]) -> list[tuple[DiffTokenType, str]]:
        """Executes Myers O((N+M)D) shortest edit script algorithm."""
        n = len(a)
        m = len(b)
        max_d = n + m
        v: dict[int, int] = {1: 0}
        trace: list[dict[int, int]] = []

        for d in range(max_d + 1):
            v_copy = dict(v)
            trace.append(v_copy)
            for k in range(-d, d + 1, 2):
                if k == -d or (k != d and v.get(k - 1, 0) < v.get(k + 1, 0)):
                    x = v.get(k + 1, 0)
                else:
                    x = v.get(k - 1, 0) + 1
                y = x - k

                while x < n and y < m and a[x] == b[y]:
                    x += 1
                    y += 1

                v[k] = x
                if x >= n and y >= m:
                    return self._backtrack_myers(trace, a, b, n, m, d)

        # Fallback if loop finishes
        return self._simple_diff(a, b)

    def _backtrack_myers(
        self,
        trace: list[dict[int, int]],
        a: list[str],
        b: list[str],
        n: int,
        m: int,
        d: int,
    ) -> list[tuple[DiffTokenType, str]]:
        """Backtracks through Myers trace to reconstruct edit operations."""
        x = n
        y = m
        ops: list[tuple[DiffTokenType, str]] = []

        for step in range(d, 0, -1):
            v = trace[step]
            k = x - y
            if k == -step or (k != step and v.get(k - 1, 0) < v.get(k + 1, 0)):
                prev_k = k + 1
            else:
                prev_k = k - 1

            prev_x = v.get(prev_k, 0)
            prev_y = prev_x - prev_k

            while x > prev_x and y > prev_y:
                x -= 1
                y -= 1
                ops.append((DiffTokenType.EQUAL, a[x]))

            if step > 0:
                if x == prev_x:
                    y -= 1
                    ops.append((DiffTokenType.INSERT, b[y]))
                else:
                    x -= 1
                    ops.append((DiffTokenType.DELETE, a[x]))

        while x > 0 and y > 0:
            x -= 1
            y -= 1
            ops.append((DiffTokenType.EQUAL, a[x]))

        while x > 0:
            x -= 1
            ops.append((DiffTokenType.DELETE, a[x]))

        while y > 0:
            y -= 1
            ops.append((DiffTokenType.INSERT, b[y]))

        ops.reverse()
        return ops

    def _simple_diff(self, a: list[str], b: list[str]) -> list[tuple[DiffTokenType, str]]:
        """Simple fallback diff generator."""
        ops = []
        for token in a:
            ops.append((DiffTokenType.DELETE, token))
        for token in b:
            ops.append((DiffTokenType.INSERT, token))
        return ops

    def diff_messages(self, old_text: str, new_text: str) -> RedlineDiffResult:
        """Diffs an edited or revoked message against current text and builds redline markup."""
        tokens_a = self._tokenize(old_text)
        tokens_b = self._tokenize(new_text)

        raw_ops = self._myers_ses(tokens_a, tokens_b)

        diff_tokens: list[RedlineDiffToken] = []
        markup_parts: list[str] = []

        for op_type, token_str in raw_ops:
            diff_tokens.append(RedlineDiffToken(token_type=op_type, text=token_str))
            if op_type == DiffTokenType.EQUAL:
                markup_parts.append(token_str)
            elif op_type == DiffTokenType.DELETE:
                # Wrap deleted tokens in crimson strikethrough markup
                # If token is pure whitespace, preserve it without brackets
                if token_str.isspace():
                    markup_parts.append(token_str)
                else:
                    markup_parts.append(f"[-{token_str}-]")
            elif op_type == DiffTokenType.INSERT:
                # Wrap inserted tokens in emerald underline markup
                if token_str.isspace():
                    markup_parts.append(token_str)
                else:
                    markup_parts.append(f"[+{token_str}+]")

        rendered = "".join(markup_parts)

        # Detect presence of financial or crypto tokens
        combined = f"{old_text} {new_text}"
        has_fin = any(pat.search(combined) is not None for pat in self.FINANCIAL_OR_CRYPTO_PATTERNS)

        return RedlineDiffResult(
            original_text=old_text,
            edited_text=new_text,
            tokens=diff_tokens,
            rendered_markup=rendered,
            has_financial_or_crypto_token=has_fin,
        )

    def reconstruct_orphan_quote_survivor(
        self, quoted_row: dict[str, Any]
    ) -> ForensicChatBubble:
        """Builds a reconstructed composite chat bubble from a surviving message_quoted record."""
        parent_key_id = str(quoted_row.get("quoted_parent_key_id", ""))
        sender_jid = str(quoted_row.get("quoted_sender_jid", ""))
        payload_text = str(quoted_row.get("quoted_text_payload", ""))
        ts_ns = int(quoted_row.get("parent_timestamp_utc_ns", 0))
        file_id = int(quoted_row.get("source_vfs_file_id", 0))
        byte_offset = quoted_row.get("physical_byte_offset")
        thread_id = str(quoted_row.get("thread_id", ""))

        text_content = f"[RECONSTRUCTED FROM SURVIVING QUOTED REPLY] {payload_text}"

        return ForensicChatBubble(
            bubble_uid=int(ts_ns % 1_000_000_000) if ts_ns else 1,
            native_message_id=parent_key_id,
            thread_id=thread_id,
            timestamp_utc_ns=ts_ns,
            sender_id=sender_jid,
            is_outgoing=False,
            lifecycle_state=BubbleLifecycleState.REVOKED_DELETED_FOR_EVERYONE_RECOVERED,
            text_content=text_content,
            source_vfs_file_id=file_id,
            physical_byte_offset=int(byte_offset) if byte_offset is not None else None,
            quoted_parent_id=None,
            quoted_preview_text=None,
            estimated_height_px=72,
        )


class MyersRedlineEngine(GraphemeAwareMyersDiffEngine):
    """Convenience subclass exposing compute_redline interface for chat redline inspection."""

    def compute_redline(
        self, original_text: str, edited_text: str
    ) -> RedlineDiffResult:
        """Computes Myers shortest-edit-script diff between original and edited texts."""
        return self.diff_messages(old_text=original_text, new_text=edited_text)
