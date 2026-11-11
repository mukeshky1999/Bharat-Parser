"""
Sub-Engine 7.4A: Position-Constrained OCR Homoglyph Normalizer.
Repairs lookalike characters in fixed-mask Indian identity & banking formats:
- Map A (force_alpha_position): repairs digits/symbols into uppercase letters.
- Map B (force_digit_position): repairs letters/symbols into numeric digits.
Adheres strictly to AGENTS.md Forensic Invariants and Section 3.3 of Module 7.4 Specification.
"""


class PositionalHomoglyphNormalizer:
    """Repairs OCR character misclassifications according to positional format masks."""

    ALPHA_LOOKALIKES = {
        "0": "O",
        "O": "O",
        "o": "O",
        "Q": "O",
        "q": "O",
        "1": "I",
        "I": "I",
        "i": "I",
        "l": "I",
        "|": "I",
        "!": "I",
        "2": "Z",
        "z": "Z",
        "5": "S",
        "s": "S",
        "$": "S",
        "8": "B",
        "b": "B",
        "6": "G",
        "g": "G",
    }

    DIGIT_LOOKALIKES = {
        "O": "0",
        "o": "0",
        "Q": "0",
        "q": "0",
        "D": "0",
        "d": "0",
        "I": "1",
        "i": "1",
        "l": "1",
        "L": "1",
        "|": "1",
        "!": "1",
        "Z": "2",
        "z": "2",
        "S": "5",
        "s": "5",
        "$": "5",
        "B": "8",
        "b": "8",
        "G": "6",
        "g": "6",
    }

    @classmethod
    def repair_alpha_position(cls, char: str) -> str:
        """Normalizes a single character when the position strictly mandates an uppercase letter [A-Z]."""
        if char in cls.ALPHA_LOOKALIKES:
            return cls.ALPHA_LOOKALIKES[char]
        return char.upper()

    @classmethod
    def repair_digit_position(cls, char: str) -> str:
        """Normalizes a single character when the position strictly mandates a digit [0-9]."""
        if char in cls.DIGIT_LOOKALIKES:
            return cls.DIGIT_LOOKALIKES[char]
        return char

    @classmethod
    def apply_mask(cls, text: str, mask: str) -> str:
        """Applies positional mask ('A' = Alpha, 'D' = Digit) over text of matching length."""
        if len(text) != len(mask):
            return text

        repaired = []
        for ch, m in zip(text, mask):
            if m == "A":
                repaired.append(cls.repair_alpha_position(ch))
            elif m == "D":
                repaired.append(cls.repair_digit_position(ch))
            else:
                repaired.append(ch)

        return "".join(repaired)
