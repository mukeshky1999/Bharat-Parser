"""
Bilingual Hindi (Devanagari) + English (hin+eng) OCR Engine & Indic Normalizer.
Provides 3-tier OCR execution pipeline, Indic numeral normalization, and forensic entity classification.
"""

from dataclasses import dataclass, field
import io
import os
import re
import shutil
import subprocess
from typing import Any, Optional
import zlib

from src.correlator.utr_validator import NPCIUTRJulianAndVerhoeffValidator
from src.seedhunter.seed_hunter import validate_bip39_mnemonic


@dataclass
class BilingualOcrResult:
    """Consolidated result from bilingual Hindi + English OCR analysis."""

    engine_used: str
    raw_bilingual_text: str
    normalized_ascii_text: str
    detected_scripts: list[str] = field(default_factory=list)
    document_category: str = "GENERAL_TEXT"
    extracted_utrs: list[str] = field(default_factory=list)
    extracted_pans: list[str] = field(default_factory=list)
    extracted_ifscs: list[str] = field(default_factory=list)
    extracted_amounts_inr: list[float] = field(default_factory=list)
    uidai_verhoeff_valid: bool = False
    bip39_seed_detected: bool = False
    confidence_score: float = 0.0


DEVANAGARI_TO_ASCII_DIGITS = {
    "०": "0",
    "१": "1",
    "२": "2",
    "३": "3",
    "४": "4",
    "५": "5",
    "६": "6",
    "७": "7",
    "८": "8",
    "९": "9",
}

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff"]


def normalize_indic_text(text: str) -> str:
    """
    Normalizes Indic/Devanagari text by converting Devanagari numerals to ASCII digits,
    stripping zero-width formatting characters, and normalizing whitespace.
    """
    if not text:
        return ""

    cleaned = text
    for zw in ZERO_WIDTH_CHARS:
        cleaned = cleaned.replace(zw, "")

    for dev_char, asc_char in DEVANAGARI_TO_ASCII_DIGITS.items():
        cleaned = cleaned.replace(dev_char, asc_char)

    # Normalize whitespace
    cleaned = re.sub(r"[ \t\r\f\v]+", " ", cleaned)
    return cleaned.strip()


def detect_scripts_in_text(text: str) -> list[str]:
    """Detects scripts present in the text (Devanagari and Latin)."""
    scripts: list[str] = []
    has_devanagari = any("\u0900" <= ch <= "\u097f" for ch in text)
    has_latin = any(("A" <= ch <= "Z") or ("a" <= ch <= "z") for ch in text)

    if has_devanagari:
        scripts.append("DEVANAGARI")
    if has_latin:
        scripts.append("LATIN")
    return scripts


class BilingualOcrEngine:
    """
    3-tier bilingual OCR execution engine:
    Tier 1: Native Tesseract hin+eng binary execution.
    Tier 2: Pure-Python container and embedded UTF-8 metadata/stream scanner.
    Tier 3: Rule-based forensic classification and entity extraction.
    """

    def __init__(self, tessdata_dir: Optional[str] = None):
        self.tessdata_dir = tessdata_dir or os.environ.get("TESSDATA_PREFIX", "")
        self.verhoeff_validator = NPCIUTRJulianAndVerhoeffValidator()

    def _find_tesseract_binary(self) -> Optional[str]:
        """Locates tesseract executable on system path or standard Windows install roots."""
        bin_path = shutil.which("tesseract")
        if bin_path:
            return bin_path

        common_win_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]
        for p in common_win_paths:
            if os.path.exists(p):
                return p
        return None

    def extract_from_bytes(
        self, image_or_text_bytes: bytes, lang: str = "hin+eng"
    ) -> BilingualOcrResult:
        """
        Extracts bilingual Hindi + English text from image bytes or text stream,
        falling back gracefully to pure-Python container and stream parsing.
        """
        raw_text = ""
        engine_used = "PURE_PYTHON_STREAM_SCANNER"

        tesseract_bin = self._find_tesseract_binary()
        if tesseract_bin and len(image_or_text_bytes) > 16:
            # Check for raster image headers
            is_raster = (
                image_or_text_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                or image_or_text_bytes.startswith(b"\xff\xd8")
                or image_or_text_bytes.startswith(b"BM")
                or image_or_text_bytes.startswith(b"RIFF")
            )
            if is_raster:
                try:
                    cmd = [tesseract_bin, "stdin", "stdout", "-l", lang, "--oem", "1", "--psm", "6"]
                    env = os.environ.copy()
                    if self.tessdata_dir:
                        env["TESSDATA_PREFIX"] = self.tessdata_dir
                    proc = subprocess.run(
                        cmd,
                        input=image_or_text_bytes,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                        env=env,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        raw_text = proc.stdout.decode("utf-8", errors="replace").strip()
                        engine_used = "TESSERACT_HIN_ENG"
                except Exception:
                    # Fallback to pure python scanner
                    raw_text = ""

        if not raw_text:
            raw_text = self._parse_pure_python_streams(image_or_text_bytes)
            engine_used = "PURE_PYTHON_STREAM_SCANNER"

        return self.extract_from_text(raw_text, engine_used=engine_used)

    def _parse_pure_python_streams(self, raw_bytes: bytes) -> str:
        """Extracts text chunks from PNG iTXt/tEXt/zTXt, JPEG markers, or direct UTF-8 streams."""
        extracted_chunks: list[str] = []

        # Check PNG chunks
        if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            offset = 8
            byte_len = len(raw_bytes)
            while offset + 8 <= byte_len:
                chunk_len = int.from_bytes(raw_bytes[offset : offset + 4], "big")
                chunk_type = raw_bytes[offset + 4 : offset + 8]
                data_start = offset + 8
                data_end = data_start + chunk_len
                if data_end > byte_len:
                    break

                chunk_data = raw_bytes[data_start:data_end]
                if chunk_type == b"tEXt":
                    parts = chunk_data.split(b"\x00", 1)
                    if len(parts) == 2:
                        extracted_chunks.append(parts[1].decode("utf-8", errors="replace"))
                elif chunk_type == b"iTXt":
                    # iTXt format: keyword \0 comp_flag comp_method lang_tag \0 trans_key \0 text
                    parts = chunk_data.split(b"\x00", 3)
                    if len(parts) >= 4:
                        tail = parts[3]
                        if len(tail) >= 1:
                            comp_flag = tail[0] if isinstance(tail[0], int) else ord(tail[0])
                            text_bytes = tail[1:]
                            if comp_flag == 1:
                                try:
                                    decomp = zlib.decompress(text_bytes)
                                    extracted_chunks.append(decomp.decode("utf-8", errors="replace"))
                                except Exception:
                                    extracted_chunks.append(text_bytes.decode("utf-8", errors="replace"))
                            else:
                                extracted_chunks.append(text_bytes.decode("utf-8", errors="replace"))
                elif chunk_type == b"zTXt":
                    parts = chunk_data.split(b"\x00", 1)
                    if len(parts) == 2 and len(parts[1]) > 1:
                        try:
                            decomp = zlib.decompress(parts[1][1:])
                            extracted_chunks.append(decomp.decode("utf-8", errors="replace"))
                        except Exception:
                            decomp = b""
                offset = data_end + 4  # Skip CRC

        # Check JPEG COM marker (0xFFFE)
        if raw_bytes.startswith(b"\xff\xd8"):
            offset = 2
            byte_len = len(raw_bytes)
            while offset + 4 <= byte_len:
                if raw_bytes[offset] == 0xFF:
                    marker = raw_bytes[offset + 1]
                    if marker in (0xDA, 0xD9):  # SOS or EOI
                        break
                    seg_len = int.from_bytes(raw_bytes[offset + 2 : offset + 4], "big")
                    if seg_len < 2 or offset + 2 + seg_len > byte_len:
                        break
                    if marker == 0xFE:  # COM segment
                        com_data = raw_bytes[offset + 4 : offset + 2 + seg_len]
                        extracted_chunks.append(com_data.decode("utf-8", errors="replace"))
                    offset += 2 + seg_len
                else:
                    offset += 1

        if extracted_chunks:
            return "\n".join(extracted_chunks)

        # Attempt direct UTF-8 / UTF-16LE decoding
        try:
            decoded = raw_bytes.decode("utf-8")
            if any(ord(c) > 31 for c in decoded):
                return decoded
        except Exception:
            decoded = ""

        try:
            decoded16 = raw_bytes.decode("utf-16le")
            if any(ord(c) > 31 for c in decoded16):
                return decoded16
        except Exception:
            decoded16 = ""

        return ""

    def extract_from_text(
        self, text: str, engine_used: str = "PURE_PYTHON_STREAM_SCANNER"
    ) -> BilingualOcrResult:
        """
        Parses raw text, normalizes Devanagari numerals to ASCII, extracts financial
        and identity entities, and performs forensic classification.
        """
        raw_text = text or ""
        normalized = normalize_indic_text(raw_text)
        scripts = detect_scripts_in_text(raw_text)

        # Entity extraction
        extracted_utrs: list[str] = []
        extracted_pans: list[str] = []
        extracted_ifscs: list[str] = []
        extracted_amounts: list[float] = []
        is_verhoeff_valid = False
        is_bip39 = False

        # 1. PAN Extraction: [A-Z]{5}[0-9]{4}[A-Z]
        pan_matches = re.findall(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", normalized)
        for p in pan_matches:
            if p not in extracted_pans:
                extracted_pans.append(p)

        # 2. IFSC Extraction: [A-Z]{4}0[A-Z0-9]{6}
        ifsc_matches = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", normalized)
        for ifsc in ifsc_matches:
            if ifsc not in extracted_ifscs:
                extracted_ifscs.append(ifsc)

        has_pan_keywords = any(
            kw in raw_text or kw in normalized
            for kw in [
                "आयकर विभाग",
                "INCOME TAX DEPARTMENT",
                "स्थायी खाता संख्या",
                "Permanent Account Number",
            ]
        )

        # 3. 12-Digit Numbers: Disambiguate UTR vs Aadhaar
        candidate_12d = re.findall(r"\b\d{12}\b", normalized)
        has_uidai_keywords = any(
            kw in raw_text or kw in normalized
            for kw in [
                "मेरा आधार",
                "मेरी पहचान",
                "आधार",
                "Unique Identification",
                "UIDAI",
            ]
        )
        has_upi_keywords = any(
            kw in raw_text or kw in normalized
            for kw in [
                "भुगतान सफल",
                "यूपीआई",
                "खाता संख्या",
                "भारतीय स्टेट बैंक",
                "ट्रांसफर",
                "संदर्भ",
                "Payment Successful",
                "Paid to",
                "UPI Ref",
                "UTR",
                "Debited from",
            ]
        )

        for num in candidate_12d:
            if self.verhoeff_validator.validate_verhoeff(num) and (has_uidai_keywords or not has_upi_keywords):
                is_verhoeff_valid = True
            else:
                if num not in extracted_utrs:
                    extracted_utrs.append(num)

        # 4. Amount Extraction
        amount_patterns = [
            r"(?:₹|Rs\.?|INR|रु\.?|रुपये)\s*([\d,]+(?:\.\d{1,2})?)",
            r"([\d,]+(?:\.\d{1,2})?)\s*(?:₹|Rs\.?|INR|रु\.?|रुपये)",
        ]
        for pat in amount_patterns:
            matches = re.findall(pat, normalized, re.IGNORECASE)
            for m in matches:
                clean_num_str = m.replace(",", "")
                try:
                    val = float(clean_num_str)
                    if val not in extracted_amounts:
                        extracted_amounts.append(val)
                except ValueError:
                    continue

        # 5. BIP-39 Seed validation
        is_seed, _, _ = validate_bip39_mnemonic(normalized)
        if is_seed:
            is_bip39 = True

        # Document Classification
        category = "GENERAL_TEXT"
        confidence = 0.50

        if is_bip39:
            category = "CRYPTO_SEED_PHRASE"
            confidence = 0.98
        elif extracted_pans or has_pan_keywords:
            category = "INCOME_TAX_PAN"
            confidence = 0.95 if extracted_pans else 0.85
        elif has_uidai_keywords or is_verhoeff_valid:
            category = "UIDAI_IDENTITY_CARD"
            confidence = 0.95 if is_verhoeff_valid else 0.85
        elif has_upi_keywords or extracted_utrs:
            category = "UPI_BANK_RECEIPT"
            confidence = 0.92 if (extracted_utrs and extracted_amounts) else 0.82
        elif any(kw in raw_text or kw in normalized for kw in ["निर्वाचन आयोग", "मतदाता फोटो पहचान पत्र", "Election Commission of India", "Voter ID", "EPIC"]):
            category = "VOTER_ID_EPIC"
            confidence = 0.90
        elif any(kw in raw_text or kw in normalized for kw in ["ड्राइविंग लाइसेंस", "Driving Licence", "Transport Department"]):
            category = "DRIVING_LICENCE"
            confidence = 0.90
        elif raw_text:
            confidence = 0.60

        return BilingualOcrResult(
            engine_used=engine_used,
            raw_bilingual_text=raw_text,
            normalized_ascii_text=normalized,
            detected_scripts=scripts,
            document_category=category,
            extracted_utrs=extracted_utrs,
            extracted_pans=extracted_pans,
            extracted_ifscs=extracted_ifscs,
            extracted_amounts_inr=extracted_amounts,
            uidai_verhoeff_valid=is_verhoeff_valid,
            bip39_seed_detected=is_bip39,
            confidence_score=confidence,
        )
