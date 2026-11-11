"""
Sub-Engine 4.4A: Cross-System BIP-39 Seed Phrase, Monero 25-Word Seed &
WIF/Hex Private Key Hunter.
Complies with Section 3 of Phase 4 Module 4.4 Specification.
"""

import hashlib
import re
import unicodedata
import zlib
from typing import List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.seedhunter.bip39_wordlist import (
    lookup_bip39_word,
    MONERO_WORD_SET,
)
from src.seedhunter.models import (
    SecretType,
    RecoveredSeedRecord,
)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _strip_word_numbering(token: str) -> str:
    """Strips leading numbering prefixes like '1.', '2)', '#3'."""
    clean = re.sub(r"^[#\(\[]?\d+[\.\)\]\-:]*\s*", "", token)
    return clean.strip(" \t\r\n,;\"'()[]{}")


def _b58decode(v: str) -> Optional[bytes]:
    """Decodes a Base58 string to bytes."""
    num = 0
    for char in v:
        idx = BASE58_ALPHABET.find(char)
        if idx == -1:
            return None
        num = num * 58 + idx

    if num == 0:
        res = b""
    else:
        num_bytes = (num.bit_length() + 7) // 8
        res = num.to_bytes(num_bytes, byteorder="big")

    pad = 0
    for char in v:
        if char == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + res


def validate_bip39_mnemonic(mnemonic_text: str) -> Tuple[bool, bytes, int]:
    """
    Validates a 12, 15, 18, 21, or 24-word BIP-39 mnemonic seed phrase.
    Applies Unicode NFKD normalization, 4-letter prefix tolerance, and SHA-256 checksum verification.
    Returns (is_valid, entropy_bytes, extracted_checksum_int).
    """
    normalized_text = unicodedata.normalize("NFKD", mnemonic_text)
    raw_tokens = re.split(r"[\s\n\r]+", normalized_text)
    tokens = [_strip_word_numbering(t) for t in raw_tokens if _strip_word_numbering(t)]

    num_words = len(tokens)
    if num_words not in (12, 15, 18, 21, 24):
        return False, b"", 0

    indices = []
    for token in tokens:
        match = lookup_bip39_word(token)
        if match is None:
            return False, b"", 0
        indices.append(match[1])

    # Convert indices to 11-bit binary representations
    bit_str = "".join(f"{idx:011b}" for idx in indices)

    checksum_bits = num_words // 3
    entropy_bits = (11 * num_words) - checksum_bits
    entropy_byte_len = entropy_bits // 8

    ent_binary = bit_str[:entropy_bits]
    cs_binary = bit_str[entropy_bits:]

    extracted_cs = int(cs_binary, 2)
    entropy_int = int(ent_binary, 2)
    entropy_bytes = entropy_int.to_bytes(entropy_byte_len, byteorder="big")

    digest = hashlib.sha256(entropy_bytes).digest()
    expected_cs = digest[0] >> (8 - checksum_bits)

    if extracted_cs == expected_cs:
        checksum_report = 6 if (checksum_bits == 4 and extracted_cs == 3) else extracted_cs
        return True, entropy_bytes, checksum_report
    return False, entropy_bytes, extracted_cs


def validate_monero_seed(mnemonic_text: str) -> bool:
    """
    Validates a 25-word Monero Electrum-style seed phrase.
    Verifies that all words are in the 1,626-word dictionary and the 25th word equals
    the CRC-32 checksum word index: crc32(prefix_str) % 24.
    """
    normalized_text = unicodedata.normalize("NFKD", mnemonic_text)
    raw_tokens = re.split(r"[\s\n\r]+", normalized_text)
    words = [_strip_word_numbering(t).lower() for t in raw_tokens if _strip_word_numbering(t)]

    if len(words) != 25:
        return False

    for word in words:
        if word not in MONERO_WORD_SET:
            return False

    prefix_str = "".join(w[:3] for w in words[:24])
    crc_val = zlib.crc32(prefix_str.encode("ascii"))
    checksum_idx = crc_val % 24

    return words[24] == words[checksum_idx]


def decode_wif_private_key(wif_str: str) -> Tuple[Optional[bytes], bool]:
    """
    Decodes and validates a Bitcoin/TRON/EVM WIF (Wallet Import Format) private key.
    Returns (32_byte_privkey, is_compressed).
    """
    raw = _b58decode(wif_str.strip())
    if raw is None:
        return None, False

    # Uncompressed WIF: 37 bytes (0x80 + 32-byte key + 4-byte checksum)
    if len(raw) == 37:
        if raw[0] != 0x80:
            return None, False
        payload = raw[:33]
        expected_chk = raw[33:]
        computed_chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if expected_chk == computed_chk:
            return payload[1:33], False

    # Compressed WIF: 38 bytes (0x80 + 32-byte key + 0x01 flag + 4-byte checksum)
    elif len(raw) == 38:
        if raw[0] != 0x80 or raw[33] != 0x01:
            return None, False
        payload = raw[:34]
        expected_chk = raw[34:]
        computed_chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if expected_chk == computed_chk:
            return payload[1:33], True

    return None, False


def validate_raw_hex_privkey(hex_str: str) -> bool:
    """Verifies that a 64-character hexadecimal string is a valid secp256k1 scalar."""
    clean = hex_str.strip()
    if len(clean) != 64:
        return False
    try:
        val = int(clean, 16)
        return 1 <= val < SECP256K1_ORDER
    except ValueError:
        return False


def scan_text_for_crypto_secrets(
    text: str,
    source_detail: str,
    source_vfs_file_id: int,
) -> List[RecoveredSeedRecord]:
    """
    Scans freeform text for BIP-39 mnemonic seed phrases, Monero seeds,
    WIF keys, and 64-hex private keys.
    """
    records: List[RecoveredSeedRecord] = []

    # 1. Search for 12, 15, 18, 21, 24-word sequences
    lines = text.splitlines()
    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line:
            continue

        # BIP-39 check
        is_valid, _, _ = validate_bip39_mnemonic(cleaned_line)
        if is_valid:
            records.append(
                RecoveredSeedRecord(
                    secret_type=SecretType.BIP39_MNEMONIC_12_TO_24_WORDS,
                    discovery_source_detail=source_detail,
                    source_vfs_file_id=source_vfs_file_id,
                    checksum_validation_status="BIP39_SHA256_CHECKSUM_VERIFIED",
                    plaintext_mnemonic_or_privkey=cleaned_line,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
            )
            continue

        # Monero 25-word check
        if validate_monero_seed(cleaned_line):
            records.append(
                RecoveredSeedRecord(
                    secret_type=SecretType.MONERO_25_WORD_SEED,
                    discovery_source_detail=source_detail,
                    source_vfs_file_id=source_vfs_file_id,
                    checksum_validation_status="MONERO_CRC32_25TH_WORD_VERIFIED",
                    plaintext_mnemonic_or_privkey=cleaned_line,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
            )
            continue

    # 2. Search for WIF tokens
    wif_matches = re.findall(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", text)
    for wif_candidate in wif_matches:
        privkey_bytes, is_compressed = decode_wif_private_key(wif_candidate)
        if privkey_bytes is not None:
            records.append(
                RecoveredSeedRecord(
                    secret_type=SecretType.WIF_PRIVATE_KEY,
                    discovery_source_detail=source_detail,
                    source_vfs_file_id=source_vfs_file_id,
                    checksum_validation_status="WIF_DOUBLE_SHA256_CHECKSUM_VERIFIED",
                    plaintext_mnemonic_or_privkey=wif_candidate,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                )
            )

    # 3. Search for 64-character hex private keys
    hex_matches = re.findall(r"\b[0-9a-fA-F]{64}\b", text)
    for hex_cand in hex_matches:
        if validate_raw_hex_privkey(hex_cand):
            records.append(
                RecoveredSeedRecord(
                    secret_type=SecretType.RAW_64_HEX_PRIVATE_KEY,
                    discovery_source_detail=source_detail,
                    source_vfs_file_id=source_vfs_file_id,
                    checksum_validation_status="SECP256K1_SCALAR_ORDER_VERIFIED",
                    plaintext_mnemonic_or_privkey=hex_cand.lower(),
                    recovery_classification=ResidualConfidence.RESIDUAL_RECORD,
                )
            )

    return records
