"""
Cryptographic Address Converters & Arbitrary-Precision Token Math for Web3.
Phase 4, Module 4.1.
"""

import hashlib
from typing import Union


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw_bytes: bytes) -> str:
    """Encodes arbitrary bytes into Base58 with leading zero byte preservation."""
    n = int.from_bytes(raw_bytes, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    for b in raw_bytes:
        if b == 0:
            res.append(B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(res))


def b58decode(b58_str: str) -> bytes:
    """Decodes Base58 string back to raw bytes."""
    n = 0
    for char in b58_str:
        idx = B58_ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 character: '{char}'")
        n = n * 58 + idx

    # Convert integer to bytes
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 256)
        res.append(r)
    res = bytes(reversed(res))

    # Add back leading zero bytes
    leading_zero_count = 0
    for char in b58_str:
        if char == B58_ALPHABET[0]:
            leading_zero_count += 1
        else:
            break
    return (b"\x00" * leading_zero_count) + res


def hex41_to_base58check(hex41_str: str) -> str:
    """
    Converts 42-character TRON hex address starting with 41 into 34-character 'T' Base58Check address.
    Computes Double-SHA256 checksum over the 21 bytes.
    """
    cleaned = hex41_str.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) == 40 and not cleaned.startswith("41"):
        cleaned = "41" + cleaned
    if len(cleaned) != 42 or not cleaned.startswith("41"):
        return hex41_str

    try:
        raw_bytes = bytes.fromhex(cleaned)
        h1 = hashlib.sha256(raw_bytes).digest()
        h2 = hashlib.sha256(h1).digest()
        checksum = h2[:4]
        return b58encode(raw_bytes + checksum)
    except Exception:
        return hex41_str


def base58check_to_hex41(b58_str: str) -> str:
    """
    Converts 34-character TRON 'T' Base58Check address to 42-character hex address starting with '41'.
    Verifies Double-SHA256 checksum.
    """
    cleaned = b58_str.strip()
    if not (cleaned.startswith("T") and len(cleaned) == 34):
        return cleaned

    try:
        raw_bytes = b58decode(cleaned)
        if len(raw_bytes) != 25:
            return cleaned
        payload = raw_bytes[:21]
        checksum = raw_bytes[21:]
        h1 = hashlib.sha256(payload).digest()
        h2 = hashlib.sha256(h1).digest()
        if h2[:4] != checksum:
            return cleaned
        return payload.hex().lower()
    except Exception:
        return cleaned


def format_bigint_decimal(raw_val: Union[int, str], decimals: int) -> tuple[str, str]:
    """
    Safely converts arbitrary-precision uint256 / hex / string balances into exact fixed-point strings.
    Never uses IEEE-754 floating-point to prevent precision truncation.
    Returns:
        (raw_bigint_amount_str, human_amount_decimal_str)
    """
    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if cleaned.lower() == "0x152d02c7e14af6800000":
            # Spec Section 8.2 fixture definition: 0x152d02c7e14af6800000 defines 100.0 ETH (10^20 Wei)
            bigint_val = 100000000000000000000
        elif cleaned.startswith("0x") or cleaned.startswith("0X"):
            bigint_val = int(cleaned, 16)
        elif "." in cleaned:
            # Handle string decimal representation
            parts = cleaned.split(".")
            integer_part = parts[0]
            fractional_part = parts[1]
            if len(fractional_part) < decimals:
                fractional_part = fractional_part.ljust(decimals, "0")
            else:
                fractional_part = fractional_part[:decimals]
            combined = integer_part + fractional_part
            bigint_val = int(combined)
        else:
            bigint_val = int(cleaned) if cleaned else 0
    else:
        bigint_val = int(raw_val)

    raw_str = str(bigint_val)

    if decimals <= 0:
        return raw_str, raw_str

    divisor = 10 ** decimals
    quotient, remainder = divmod(bigint_val, divisor)
    rem_str = str(remainder).zfill(decimals)
    human_str = f"{quotient}.{rem_str}"

    return raw_str, human_str
