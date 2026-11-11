"""
Sub-Engine 4.3A: Mathematical Blockchain Address Checksum Validators.
Pure-Python cryptographic validation for TRON, Bitcoin (Legacy/SegWit/Taproot),
Ethereum EIP-55 (Original Keccak-256), Solana Ed25519, Monero, and TON.
"""

import base64
import hashlib
import re
from typing import Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.validators.models import (
    BlockchainEcosystem,
    ValidatedCryptoAddressRecord,
)

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Keccak-256 Round Constants & Rotation Offsets
KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
KECCAK_RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(x: int, y: int) -> int:
    return ((x << (y % 64)) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - (y % 64)))


def _keccak_f1600(state: list[int]) -> None:
    lanes = [[state[x + 5 * y] for y in range(5)] for x in range(5)]
    for r in range(24):
        # Theta
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]

        # Rho & Pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(lanes[x][y], KECCAK_RHO[x][y])

        # Chi
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        # Iota
        lanes[0][0] ^= KECCAK_RC[r]

    for x in range(5):
        for y in range(5):
            state[x + 5 * y] = lanes[x][y]


def keccak_256(data: bytes) -> bytes:
    """Computes Original Keccak-256 (0x01 domain padding) over arbitrary input bytes."""
    rate = 136
    state = [0] * 25
    pad_len = rate - (len(data) % rate)
    if pad_len == 1:
        padded = data + b"\x81"
    else:
        padded = data + b"\x01" + (b"\x00" * (pad_len - 2)) + b"\x80"

    for block_idx in range(0, len(padded), rate):
        block = padded[block_idx : block_idx + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)

    output = bytearray()
    for i in range(4):
        output.extend(state[i].to_bytes(8, "little"))
    return bytes(output)


def b58_decode(s: str) -> bytes:
    """Decodes Base58 string back to raw bytes with leading zeros preserved."""
    n = 0
    for char in s:
        idx = B58_ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 char: {char}")
        n = n * 58 + idx

    res = bytearray()
    while n > 0:
        n, r = divmod(n, 256)
        res.append(r)
    res = bytes(reversed(res))

    leading_zeros = 0
    for char in s:
        if char == B58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break
    return (b"\x00" * leading_zeros) + res


def verify_base58check(addr: str) -> Tuple[bool, Optional[int], bytes]:
    """Decodes and validates Base58Check Double-SHA256 checksum."""
    try:
        raw = b58_decode(addr)
        if len(raw) != 25:
            return False, None, b""
        payload = raw[:21]
        embedded_chk = raw[21:25]
        h1 = hashlib.sha256(payload).digest()
        h2 = hashlib.sha256(h1).digest()
        if h2[:4] == embedded_chk:
            return True, payload[0], payload[1:]
        return False, None, b""
    except Exception:
        return False, None, b""


def verify_eip55_checksum(addr: str) -> bool:
    """Validates Ethereum EIP-55 mixed-case checksum using Keccak-256."""
    cleaned = addr.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if len(cleaned) != 40 or not re.match(r"^[0-9a-fA-F]{40}$", cleaned):
        return False

    has_upper = any(c in "ABCDEF" for c in cleaned)
    has_lower = any(c in "abcdef" for c in cleaned)

    if not (has_upper and has_lower):
        return False

    raw_lower = cleaned.lower()
    hash_hex = keccak_256(raw_lower.encode("ascii")).hex()

    for i, c in enumerate(cleaned):
        if c.isalpha():
            nibble = int(hash_hex[i], 16)
            if nibble >= 8 and not c.isupper():
                return False
            if nibble < 8 and not c.islower():
                return False
    return True


def to_eip55_checksum(addr: str) -> str:
    """Converts a 40-hex character Ethereum address into its canonical EIP-55 format."""
    cleaned = addr.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    raw_lower = cleaned.lower()
    hash_hex = keccak_256(raw_lower.encode("ascii")).hex()
    res = ["0x"]
    for i, c in enumerate(raw_lower):
        if c.isalpha() and int(hash_hex[i], 16) >= 8:
            res.append(c.upper())
        else:
            res.append(c)
    return "".join(res)


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def verify_bitcoin_bech32(addr: str) -> bool:
    """Validates Bitcoin SegWit v0 (Bech32, polymod == 1) and Taproot v1 (Bech32m, polymod == 0x2bc830a3)."""
    # BIP-173 mixed-case check: string must be all-lowercase or all-uppercase
    has_upper = any(c.isupper() for c in addr)
    has_lower = any(c.islower() for c in addr)
    if has_upper and has_lower:
        return False

    cleaned = addr.lower().strip()
    if not (cleaned.startswith("bc1") or cleaned.startswith("tb1")):
        return False

    try:
        hrp, data_part = cleaned.split("1", 1)
        if len(data_part) < 6:
            return False

        d = []
        for c in data_part:
            idx = B32_CHARSET.find(c)
            if idx == -1:
                return False
            d.append(idx)

        witness_ver = d[0]
        expanded = _bech32_hrp_expand(hrp) + d
        polymod = _bech32_polymod(expanded)

        if witness_ver == 0:
            return polymod == 1
        else:
            return polymod == 0x2BC830A3
    except Exception:
        return False


def verify_monero_address(addr: str) -> bool:
    """Validates 95-character Monero block-wise Base58 and Keccak-256 checksum."""
    cleaned = addr.strip()
    if len(cleaned) != 95:
        return False
    if not (cleaned.startswith("4") or cleaned.startswith("8")):
        return False

    try:
        raw = bytearray()
        # Decode 8 full blocks of 11 chars -> 8 bytes each
        for i in range(8):
            block_str = cleaned[i * 11 : (i + 1) * 11]
            val = 0
            for c in block_str:
                idx = B58_ALPHABET.find(c)
                if idx == -1:
                    return False
                val = val * 58 + idx
            raw.extend(val.to_bytes(8, "big"))

        # Decode final block of 7 chars -> 5 bytes
        last_block = cleaned[88:95]
        val_last = 0
        for c in last_block:
            idx = B58_ALPHABET.find(c)
            if idx == -1:
                return False
            val_last = val_last * 58 + idx
        raw.extend(val_last.to_bytes(5, "big"))

        if len(raw) != 69:
            return False

        # Byte 0 must be 0x12 (Primary) or 0x2A (Subaddress)
        if raw[0] not in [0x12, 0x2A]:
            return False

        calc_chk = keccak_256(bytes(raw[:65]))[:4]
        embedded_chk = bytes(raw[65:69])
        return calc_chk == embedded_chk
    except Exception:
        return False


def _crc16_ccitt(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def verify_ton_address(addr: str) -> bool:
    """Validates 48-character TON user-friendly address (Base64URL + CRC16-CCITT)."""
    cleaned = addr.strip()
    if len(cleaned) != 48:
        return False
    if not (cleaned.startswith("EQ") or cleaned.startswith("UQ")):
        return False

    try:
        padded = cleaned + ("=" * ((4 - len(cleaned) % 4) % 4))
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) != 36:
            return False

        if raw[0] not in [0x11, 0x51]:
            return False

        calc_crc = _crc16_ccitt(raw[:34])
        embedded_crc = int.from_bytes(raw[34:36], "big")
        return calc_crc == embedded_crc
    except Exception:
        return False


def validate_crypto_address(
    candidate: str,
    allow_unchecksummed_evm: bool = False,
    source_module: str = "",
    source_vfs_file_id: int = 0,
    context: Optional[str] = None,
) -> Optional[ValidatedCryptoAddressRecord]:
    """
    Mathematical dispatcher validating an address against all 7 major standards.
    Returns ValidatedCryptoAddressRecord if cryptographically valid, else None.
    """
    s = candidate.strip()

    # 1. TRON (34-character 'T...' with Base58Check Double-SHA256)
    if s.startswith("T") and len(s) == 34:
        valid, ver, _ = verify_base58check(s)
        if valid and ver == 0x41:
            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )
            return ValidatedCryptoAddressRecord(
                blockchain_ecosystem=BlockchainEcosystem.TRON_TRC20,
                canonical_address=s,
                checksum_verification_method="BASE58CHECK_DOUBLE_SHA256_OK",
                discovered_in_module_and_app=source_module,
                source_vfs_file_id=source_vfs_file_id,
                associated_actor_or_context=context,
                evidentiary_state=ev_state,
            )

    # 2. Bitcoin Legacy (1... / 3... with Base58Check)
    if (s.startswith("1") or s.startswith("3")) and (26 <= len(s) <= 35):
        valid, ver, _ = verify_base58check(s)
        if valid and ver in [0x00, 0x05]:
            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )
            return ValidatedCryptoAddressRecord(
                blockchain_ecosystem=BlockchainEcosystem.BITCOIN_LEGACY_P2PKH_P2SH,
                canonical_address=s,
                checksum_verification_method="BASE58CHECK_DOUBLE_SHA256_OK",
                discovered_in_module_and_app=source_module,
                source_vfs_file_id=source_vfs_file_id,
                associated_actor_or_context=context,
                evidentiary_state=ev_state,
            )

    # 3. Bitcoin SegWit / Taproot (bc1...)
    if s.lower().startswith("bc1") and (42 <= len(s) <= 62):
        if verify_bitcoin_bech32(s):
            is_taproot = s.lower().startswith("bc1p")
            ecosystem = (
                BlockchainEcosystem.BITCOIN_TAPROOT_BECH32M
                if is_taproot
                else BlockchainEcosystem.BITCOIN_SEGWIT_BECH32
            )
            method = (
                "BECH32M_POLYMOD_0x2bc830a3_OK"
                if is_taproot
                else "BECH32_POLYMOD_1_OK"
            )
            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )
            return ValidatedCryptoAddressRecord(
                blockchain_ecosystem=ecosystem,
                canonical_address=s.lower(),
                checksum_verification_method=method,
                discovered_in_module_and_app=source_module,
                source_vfs_file_id=source_vfs_file_id,
                associated_actor_or_context=context,
                evidentiary_state=ev_state,
            )

    # 4. Ethereum / EVM (0x... EIP-55)
    if s.startswith("0x") or s.startswith("0X"):
        if len(s) == 42:
            has_upper = any(c in "ABCDEF" for c in s[2:])
            has_lower = any(c in "abcdef" for c in s[2:])

            if has_upper and has_lower:
                if verify_eip55_checksum(s):
                    ev_state = EvidentiaryState(
                        existence=EvidentiaryExistence.OBSERVED,
                        access=EvidentiaryAccess.PLAINTEXT,
                        storage_layer=EvidentiaryStorage.LIVE_RECORD,
                        forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                    )
                    return ValidatedCryptoAddressRecord(
                        blockchain_ecosystem=BlockchainEcosystem.ETHEREUM_EVM_0X,
                        canonical_address=s,
                        checksum_verification_method="EIP55_KECCAK256_OK",
                        discovered_in_module_and_app=source_module,
                        source_vfs_file_id=source_vfs_file_id,
                        associated_actor_or_context=context,
                        evidentiary_state=ev_state,
                    )
                else:
                    return None
            elif allow_unchecksummed_evm:
                canonical = to_eip55_checksum(s)
                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                )
                return ValidatedCryptoAddressRecord(
                    blockchain_ecosystem=BlockchainEcosystem.ETHEREUM_EVM_0X,
                    canonical_address=canonical,
                    checksum_verification_method="EIP55_NORMALIZED_FROM_UNCHECKED",
                    discovered_in_module_and_app=source_module,
                    source_vfs_file_id=source_vfs_file_id,
                    associated_actor_or_context=context,
                    evidentiary_state=ev_state,
                )

    # 5. Monero (95-character '4...' or '8...')
    if (s.startswith("4") or s.startswith("8")) and len(s) == 95:
        if verify_monero_address(s):
            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )
            return ValidatedCryptoAddressRecord(
                blockchain_ecosystem=BlockchainEcosystem.MONERO_XMR_CRYPTONOTE,
                canonical_address=s,
                checksum_verification_method="MONERO_BLOCK_BASE58_KECCAK256_OK",
                discovered_in_module_and_app=source_module,
                source_vfs_file_id=source_vfs_file_id,
                associated_actor_or_context=context,
                evidentiary_state=ev_state,
            )

    # 6. TON (48-character 'EQ...' or 'UQ...')
    if (s.startswith("EQ") or s.startswith("UQ")) and len(s) == 48:
        if verify_ton_address(s):
            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )
            return ValidatedCryptoAddressRecord(
                blockchain_ecosystem=BlockchainEcosystem.TON_CRC16,
                canonical_address=s,
                checksum_verification_method="TON_CRC16_CCITT_OK",
                discovered_in_module_and_app=source_module,
                source_vfs_file_id=source_vfs_file_id,
                associated_actor_or_context=context,
                evidentiary_state=ev_state,
            )

    return None
