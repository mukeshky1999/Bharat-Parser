"""
Sub-Engine 4.4B: Offline BIP-32 / BIP-44 / BIP-84 / SLIP-0010 Hierarchical Deterministic
(HD) Public Address Derivation Engine.
Complies with Section 4 of Phase 4 Module 4.4 Specification.
"""

import hashlib
import hmac
import logging
import unicodedata
from typing import List, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from src.seedhunter.models import (
    BlockchainNetwork,
    HDDerivedAddressRecord,
)
from src.validators.address_validators import keccak_256

logger = logging.getLogger(__name__)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _b58encode(b: bytes) -> str:
    """Encodes bytes to a Base58 string preserving leading zero bytes."""
    num = int.from_bytes(b, byteorder="big")
    res = []
    while num > 0:
        num, rem = divmod(num, 58)
        res.append(BASE58_ALPHABET[rem])

    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return (BASE58_ALPHABET[0] * pad) + "".join(reversed(res))


def _bech32_polymod(values: List[int]) -> int:
    """Internal Bech32 polynomial checksum generator."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    """Expands human-readable part into values for Bech32 checksum."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Computes Bech32 checksum for given HRP and 5-bit data payload."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> List[int]:
    """Converts bit arrays between 8-bit and 5-bit representations."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def derive_master_seed_bip39(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derives 64-byte binary master seed from mnemonic and optional passphrase
    using PBKDF2-HMAC-SHA512 with 2048 iterations.
    """
    # BIP-39 requires NFKD normalisation of both strings; without it a non-ASCII passphrase gives a different seed.
    mnemonic = unicodedata.normalize("NFKD", mnemonic)
    passphrase = unicodedata.normalize("NFKD", passphrase)
    salt = b"mnemonic" + passphrase.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, 64)


def _derive_bip32_child_secp256k1(
    parent_key: bytes, parent_chain: bytes, index: int
) -> Tuple[bytes, bytes]:
    """Derives a BIP-32 child private key and chain code over secp256k1."""
    if index >= 0x80000000:
        data = b"\x00" + parent_key + index.to_bytes(4, byteorder="big")
    else:
        priv = ec.derive_private_key(
            int.from_bytes(parent_key, byteorder="big"), ec.SECP256K1(), default_backend()
        )
        pn = priv.public_key().public_numbers()
        prefix = b"\x02" if pn.y % 2 == 0 else b"\x03"
        compressed_pub = prefix + pn.x.to_bytes(32, byteorder="big")
        data = compressed_pub + index.to_bytes(4, byteorder="big")

    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    I_L = I[:32]
    I_R = I[32:]

    child_k_int = (
        int.from_bytes(I_L, byteorder="big")
        + int.from_bytes(parent_key, byteorder="big")
    ) % SECP256K1_ORDER
    child_key = child_k_int.to_bytes(32, byteorder="big")
    return child_key, I_R


def _derive_slip0010_child_ed25519(
    parent_key: bytes, parent_chain: bytes, index: int
) -> Tuple[bytes, bytes]:
    """Derives a SLIP-0010 hardened child private key and chain code over Ed25519."""
    data = b"\x00" + parent_key + index.to_bytes(4, byteorder="big")
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    return I[:32], I[32:]


def _parse_path(path_str: str) -> List[int]:
    """Parses a derivation path string like \"m/44'/60'/0'/0/0\" into integer indices."""
    parts = path_str.strip().split("/")
    indices = []
    for part in parts:
        part = part.strip()
        if not part or part == "m":
            continue
        if part.endswith("'") or part.endswith("h"):
            indices.append(int(part[:-1]) + 0x80000000)
        else:
            indices.append(int(part))
    return indices


def derive_hd_address(
    seed_bytes: bytes, network: BlockchainNetwork, path_str: str
) -> str:
    """
    Derives the public address for a specified network and derivation path from a 64-byte seed.
    """
    indices = _parse_path(path_str)

    if network == BlockchainNetwork.SOLANA_SLIP0010:
        # SLIP-0010 Ed25519 derivation
        I = hmac.new(b"ed25519 seed", seed_bytes, hashlib.sha512).digest()
        k, c = I[:32], I[32:]
        for idx in indices:
            k, c = _derive_slip0010_child_ed25519(k, c, idx)

        priv_ed = ed25519.Ed25519PrivateKey.from_private_bytes(k)
        pub_raw = priv_ed.public_key().public_bytes_raw()
        return _b58encode(pub_raw)

    # secp256k1 derivation
    I = hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for idx in indices:
        k, c = _derive_bip32_child_secp256k1(k, c, idx)

    priv_ec = ec.derive_private_key(
        int.from_bytes(k, byteorder="big"), ec.SECP256K1(), default_backend()
    )
    pn = priv_ec.public_key().public_numbers()
    x_bytes = pn.x.to_bytes(32, byteorder="big")
    y_bytes = pn.y.to_bytes(32, byteorder="big")

    # 1. TRON TRC-20 (Base58Check with 0x41 prefix over Keccak-256 coordinates)
    if network == BlockchainNetwork.TRON_TRC20:
        uncompressed_coords = x_bytes + y_bytes
        keccak_digest = keccak_256(uncompressed_coords)
        tron_p21 = b"\x41" + keccak_digest[12:32]
        tron_chk = hashlib.sha256(hashlib.sha256(tron_p21).digest()).digest()[:4]
        return _b58encode(tron_p21 + tron_chk)

    # 2. Ethereum / BSC EVM 0x (EIP-55 mixed-case checksum)
    if network == BlockchainNetwork.ETHEREUM_EVM_0X:
        uncompressed_coords = x_bytes + y_bytes
        keccak_digest = keccak_256(uncompressed_coords)
        raw_hex = keccak_digest[12:32].hex().lower()
        hash_hex = keccak_256(raw_hex.encode("ascii")).hex()
        eip55_chars = []
        for i, ch in enumerate(raw_hex):
            if ch in "0123456789":
                eip55_chars.append(ch)
            elif int(hash_hex[i], 16) >= 8:
                eip55_chars.append(ch.upper())
            else:
                eip55_chars.append(ch.lower())
        return "0x" + "".join(eip55_chars)

    # 3. Bitcoin Native SegWit BIP-84 (Bech32 hrp="bc" witness v0)
    if network == BlockchainNetwork.BITCOIN_SEGWIT_BIP84:
        prefix = b"\x02" if pn.y % 2 == 0 else b"\x03"
        comp_pub = prefix + x_bytes
        sha_dig = hashlib.sha256(comp_pub).digest()
        h160 = hashlib.new("ripemd160", sha_dig).digest()
        payload_5bit = [0] + _convertbits(h160, 8, 5)
        checksum = _bech32_create_checksum("bc", payload_5bit)
        return "bc1" + "".join(BECH32_CHARSET[d] for d in payload_5bit + checksum)

    # 4. Bitcoin Legacy BIP-44 (Base58Check with 0x00 prefix)
    if network == BlockchainNetwork.BITCOIN_LEGACY_BIP44:
        prefix = b"\x02" if pn.y % 2 == 0 else b"\x03"
        comp_pub = prefix + x_bytes
        sha_dig = hashlib.sha256(comp_pub).digest()
        h160 = hashlib.new("ripemd160", sha_dig).digest()
        payload = b"\x00" + h160
        chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return _b58encode(payload + chk)

    return ""


def derive_all_standard_addresses(
    mnemonic: str, passphrase: str = "", seed_record_uid: int = 1
) -> List[HDDerivedAddressRecord]:
    """
    Derives standard Index 0 addresses across TRON, Ethereum/EVM, Bitcoin SegWit,
    Bitcoin Legacy, and Solana from a BIP-39 mnemonic seed phrase.

    Only the first address of each account is derived: no match here does not mean the wallet was unused.
    A network whose derivation fails (e.g. RIPEMD-160 missing from this OpenSSL build) is skipped with a
    logged warning instead of aborting every other network.
    """
    seed_bytes = derive_master_seed_bip39(mnemonic, passphrase)

    configs = [
        (BlockchainNetwork.TRON_TRC20, "m/44'/195'/0'/0/0"),
        (BlockchainNetwork.ETHEREUM_EVM_0X, "m/44'/60'/0'/0/0"),
        (BlockchainNetwork.BITCOIN_SEGWIT_BIP84, "m/84'/0'/0'/0/0"),
        (BlockchainNetwork.BITCOIN_LEGACY_BIP44, "m/44'/0'/0'/0/0"),
        (BlockchainNetwork.SOLANA_SLIP0010, "m/44'/501'/0'/0'"),
    ]

    records = []
    for network, path in configs:
        try:
            addr = derive_hd_address(seed_bytes, network, path)
        except (ValueError, TypeError) as exc:
            logger.warning("derivation for %s failed: %s", network, exc)
            continue
        records.append(
            HDDerivedAddressRecord(
                seed_record_uid=seed_record_uid,
                blockchain_network=network,
                derivation_path=path,
                derived_public_address=addr,
                matches_on_device_activity=0,
            )
        )
    return records
