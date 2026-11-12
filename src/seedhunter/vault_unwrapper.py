"""
Sub-Engine 4.4C: Web3 Keystore (scrypt / PBKDF2) & MetaMask Vault Unwrapper.
Complies with Section 5 of Phase 4 Module 4.4 Specification.
"""

import base64
import hashlib
import json
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.validators.address_validators import keccak_256


def unwrap_web3_keystore_v3(
    keystore_json_str: str, candidate_password: str
) -> Tuple[bool, Optional[str], dict]:
    """
    Unwraps a Version 3 Web3 Secret Storage Keystore JSON (Trust Wallet, TronLink, TokenPocket).
    Derives key via scrypt or PBKDF2-HMAC-SHA256, verifies password via Keccak-256 MAC,
    and decrypts payload via AES-128-CTR.
    Returns (success, recovered_secret_hex, metadata_dict).
    """
    try:
        data = json.loads(keystore_json_str)
    except Exception as exc:
        return False, None, {"error": f"Invalid JSON: {exc}"}

    crypto = data.get("crypto") or data.get("Crypto")
    if not isinstance(crypto, dict):
        return False, None, {"error": "Missing crypto section"}

    kdf = str(crypto.get("kdf") or "").lower()
    kdfparams = crypto.get("kdfparams") or {}
    if not isinstance(kdfparams, dict):
        return False, None, {"error": "Malformed kdfparams"}
    salt_hex = kdfparams.get("salt", "")
    try:
        salt = bytes.fromhex(salt_hex)
    except Exception:
        salt = salt_hex.encode("utf-8")

    # 1. Key Derivation (32-byte derivedKey)
    if kdf == "pbkdf2":
        iterations = int(kdfparams.get("c", 262144))
        if not (1 <= iterations <= 10_000_000):  # the file is untrusted: do not let it set an unbounded run time
            return False, None, {"error": f"Refusing PBKDF2 iteration count {iterations}"}
        derived_key = hashlib.pbkdf2_hmac(
            "sha256", candidate_password.encode("utf-8"), salt, iterations, 32
        )
    elif kdf == "scrypt":
        n = int(kdfparams.get("n", 8192))
        r = int(kdfparams.get("r", 8))
        p = int(kdfparams.get("p", 1))
        if not (2 <= n <= 1 << 22) or not (1 <= r <= 64) or not (1 <= p <= 16):
            return False, None, {"error": f"Refusing scrypt parameters n={n} r={r} p={p}"}
        try:
            derived_key = hashlib.scrypt(
                candidate_password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=2 * 128 * r * (n + p + 2),  # the default 32 MB limit rejects the real n=262144 keystores
                dklen=32,
            )
        except (ValueError, MemoryError) as exc:
            return False, None, {"error": f"scrypt failed: {exc}"}
    else:
        return False, None, {"error": f"Unsupported KDF: {kdf}"}

    mac_key = derived_key[16:32]
    aes_key = derived_key[:16]

    # 2. Keccak-256 MAC Verification: keccak256(derivedKey[16:32] || ciphertext)
    ciphertext_hex = crypto.get("ciphertext", "")
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except Exception:
        return False, None, {"error": "Malformed ciphertext hex"}

    computed_mac = keccak_256(mac_key + ciphertext).hex().lower()
    expected_mac = crypto.get("mac", "").lower()

    if computed_mac != expected_mac:
        return False, None, {
            "mac_verified": False,
            "kdf": kdf,
            "error": "Keccak-256 MAC mismatch - incorrect password",
        }

    # 3. Decryption via AES-128-CTR
    cipher_name = crypto.get("cipher", "").lower()
    iv_hex = crypto.get("cipherparams", {}).get("iv", "")
    try:
        iv = bytes.fromhex(iv_hex)
    except Exception:
        return False, None, {"error": "Malformed IV hex"}

    if cipher_name == "aes-128-ctr":
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return True, plaintext.hex(), {
            "mac_verified": True,
            "kdf": kdf,
            "address": data.get("address", ""),
            "id": data.get("id", ""),
        }

    return False, None, {
        "mac_verified": True,
        "error": f"Unsupported cipher: {cipher_name}",
    }


def unwrap_metamask_vault(
    vault_json_str: str, candidate_password: str
) -> Tuple[bool, Optional[str], dict]:
    """
    Unwraps a MetaMask KeyringController.vault JSON using PBKDF2-HMAC-SHA256 and AES-256-GCM.
    Returns (success, recovered_mnemonic_or_json_str, metadata_dict).
    """
    try:
        vault = json.loads(vault_json_str)
    except Exception as exc:
        return False, None, {"error": f"Invalid JSON: {exc}"}

    data_b64 = vault.get("data")
    iv_b64 = vault.get("iv")
    salt_b64 = vault.get("salt")
    if not (data_b64 and iv_b64 and salt_b64):
        return False, None, {"error": "Missing data/iv/salt in MetaMask vault"}

    try:
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        ct_and_tag = base64.b64decode(data_b64)
    except Exception as exc:
        return False, None, {"error": f"Base64 decode error: {exc}"}

    key_meta = vault.get("keyMetadata", {})
    iterations = int(key_meta.get("params", {}).get("iterations", 10000))

    try:
        derived_key = hashlib.pbkdf2_hmac(
            "sha256", candidate_password.encode("utf-8"), salt, iterations, 32
        )
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(iv, ct_and_tag, None).decode("utf-8")
        return True, plaintext, {
            "iterations": iterations,
            "algorithm": "PBKDF2-AESGCM",
        }
    except InvalidTag:
        return False, None, {
            "error": "AES-256-GCM authentication tag verification failed - incorrect password"
        }
    except Exception as exc:
        return False, None, {"error": str(exc)}
