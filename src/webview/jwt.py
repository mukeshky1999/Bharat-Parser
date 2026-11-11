"""
Automated JSON Web Token (JWT) & Session Identity Claims Unpacker.
Adheres strictly to Specification Section 7.3 and AGENTS.md Forensic Invariants.
"""

import base64
import json
import re
from typing import Any, Dict, Optional, Tuple

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _b64url_decode(segment: str) -> bytes:
    """Decodes a Base64URL string, adding necessary padding bytes."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def unpack_jwt_token(text: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    Scans a string for a 3-part Base64URL JSON Web Token (`eyJ...`) and extracts
    the decoded header and payload JSON dictionaries.
    """
    if not text:
        return None

    match = JWT_PATTERN.search(text)
    if not match:
        return None

    jwt_str = match.group(0)
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, _ = parts

    try:
        header_bytes = _b64url_decode(header_b64)
        payload_bytes = _b64url_decode(payload_b64)
        header_dict = json.loads(header_bytes.decode("utf-8"))
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
        if isinstance(header_dict, dict) and isinstance(payload_dict, dict):
            return header_dict, payload_dict
        return None
    except Exception:
        return None


def extract_jwt_claims_json(text: str) -> Optional[str]:
    """
    Extracts high-value identity claims from a JWT token in text and returns
    a formatted JSON string. Returns None if no valid JWT is present.
    """
    unpacked = unpack_jwt_token(text)
    if unpacked is None:
        return None

    _, payload = unpacked
    return json.dumps(payload, indent=2)
