"""
Tencent WCDB (WeChat EnMicroMsg.db) Password Derivation.
Adheres strictly to Specification Section 6.4 (Recipe 4).
"""

import hashlib
from typing import List, Union


DEFAULT_FALLBACK_IMEI = "1234567890ABCDEF"


def derive_wcdb_password(imei: str, uin: Union[int, str]) -> str:
    """
    Derives the 7-character lowercase hexadecimal WCDB database password:
    seed = IMEI || str(signed_uin)
    wcdb_password = md5(seed)[:7]
    """
    seed = f"{imei.strip()}{str(uin).strip()}"
    md5_hash = hashlib.md5(seed.encode("utf-8")).hexdigest().lower()
    return md5_hash[:7]


def get_candidate_wcdb_passwords(
    discovered_imeis: List[str],
    uin: Union[int, str]
) -> List[str]:
    """
    Generates candidate WCDB passwords across all discovered device IMEIs,
    always including the standard Android 10-17 fallback string '1234567890ABCDEF'.
    """
    candidates = []
    seen_seeds = set()

    all_imeis = list(discovered_imeis)
    if DEFAULT_FALLBACK_IMEI not in all_imeis:
        all_imeis.append(DEFAULT_FALLBACK_IMEI)

    for imei in all_imeis:
        if not imei:
            continue
        pwd = derive_wcdb_password(imei, uin)
        if pwd not in seen_seeds:
            seen_seeds.add(pwd)
            candidates.append(pwd)

    return candidates
