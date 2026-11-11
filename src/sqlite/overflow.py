"""
SQLite Overflow Page Calculation and Chain Reassembly.
Adheres strictly to Specification Section 5.2.
"""

import struct
from typing import Callable, Tuple


MAX_SAFE_OVERFLOW_PAYLOAD = 100 * 1024 * 1024  # 100 MB hostile payload cap


def calculate_overflow_bounds(
    usable_page_size: int,
    total_payload_bytes: int
) -> Tuple[int, bool]:
    """
    Calculates the number of local payload bytes stored on a Table B-Tree Leaf Page (0x0D),
    and whether the cell spills onto overflow pages.

    Returns `(local_bytes, has_overflow)`.
    """
    if usable_page_size <= 35:
        return max(0, total_payload_bytes), False

    # Hostile bounds clamp
    if total_payload_bytes < 0:
        return 0, False
    if total_payload_bytes > MAX_SAFE_OVERFLOW_PAYLOAD:
        P = MAX_SAFE_OVERFLOW_PAYLOAD
    else:
        P = total_payload_bytes

    U = usable_page_size
    X = U - 35
    M = ((U - 12) * 32) // 255 - 23

    if P <= X:
        return P, False

    K = M + ((P - M) % (U - 4))
    if K <= X:
        local_bytes = K
    else:
        local_bytes = M

    return local_bytes, True


def reassemble_overflow_chain(
    first_chunk: bytes,
    first_overflow_page_num: int,
    total_payload_bytes: int,
    usable_page_size: int,
    page_fetcher: Callable[[int], bytes]
) -> bytes:
    """
    Follows the 4-byte linked overflow page chain and reassembles the full payload buffer.
    Includes cycle detection and hostile overflow bounds protection.
    """
    if total_payload_bytes <= len(first_chunk) or usable_page_size <= 4:
        return bytes(first_chunk)

    safe_total = min(total_payload_bytes, MAX_SAFE_OVERFLOW_PAYLOAD)
    buffer = bytearray(first_chunk)
    U = usable_page_size
    next_page_num = first_overflow_page_num
    visited_pages = set()

    while len(buffer) < safe_total and next_page_num > 0:
        if next_page_num in visited_pages:
            break
        visited_pages.add(next_page_num)

        page_bytes = page_fetcher(next_page_num)
        if len(page_bytes) < 4:
            break

        # Bytes 0-3: next overflow page number
        next_page = struct.unpack(">I", page_bytes[:4])[0]

        bytes_needed = safe_total - len(buffer)
        available_payload = min(bytes_needed, U - 4, len(page_bytes) - 4)

        if available_payload <= 0:
            break

        buffer.extend(page_bytes[4:4 + available_payload])
        next_page_num = next_page

    return bytes(buffer)
