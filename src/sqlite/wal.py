"""
Shared WAL (Write-Ahead Log) Reader & Forensic Frame Classifier.
Adheres strictly to Specification Section 6 (Pipeline B1).
"""

import struct
from dataclasses import dataclass
from enum import Enum, unique
from pathlib import Path
from typing import List, Optional, Tuple, Union


@unique
class WALFrameState(str, Enum):
    """4-state forensic classification of a WAL frame."""
    LATEST_COMMITTED_WAL_FRAME = "LATEST_COMMITTED_WAL_FRAME"
    HISTORICAL_SUPERSEDED_COMMITTED_FRAME = "HISTORICAL_SUPERSEDED_COMMITTED_FRAME"
    UNCOMMITTED_IN_FLIGHT_WAL_FRAME = "UNCOMMITTED_IN_FLIGHT_WAL_FRAME"
    PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME = "PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME"


@dataclass(slots=True)
class WALHeader:
    """Decoded 32-byte WAL file header."""
    wal_magic: int
    file_format_version: int
    page_size: int
    checkpoint_seq: int
    salt_1: int
    salt_2: int
    chksum_1: int
    chksum_2: int
    is_big_endian_checksum: bool


@dataclass(slots=True)
class WALFrame:
    """Represents a single decoded frame in the WAL file."""
    frame_index: int  # 1-based index
    page_number: int
    commit_size: int  # > 0 if this frame commits a transaction
    salt_1: int
    salt_2: int
    chksum_1: int
    chksum_2: int
    page_data: bytes
    file_byte_offset: int
    is_valid_active_checksum: bool
    state: WALFrameState = WALFrameState.UNCOMMITTED_IN_FLIGHT_WAL_FRAME


def compute_wal_checksum(
    buf: bytes,
    is_big_endian: Union[bool, str] = False,
    s0: int = 0,
    s1: int = 0
) -> Tuple[int, int]:
    """
    Computes cumulative WAL checksum over buffer of 8-byte chunks.
    s0 = (s0 + x0 + s1) mod 2^32
    s1 = (s1 + x1 + s0) mod 2^32
    """
    if isinstance(is_big_endian, str):
        is_big = is_big_endian in (">", "big", "BE", "be", "True", "true")
    else:
        is_big = bool(is_big_endian)

    unpack_fmt = ">II" if is_big else "<II"
    chunks = len(buf) // 8

    for i in range(chunks):
        chunk = buf[i * 8:(i + 1) * 8]
        x0, x1 = struct.unpack(unpack_fmt, chunk)
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF

    return s0, s1


def parse_wal_header(header_bytes: bytes) -> WALHeader:
    """Parses and validates 32-byte WAL header."""
    if len(header_bytes) < 32:
        raise ValueError(f"WAL header requires 32 bytes, got {len(header_bytes)}")

    magic = struct.unpack(">I", header_bytes[:4])[0]
    if magic == 0x377F0682:
        is_big_endian = False
    elif magic == 0x377F0683:
        is_big_endian = True
    else:
        # Default to Little-Endian word checksum
        is_big_endian = False

    fmt = ">I"
    version = struct.unpack(fmt, header_bytes[4:8])[0]
    page_size = struct.unpack(fmt, header_bytes[8:12])[0]
    chkpt_seq = struct.unpack(fmt, header_bytes[12:16])[0]
    salt1 = struct.unpack(fmt, header_bytes[16:20])[0]
    salt2 = struct.unpack(fmt, header_bytes[20:24])[0]

    # Checksum integers are always serialized on disk as Big-Endian uint32_be
    chksum_fmt = ">II"
    s0, s1 = struct.unpack(chksum_fmt, header_bytes[24:32])

    return WALHeader(
        wal_magic=magic,
        file_format_version=version,
        page_size=page_size,
        checkpoint_seq=chkpt_seq,
        salt_1=salt1,
        salt_2=salt2,
        chksum_1=s0,
        chksum_2=s1,
        is_big_endian_checksum=is_big_endian,
    )


class WALReader:
    """Reads, verifies, and classifies frames from a SQLite WAL file."""

    def __init__(self, wal_path: Union[str, Path], page_size: Optional[int] = None):
        self.wal_path = Path(wal_path)
        self.override_page_size = page_size
        self.header: Optional[WALHeader] = None
        self.frames: List[WALFrame] = []

    def read_all_frames(self) -> List[WALFrame]:
        """Reads all frames from the WAL file, tracking cumulative checksums and states."""
        if not self.wal_path.exists():
            return []

        file_size = self.wal_path.stat().st_size
        if file_size < 32:
            return []

        with open(self.wal_path, "rb") as f:
            header_bytes = f.read(32)
            self.header = parse_wal_header(header_bytes)
            page_size = self.override_page_size or self.header.page_size
            if page_size <= 0:
                page_size = 4096

            is_be = self.header.is_big_endian_checksum
            # Checksums on disk are always stored as Big-Endian uint32_be
            chksum_fmt = ">II"

            frame_size = 24 + page_size
            total_possible_frames = (file_size - 32) // frame_size

            s0, s1 = self.header.chksum_1, self.header.chksum_2
            active_chain_intact = True

            frames: List[WALFrame] = []

            for i in range(1, total_possible_frames + 1):
                offset = 32 + (i - 1) * frame_size
                f.seek(offset)
                hdr = f.read(24)
                if len(hdr) < 24:
                    break

                page_num = struct.unpack(">I", hdr[:4])[0]
                commit_size = struct.unpack(">I", hdr[4:8])[0]
                salt1 = struct.unpack(">I", hdr[8:12])[0]
                salt2 = struct.unpack(">I", hdr[12:16])[0]
                expected_s0, expected_s1 = struct.unpack(chksum_fmt, hdr[16:24])

                page_data = f.read(page_size)
                if len(page_data) < page_size:
                    break

                # Verify checksum if still within active chain
                is_valid = False
                if active_chain_intact and salt1 == self.header.salt_1 and salt2 == self.header.salt_2:
                    # Feed bytes 0..7 of frame header, then page_data
                    next_s0, next_s1 = compute_wal_checksum(hdr[:8], is_be, s0, s1)
                    next_s0, next_s1 = compute_wal_checksum(page_data, is_be, next_s0, next_s1)

                    if next_s0 == expected_s0 and next_s1 == expected_s1:
                        is_valid = True
                        s0, s1 = next_s0, next_s1
                    else:
                        active_chain_intact = False
                else:
                    active_chain_intact = False

                frames.append(
                    WALFrame(
                        frame_index=i,
                        page_number=page_num,
                        commit_size=commit_size,
                        salt_1=salt1,
                        salt_2=salt2,
                        chksum_1=expected_s0,
                        chksum_2=expected_s1,
                        page_data=page_data,
                        file_byte_offset=offset,
                        is_valid_active_checksum=is_valid,
                    )
                )

            # Classify frames into the 4 states
            self._classify_frame_states(frames)
            self.frames = frames
            return frames

    def _classify_frame_states(self, frames: List[WALFrame]) -> None:
        """Classifies each WAL frame into States 1-4 per Section 6.3."""
        # Find index of last continuous valid frame with commit_size > 0
        last_commit_idx = -1
        last_valid_active_idx = -1

        for idx, frame in enumerate(frames):
            if frame.is_valid_active_checksum:
                last_valid_active_idx = idx
                if frame.commit_size > 0:
                    last_commit_idx = idx
            else:
                break

        # Map page_number to the highest committed frame index <= last_commit_idx
        latest_committed_map: dict[int, int] = {}
        for idx in range(last_commit_idx + 1):
            frame = frames[idx]
            latest_committed_map[frame.page_number] = idx

        for idx, frame in enumerate(frames):
            if idx > last_valid_active_idx:
                # Outside active continuous WAL chain
                frame.state = WALFrameState.PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME
            elif idx > last_commit_idx:
                # Inside active chain, but after last commit frame
                frame.state = WALFrameState.UNCOMMITTED_IN_FLIGHT_WAL_FRAME
            else:
                # At or before last commit frame
                if latest_committed_map.get(frame.page_number) == idx:
                    frame.state = WALFrameState.LATEST_COMMITTED_WAL_FRAME
                else:
                    frame.state = WALFrameState.HISTORICAL_SUPERSEDED_COMMITTED_FRAME
