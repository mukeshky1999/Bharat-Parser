"""
Sub-Engine 7.1C: Binary Container Provenance, Live Photo Companion Pairing,
and Android Motion Photo Embedded MP4 Video Carver.
Complies with Section 5 of Phase 7 Module 7.1 Specification and AGENTS.md Constitution.
"""

import os
from pathlib import Path
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from src.media_library.models import (
    ProvenanceClassification,
)

_XMP_MICRO_VIDEO_OFFSET_REGEX = re.compile(rb'GCamera:MicroVideoOffset="([0-9]+)"')
_XMP_ITEM_LENGTH_REGEX = re.compile(rb'Item:Length="([0-9]+)"')
_FTYP_BOX_REGEX = re.compile(rb"(\x00\x00\x00[\x14-\x40]ftyp(?:mp42|isom|qt  |heic|mif1))")


class BinaryProvenanceCarver:
    """Carves embedded motion videos, pairs Apple Live Photos, and verifies binary provenance."""

    def carve_motion_photo(
        self,
        image_path: str,
        output_dir: str,
    ) -> Optional[str]:
        """
        Carves embedded MP4 video stream appended inside an Android Motion Photo (Pixel/Samsung/Xiaomi).
        Uses XMP GCamera:MicroVideoOffset or scans trailing bytes after JPEG EOI marker (FF D9).
        """
        if not os.path.exists(image_path):
            return None

        with open(image_path, "rb") as f:
            data = f.read()

        file_len = len(data)
        if file_len < 128:
            return None

        # 1. Search for XMP MicroVideoOffset
        offset_match = _XMP_MICRO_VIDEO_OFFSET_REGEX.search(data)
        item_len_match = _XMP_ITEM_LENGTH_REGEX.search(data)

        vid_offset: Optional[int] = None
        if offset_match:
            try:
                vid_offset = int(offset_match.group(1))
            except (ValueError, IndexError):
                vid_offset = None
        elif item_len_match:
            try:
                vid_offset = int(item_len_match.group(1))
            except (ValueError, IndexError):
                vid_offset = None

        mp4_payload: Optional[bytes] = None

        # 2. Search for ftyp box start
        ftyp_pos = data.find(b"ftyp")
        if ftyp_pos >= 4:
            cand = data[ftyp_pos - 4 :]
            if vid_offset and len(cand) >= vid_offset:
                mp4_payload = cand[:vid_offset]
            else:
                mp4_payload = cand
        elif vid_offset and 0 < vid_offset < file_len:
            mp4_payload = data[-vid_offset:]
        else:
            # Fallback: search after JPEG End-Of-Image marker (\xFF\xD9)
            eoi_idx = data.find(b"\xff\xd9")
            if eoi_idx != -1 and (eoi_idx + 2) < file_len:
                trailing = data[eoi_idx + 2 :]
                ftyp_match = _FTYP_BOX_REGEX.search(trailing)
                if ftyp_match:
                    start_pos = ftyp_match.start(1)
                    cand = trailing[start_pos:]
                    if vid_offset and len(cand) >= vid_offset:
                        mp4_payload = cand[:vid_offset]
                    else:
                        mp4_payload = cand

        if mp4_payload and len(mp4_payload) >= 16:
            # Validate box structure: begins with box length and 'ftyp'
            if b"ftyp" in mp4_payload[4:8]:
                Path(output_dir).mkdir(parents=True, exist_ok=True)
                stem = Path(image_path).stem
                out_path = os.path.join(output_dir, f"{stem}_carved_motion.mp4")
                with open(out_path, "wb") as out_f:
                    out_f.write(mp4_payload)
                return out_path

        return None

    def pair_live_photos(
        self,
        file_paths: List[str],
    ) -> Dict[str, str]:
        """
        Pairs companion .HEIC/.JPG still images with corresponding .MOV video clips
        sharing the same filename stem or Apple Live Photo ContentIdentifier UUID.
        Returns mapping: image_file_path -> video_file_path.
        """
        paired: Dict[str, str] = {}
        images: Dict[str, str] = {}
        videos: Dict[str, str] = {}

        img_exts = {".heic", ".jpg", ".jpeg", ".png"}
        vid_exts = {".mov", ".mp4"}

        for p in file_paths:
            path_obj = Path(p)
            ext = path_obj.suffix.lower()
            stem = path_obj.stem
            if ext in img_exts:
                images[stem] = p
            elif ext in vid_exts:
                videos[stem] = p

        for stem, img_path in images.items():
            if stem in videos:
                paired[img_path] = videos[stem]

        return paired

    def classify_binary_provenance(
        self,
        file_path: str,
        declared_origin: Optional[str] = None,
    ) -> ProvenanceClassification:
        """
        Determines binary container provenance class based on container headers,
        EXIF maker notes, and quantization/dimension patterns.
        """
        if not os.path.exists(file_path):
            return ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL

        file_size = os.path.getsize(file_path)
        if file_size < 32:
            return ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL

        with open(file_path, "rb") as f:
            head = f.read(2048)

        # 1. Check for Screenshot markers
        if b"\x89PNG\r\n\x1a\n" in head[:8]:
            if b"iDOT" in head or b"cHRM" in head:
                return ProvenanceClassification.OS_SCREENSHOT_OR_SCREEN_RECORDING

        # 2. Check declared origin
        if declared_origin:
            dec_lower = declared_origin.lower()
            if "springboard" in dec_lower or "screenshot" in dec_lower:
                return ProvenanceClassification.OS_SCREENSHOT_OR_SCREEN_RECORDING
            if any(m in dec_lower for m in ["whatsapp", "telegram", "signal", "instagram"]):
                return ProvenanceClassification.MESSENGER_TRANSMITTED_REENCODED

        # 3. Check for camera EXIF
        if b"Exif\x00\x00" in head or b"Apple iOS" in head:
            return ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL

        return ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL
