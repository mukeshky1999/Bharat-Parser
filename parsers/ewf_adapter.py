"""
EWF (Expert Witness Compression Format / .E01, .Ex01, .L01) Adapter.
Provides Sleuth Kit (pytsk3) Img_Info integration for streaming and selectively
carving forensic artifacts from large EWF containers without memory exhaustion.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from typing import Any, Callable, Generator, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

try:
    import pyewf
except ImportError:
    pyewf = None

try:
    import pytsk3
except ImportError:
    pytsk3 = None


# Determine the base class for EwfImgInfo depending on pytsk3 availability
_BaseImgInfo = pytsk3.Img_Info if (pytsk3 is not None and hasattr(pytsk3, "Img_Info")) else object


class EwfImgInfo(_BaseImgInfo):
    """
    Adapter wrapping a pyewf file handle as a pytsk3.Img_Info object.
    Enables The Sleuth Kit (TSK) to read and walk filesystems embedded inside
    Expert Witness Format (E01 / Ex01 / L01) images without full decompression.
    """

    def __init__(self, ewf_handle: Any):
        self._ewf_handle = ewf_handle
        if pytsk3 is not None and hasattr(pytsk3, "Img_Info") and issubclass(self.__class__, pytsk3.Img_Info):
            try:
                super().__init__(url="", type=getattr(pytsk3, "TSK_IMG_TYPE_EXTERNAL", 0))
            except TypeError:
                super().__init__()
        else:
            super().__init__()

    @property
    def ewf_handle(self) -> Any:
        """Returns the wrapped pyewf handle."""
        return self._ewf_handle

    def close(self) -> None:
        """Closes the underlying pyewf handle."""
        if self._ewf_handle is not None and hasattr(self._ewf_handle, "close"):
            self._ewf_handle.close()

    def read(self, offset: int, size: int) -> bytes:
        """
        Reads `size` bytes starting at byte `offset` from the EWF container.
        """
        if self._ewf_handle is None:
            return b""
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self) -> int:
        """
        Returns the total uncompressed media size in bytes.
        """
        if self._ewf_handle is None:
            return 0
        if hasattr(self._ewf_handle, "get_media_size"):
            return int(self._ewf_handle.get_media_size())
        return 0

    def __iter__(self):
        """Allows unpacking as (handle, img_info) for maximum API compatibility."""
        return iter((self._ewf_handle, self))


def open_ewf_image(image_path: str) -> EwfImgInfo:
    """
    Discovers all image segments (.E01, .E02, etc.) using pyewf.glob,
    opens the logical container, and returns an EwfImgInfo instance.
    The returned object can also be unpacked as (ewf_handle, img_info).
    """
    if pyewf is None:
        raise ImportError(
            "pyewf is required to open EWF (.E01/.Ex01/.L01) images. "
            "Please install libewf-python (pip install -r requirements-optional.txt)."
        )

    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Forensic image not found: {image_path}")

    try:
        filenames = pyewf.glob(image_path)
    except Exception as e:
        logger.warning(f"pyewf.glob failed for {image_path}: {e}; falling back to single path.")
        filenames = [image_path]

    if not filenames:
        filenames = [image_path]

    handle = pyewf.handle()
    handle.open(filenames)
    return EwfImgInfo(handle)


def walk_pytsk3_directory(
    fs_info: Any, directory_obj: Any, current_path: str = "/"
) -> Generator[Tuple[str, Any], None, None]:
    """
    Recursively walks a pytsk3 Directory object, yielding (virtual_path, pytsk3.File).
    Safely ignores special '.' and '..' entries and avoids non-allocated / corrupt entries.
    """
    dir_type = getattr(pytsk3, "TSK_FS_META_TYPE_DIR", 2) if pytsk3 else 2
    reg_type = getattr(pytsk3, "TSK_FS_META_TYPE_REG", 1) if pytsk3 else 1
    alloc_flag = getattr(pytsk3, "TSK_FS_NAME_FLAG_ALLOC", 1) if pytsk3 else 1

    try:
        for entry in directory_obj:
            if not getattr(entry, "info", None) or not getattr(entry.info, "name", None):
                continue
            name_bytes = getattr(entry.info.name, "name", None)
            if not name_bytes or name_bytes in (b".", b".."):
                continue

            try:
                name_str = name_bytes.decode("utf-8", errors="replace")
            except Exception:
                name_str = str(name_bytes)

            path = f"{current_path.rstrip('/')}/{name_str}"
            meta = getattr(entry.info, "meta", None)

            if meta is not None:
                meta_type = getattr(meta, "type", None)

                if meta_type == dir_type:
                    name_flags = getattr(entry.info.name, "flags", alloc_flag)
                    if name_flags & alloc_flag:
                        try:
                            sub_dir = entry.as_directory()
                            yield from walk_pytsk3_directory(fs_info, sub_dir, path)
                        except Exception as e:
                            logger.debug(f"Could not open directory {path}: {e}")
                            continue

                elif meta_type == reg_type:
                    yield path, entry

    except Exception as e:
        logger.warning(f"Error traversing directory {current_path}: {e}")


def stream_tsk_file_chunks(
    entry: Any, local_out_path: str, chunk_size: int = 8 * 1024 * 1024
) -> int:
    """
    Streams file bytes from a pytsk3.File entry directly to disk in 8 MB chunks
    without buffering the entire file into memory (Zero-OOM).
    Returns total bytes written.
    """
    meta = getattr(entry.info, "meta", None)
    file_size = getattr(meta, "size", 0) if meta else 0
    if file_size <= 0:
        os.makedirs(os.path.dirname(local_out_path), exist_ok=True)
        with open(local_out_path, "wb") as f:
            f.write(b"")
        return 0

    os.makedirs(os.path.dirname(local_out_path), exist_ok=True)
    bytes_written = 0
    offset = 0

    with open(local_out_path, "wb") as dst:
        while offset < file_size:
            to_read = min(chunk_size, file_size - offset)
            if hasattr(entry, "read_random"):
                chunk = entry.read_random(offset, to_read)
            else:
                chunk = b""
            if not chunk:
                break
            dst.write(chunk)
            bytes_written += len(chunk)
            offset += len(chunk)

    return bytes_written
