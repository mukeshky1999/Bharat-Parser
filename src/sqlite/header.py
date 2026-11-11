"""
SQLite 100-Byte Database File Header and B-Tree Page Header Parsers.
Adheres strictly to Specification Section 3, Section 4, and Section 2 Mistakes 1 & 2.
"""

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class SQLiteHeader:
    """Decoded 100-byte SQLite database header."""
    header_magic: bytes
    page_size: int
    usable_page_size: int
    write_version: int
    read_version: int
    reserved_bytes: int
    file_change_counter: int
    header_page_count: int
    first_freelist_trunk_page: int
    total_freelist_pages: int
    schema_cookie: int
    schema_format_number: int
    largest_root_btree_page: int
    text_encoding: str
    incremental_vacuum_mode: int
    application_id: int
    version_valid_for: int
    sqlite_version_number: int
    auto_vacuum_mode: str
    journal_mode_header: str


@dataclass(slots=True)
class BTreePageHeader:
    """Decoded SQLite B-Tree page header."""
    page_type: int
    first_freeblock_offset: int
    cell_count: int
    cell_content_area_start: int
    fragmented_free_bytes: int
    right_most_child_page: Optional[int]
    header_offset: int
    header_size: int


def parse_sqlite_header(data: bytes) -> SQLiteHeader:
    """
    Parses the 100-byte database header from the start of a SQLite database file.
    """
    if len(data) < 100:
        raise ValueError(f"SQLite header must be at least 100 bytes, got {len(data)}")

    header_magic = data[:16]
    raw_page_size = struct.unpack(">H", data[16:18])[0]
    # Edge case: raw_page_size == 1 represents 65,536 bytes
    if raw_page_size == 1:
        page_size = 65536
    else:
        page_size = raw_page_size

    write_version = data[18]
    read_version = data[19]
    reserved_bytes = data[20]
    usable_page_size = page_size - reserved_bytes

    file_change_counter = struct.unpack(">I", data[24:28])[0]
    header_page_count = struct.unpack(">I", data[28:32])[0]
    first_freelist_trunk = struct.unpack(">I", data[32:36])[0]
    total_freelist_pages = struct.unpack(">I", data[36:40])[0]
    schema_cookie = struct.unpack(">I", data[40:44])[0]
    schema_format_number = struct.unpack(">I", data[44:48])[0]
    largest_root_btree_page = struct.unpack(">I", data[52:56])[0]

    encoding_int = struct.unpack(">I", data[56:60])[0]
    if encoding_int == 2:
        text_encoding = "UTF-16LE"
    elif encoding_int == 3:
        text_encoding = "UTF-16BE"
    else:
        text_encoding = "UTF-8"

    incremental_vacuum_mode = struct.unpack(">I", data[64:68])[0]
    application_id = struct.unpack(">I", data[68:72])[0]
    version_valid_for = struct.unpack(">I", data[92:96])[0]
    sqlite_version_number = struct.unpack(">I", data[96:100])[0]

    if largest_root_btree_page > 0:
        if incremental_vacuum_mode != 0:
            auto_vacuum_mode = "INCREMENTAL_VACUUM"
        else:
            auto_vacuum_mode = "FULL_AUTO_VACUUM"
    else:
        auto_vacuum_mode = "NONE"

    journal_mode_header = "WAL" if write_version == 2 else "LEGACY_ROLLBACK"

    return SQLiteHeader(
        header_magic=header_magic,
        page_size=page_size,
        usable_page_size=usable_page_size,
        write_version=write_version,
        read_version=read_version,
        reserved_bytes=reserved_bytes,
        file_change_counter=file_change_counter,
        header_page_count=header_page_count,
        first_freelist_trunk_page=first_freelist_trunk,
        total_freelist_pages=total_freelist_pages,
        schema_cookie=schema_cookie,
        schema_format_number=schema_format_number,
        largest_root_btree_page=largest_root_btree_page,
        text_encoding=text_encoding,
        incremental_vacuum_mode=incremental_vacuum_mode,
        application_id=application_id,
        version_valid_for=version_valid_for,
        sqlite_version_number=sqlite_version_number,
        auto_vacuum_mode=auto_vacuum_mode,
        journal_mode_header=journal_mode_header,
    )


def parse_btree_page_header(page_bytes: bytes, page_num: int) -> BTreePageHeader:
    """
    Parses the B-Tree page header.
    On Page 1: starts at Byte Offset 100.
    On Page >= 2: starts at Byte Offset 0.
    """
    offset = 100 if page_num == 1 else 0

    if len(page_bytes) < offset + 8:
        raise ValueError(
            f"Page buffer length {len(page_bytes)} is too short for page {page_num} header"
        )

    page_type = page_bytes[offset]
    first_freeblock = struct.unpack(">H", page_bytes[offset + 1:offset + 3])[0]
    cell_count = struct.unpack(">H", page_bytes[offset + 3:offset + 5])[0]
    cell_content_start = struct.unpack(">H", page_bytes[offset + 5:offset + 7])[0]
    if cell_content_start == 0:
        cell_content_start = 65536
    fragmented_free_bytes = page_bytes[offset + 7]

    is_interior = page_type in (0x02, 0x05)
    header_size = 12 if is_interior else 8

    right_most_child: Optional[int] = None
    if is_interior:
        if len(page_bytes) >= offset + 12:
            right_most_child = struct.unpack(">I", page_bytes[offset + 8:offset + 12])[0]

    return BTreePageHeader(
        page_type=page_type,
        first_freeblock_offset=first_freeblock,
        cell_count=cell_count,
        cell_content_area_start=cell_content_start,
        fragmented_free_bytes=fragmented_free_bytes,
        right_most_child_page=right_most_child,
        header_offset=offset,
        header_size=header_size,
    )
