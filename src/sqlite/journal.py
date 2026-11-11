"""
SQLite Rollback Journal (-journal) Decoder.
Adheres strictly to Specification Section 7 (Pipeline B2).
"""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union


JOURNAL_MAGIC = b"\xD9\xD5\x05\xF9\x20\xA1\x63\xD7"


@dataclass(slots=True)
class JournalSectorHeader:
    """Decoded 28-byte sector header from a rollback journal."""
    page_count: int
    checksum_nonce: int
    initial_db_page_count: int
    disk_sector_size: int
    journal_page_size: int
    header_offset: int


@dataclass(slots=True)
class JournalPage:
    """Represents a pre-transaction page record from a rollback journal."""
    page_number: int
    page_data: bytes
    checksum: int
    file_byte_offset: int


class RollbackJournalReader:
    """Decodes pre-transaction rollback journal files."""

    def __init__(self, journal_path: Union[str, Path]):
        self.journal_path = Path(journal_path)
        self.header: Optional[JournalSectorHeader] = None
        self.pages: List[JournalPage] = []

    def read_all_pages(self) -> List[JournalPage]:
        """Reads and returns all valid pre-transaction page images from the journal."""
        if not self.journal_path.exists():
            return []

        file_size = self.journal_path.stat().st_size
        if file_size < 28:
            return []

        with open(self.journal_path, "rb") as f:
            data = f.read()

        # Check for magic at offset 0
        header_offset = 0
        if len(data) >= 8 and data[:8] == JOURNAL_MAGIC:
            header_offset = 0
        else:
            # Check if zeroed out in PERSIST/TRUNCATE mode; scan offset 512 and 4096
            for candidate in (512, 4096):
                if len(data) >= candidate + 8 and data[candidate:candidate + 8] == JOURNAL_MAGIC:
                    header_offset = candidate
                    break

        if header_offset >= len(data) or len(data) < header_offset + 28:
            return []

        hdr_slice = data[header_offset:header_offset + 28]
        if hdr_slice[:8] != JOURNAL_MAGIC and not all(b == 0 for b in hdr_slice[:8]):
            return []

        page_count = struct.unpack(">i", hdr_slice[8:12])[0]
        nonce = struct.unpack(">I", hdr_slice[12:16])[0]
        init_db_pages = struct.unpack(">I", hdr_slice[16:20])[0]
        sector_size = struct.unpack(">I", hdr_slice[20:24])[0]
        page_size = struct.unpack(">I", hdr_slice[24:28])[0]

        if sector_size <= 0:
            sector_size = 512
        if page_size <= 0:
            page_size = 4096

        self.header = JournalSectorHeader(
            page_count=page_count,
            checksum_nonce=nonce,
            initial_db_page_count=init_db_pages,
            disk_sector_size=sector_size,
            journal_page_size=page_size,
            header_offset=header_offset,
        )

        record_size = 4 + page_size + 4
        records_offset = header_offset + sector_size
        pages: List[JournalPage] = []

        cursor = records_offset
        while cursor + record_size <= len(data):
            rec_bytes = data[cursor:cursor + record_size]
            page_num = struct.unpack(">I", rec_bytes[:4])[0]
            page_data = rec_bytes[4:4 + page_size]
            chksum = struct.unpack(">I", rec_bytes[4 + page_size:record_size])[0]

            if 1 <= page_num <= 100000000:
                pages.append(
                    JournalPage(
                        page_number=page_num,
                        page_data=page_data,
                        checksum=chksum,
                        file_byte_offset=cursor,
                    )
                )

            cursor += record_size
            if page_count > 0 and len(pages) >= page_count:
                break

        self.pages = pages
        return pages
