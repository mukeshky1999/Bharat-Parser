"""
Zero-Extraction Virtual Filesystem (VFS) Indexer.
Phase 1, Module 1.1, Sections 4 & 6: Builds high-speed SQLite catalog of forensic archives without extraction.
"""

import gzip
import io
import os
import plistlib
import sqlite3
import struct
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List, Dict, Any

from src.core.enums import ContainerType, EntryType, CompressionMethod
from src.vfs.fingerprint import ContainerFingerprinter
from src.vfs.normalizer import CanonicalPathNormalizer


@dataclass(slots=True)
class AbHeaderInfo:
    """Header information from Android Backup (.ab) archive."""
    magic: str
    backup_version: int
    compressed: bool
    encryption_algorithm: str
    is_encrypted: bool
    data_offset: int


class AbUnpacker:
    """Android Backup (.ab) Header and Deflate Stream Handler."""

    @staticmethod
    def parse_header(file_path: Union[str, Path]) -> AbHeaderInfo:
        with open(file_path, "rb") as f:
            header_buf = f.read(1024)

        header_text = header_buf.decode("latin-1", errors="replace")
        lines = header_text.split("\n")

        magic = lines[0].strip() if len(lines) > 0 else ""
        if not magic.startswith("ANDROID BACKUP"):
            raise ValueError(f"[AB_UNPACKER] Not a valid Android Backup file. Magic: '{magic}'")

        try:
            backup_version = int(lines[1].strip()) if len(lines) > 1 and lines[1].strip() else 1
        except ValueError:
            backup_version = 1

        compressed = (lines[2].strip() == "1") if len(lines) > 2 else True
        encryption_algorithm = lines[3].strip() if len(lines) > 3 else "none"
        is_encrypted = encryption_algorithm.lower() != "none"

        target_lines = 9 if is_encrypted else 4
        offset = 0
        line_count = 0

        for i, byte_val in enumerate(header_buf):
            if byte_val == 0x0A:  # \n
                line_count += 1
                if line_count == target_lines:
                    offset = i + 1
                    break

        return AbHeaderInfo(
            magic=magic,
            backup_version=backup_version,
            compressed=compressed,
            encryption_algorithm=encryption_algorithm,
            is_encrypted=is_encrypted,
            data_offset=offset
        )


@dataclass(slots=True)
class UfdMetadataInfo:
    """Device and extraction metadata harvested from Cellebrite UFED (.ufd/.ufdx) files."""
    device_model: Optional[str] = None
    manufacturer: Optional[str] = None
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    android_version: Optional[str] = None
    build_number: Optional[str] = None
    extraction_type: Optional[str] = None
    examiner_name: Optional[str] = None
    raw_params: dict[str, str] = field(default_factory=dict)


class UfdParser:
    """Cellebrite UFED (.ufd/.ufdx) metadata parser."""

    @staticmethod
    def parse_ufd(file_path: Union[str, Path]) -> UfdMetadataInfo:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()

        params: dict[str, str] = {}
        for line in text.splitlines():
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("[") or trimmed.startswith("#"):
                continue
            eq_idx = trimmed.find("=")
            if eq_idx != -1:
                k = trimmed[:eq_idx].strip().lower()
                v = trimmed[eq_idx + 1:].strip()
                params[k] = v

        return UfdMetadataInfo(
            device_model=params.get("model") or params.get("device model") or params.get("devicemodel"),
            manufacturer=params.get("vendor") or params.get("manufacturer") or params.get("make"),
            serial_number=params.get("serial no") or params.get("serialnumber") or params.get("device serial number"),
            imei=params.get("imei") or params.get("imei 1") or params.get("imei1"),
            android_version=params.get("os version") or params.get("android version") or params.get("os"),
            build_number=params.get("build number") or params.get("build"),
            extraction_type=params.get("extraction type") or params.get("extractiontype"),
            examiner_name=params.get("examiner name") or params.get("examiner"),
            raw_params=params
        )


@dataclass(slots=True)
class VFSIndexEntry:
    """Catalog record for a single virtual file in vfs_index."""
    container_id: int
    canonical_path: str
    parent_dir_path: str
    filename: str
    file_extension: Optional[str]
    original_raw_path: str
    entry_type: EntryType
    symlink_target: Optional[str]
    uncompressed_size: int
    compressed_size: int
    archive_data_offset: int
    compression_method: CompressionMethod
    backup_file_id_sha1: Optional[str] = None
    is_encrypted_entry: int = 0
    file_id: Optional[int] = None


class VFSIndexer:
    """Walks archive headers and records file metadata into vfs_index.sqlite."""

    BATCH_SIZE = 25000

    def __init__(self, catalog_db_path: Union[str, Path]):
        self.catalog_db_path = Path(catalog_db_path)
        self.normalizer = CanonicalPathNormalizer()
        self.fingerprinter = ContainerFingerprinter()
        self._init_db()

    def _init_db(self) -> None:
        """Initializes SQLite catalog with WAL mode and mandatory performance indexes."""
        self.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.catalog_db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA temp_store = MEMORY;")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS vfs_index (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id INTEGER NOT NULL,
                canonical_path TEXT NOT NULL,
                parent_dir_path TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_extension TEXT,
                original_raw_path TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                symlink_target TEXT,
                uncompressed_size INTEGER NOT NULL DEFAULT 0,
                compressed_size INTEGER NOT NULL DEFAULT 0,
                archive_data_offset INTEGER NOT NULL DEFAULT 0,
                compression_method TEXT NOT NULL,
                backup_file_id_sha1 TEXT,
                is_encrypted_entry INTEGER DEFAULT 0
            );
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_vfs_canonical_path ON vfs_index(canonical_path);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vfs_parent_dir ON vfs_index(parent_dir_path);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vfs_filename ON vfs_index(filename);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vfs_extension ON vfs_index(file_extension);")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS gzip_seek_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id INTEGER NOT NULL,
                compressed_offset INTEGER NOT NULL,
                uncompressed_offset INTEGER NOT NULL,
                bit_offset INTEGER NOT NULL,
                window_lz4_blob BLOB NOT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS container_sources (
                container_id INTEGER PRIMARY KEY,
                source_path TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    def index_archive(self, target_path: Union[str, Path], container_id: int) -> int:
        """
        Indexes an archive or directory without extracting payloads to disk.
        Returns total number of files indexed.
        """
        path = Path(target_path)
        conn = sqlite3.connect(self.catalog_db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO container_sources (container_id, source_path) VALUES (?, ?)",
            (container_id, str(path.resolve()))
        )
        conn.commit()
        conn.close()

        fp_result = self.fingerprinter.fingerprint(path)

        if fp_result.container_type == ContainerType.TAR_UNCOMPRESSED:
            return self._index_tar_uncompressed(path, container_id)
        elif fp_result.container_type in {ContainerType.STANDARD_ZIP, ContainerType.CELLEBRITE_UFDR, ContainerType.ZIP_OR_UFDR}:
            return self._index_zip_archive(path, container_id)
        elif fp_result.container_type == ContainerType.IOS_BACKUP_DIR:
            return self._index_ios_backup(path, container_id)
        elif fp_result.container_type == ContainerType.TAR_GZ_COMPRESSED:
            return self._index_tar_gz(path, container_id)
        elif fp_result.container_type == ContainerType.ANDROID_AB_BACKUP:
            return self._index_android_backup(path, container_id)
        elif fp_result.container_type == ContainerType.UFED_PACKAGE_DIR:
            total = 0
            for payload in fp_result.payload_paths:
                total += self.index_archive(payload, container_id)
            return total
        else:
            return self._index_tar_uncompressed(path, container_id)

    def _index_android_backup(self, archive_path: Path, container_id: int) -> int:
        """Indexes Android ADB Backup (.ab) file using AbUnpacker header offset calculation."""
        ab_info = AbUnpacker.parse_header(archive_path)
        if ab_info.is_encrypted:
            return 0

        entries: List[VFSIndexEntry] = []
        with open(archive_path, "rb") as f:
            f.seek(ab_info.data_offset)
            payload_bytes = f.read()

        if ab_info.compressed:
            try:
                uncompressed_stream = zlib.decompress(payload_bytes)
            except Exception:
                try:
                    decompressor = zlib.decompressobj()
                    uncompressed_stream = decompressor.decompress(payload_bytes)
                except Exception:
                    return 0
        else:
            uncompressed_stream = payload_bytes

        tar_buf = io.BytesIO(uncompressed_stream)
        try:
            with tarfile.open(fileobj=tar_buf, mode="r:") as tar:
                for member in tar.getmembers():
                    canonical = self.normalizer.normalize_path(member.name)
                    parent_dir = str(Path(canonical).parent).replace("\\", "/")
                    bname = Path(canonical).name
                    ext = Path(bname).suffix.lstrip(".").lower() if "." in bname else None
                    entry_type = EntryType.DIRECTORY if member.isdir() else EntryType.REGULAR_FILE

                    entry = VFSIndexEntry(
                        container_id=container_id,
                        canonical_path=canonical,
                        parent_dir_path=parent_dir,
                        filename=bname,
                        file_extension=ext,
                        original_raw_path=member.name,
                        entry_type=entry_type,
                        symlink_target=member.linkname if member.issym() else None,
                        uncompressed_size=member.size,
                        compressed_size=member.size,
                        archive_data_offset=member.offset_data,
                        compression_method=CompressionMethod.ANDROID_AB_STREAM if ab_info.compressed else CompressionMethod.RAW_STORED,
                        backup_file_id_sha1=None,
                        is_encrypted_entry=0
                    )
                    entries.append(entry)
        except Exception:
            return 0

        return self._bulk_commit(entries)

    def _index_tar_uncompressed(self, archive_path: Path, container_id: int) -> int:
        """Indexes uncompressed TAR file using 512-byte header jumps and PAX parser."""
        entries: List[VFSIndexEntry] = []
        file_size = archive_path.stat().st_size

        with open(archive_path, "rb") as f:
            offset = 0
            pending_pax_attrs: dict[str, str] = {}
            pending_long_name: Optional[str] = None

            while offset + 512 <= file_size:
                f.seek(offset)
                header_bytes = f.read(512)

                # Check for two consecutive null blocks signalling EOF
                if header_bytes == b"\x00" * 512:
                    offset += 512
                    continue

                # Read raw name (100 bytes)
                raw_name_bytes = header_bytes[0:100].split(b"\x00", 1)[0]
                try:
                    name = raw_name_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    name = raw_name_bytes.decode("latin-1")

                # Parse octal or binary size
                size_field = header_bytes[124:136]
                if size_field[0] & 0x80:
                    payload_size = struct.unpack(">Q", size_field[4:12])[0]
                else:
                    size_str = size_field.split(b"\x00", 1)[0].strip()
                    payload_size = int(size_str, 8) if size_str else 0

                typeflag = header_bytes[156:157]
                data_offset = offset + 512

                # Handle PAX Extended Header ('x' or 'g')
                if typeflag in (b"x", b"g"):
                    f.seek(data_offset)
                    pax_payload = f.read(payload_size)
                    pending_pax_attrs = self._parse_pax_payload(pax_payload)
                    padded_len = ((payload_size + 511) // 512) * 512
                    offset = data_offset + padded_len
                    continue

                # Handle GNU LongLink Filename ('L')
                if typeflag == b"L":
                    f.seek(data_offset)
                    long_bytes = f.read(payload_size).split(b"\x00", 1)[0]
                    pending_long_name = long_bytes.decode("utf-8", errors="replace")
                    padded_len = ((payload_size + 511) // 512) * 512
                    offset = data_offset + padded_len
                    continue

                # Resolve actual name
                if "path" in pending_pax_attrs:
                    actual_name = pending_pax_attrs["path"]
                elif pending_long_name:
                    actual_name = pending_long_name
                else:
                    # Check prefix field (155 bytes at offset 345)
                    prefix_bytes = header_bytes[345:500].split(b"\x00", 1)[0]
                    if prefix_bytes:
                        try:
                            prefix = prefix_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            prefix = prefix_bytes.decode("latin-1")
                        actual_name = f"{prefix}/{name}"
                    else:
                        actual_name = name

                # Entry type
                symlink_target = None
                if typeflag == b"2":
                    entry_type = EntryType.SYMLINK
                    linkname_bytes = header_bytes[157:257].split(b"\x00", 1)[0]
                    symlink_target = pending_pax_attrs.get("linkpath", linkname_bytes.decode("utf-8", errors="replace"))
                elif typeflag == b"5" or actual_name.endswith("/"):
                    entry_type = EntryType.DIRECTORY
                else:
                    entry_type = EntryType.REGULAR_FILE

                canonical = self.normalizer.normalize_path(actual_name)
                parent_dir = str(Path(canonical).parent).replace("\\", "/")
                filename = Path(canonical).name
                ext = Path(filename).suffix.lstrip(".").lower() if "." in filename else None

                entry = VFSIndexEntry(
                    container_id=container_id,
                    canonical_path=canonical,
                    parent_dir_path=parent_dir,
                    filename=filename,
                    file_extension=ext,
                    original_raw_path=actual_name,
                    entry_type=entry_type,
                    symlink_target=symlink_target,
                    uncompressed_size=payload_size,
                    compressed_size=payload_size,
                    archive_data_offset=data_offset,
                    compression_method=CompressionMethod.RAW_STORED,
                    backup_file_id_sha1=None,
                    is_encrypted_entry=0
                )
                entries.append(entry)

                # Reset pending attributes
                pending_pax_attrs = {}
                pending_long_name = None

                # Jump to next header
                padded_len = ((payload_size + 511) // 512) * 512
                offset = data_offset + padded_len

        return self._bulk_commit(entries)

    def _parse_pax_payload(self, payload: bytes) -> dict[str, str]:
        """Parses PAX key-value record block: '%d %s=%s\\n'."""
        attrs = {}
        pos = 0
        total = len(payload)
        while pos < total:
            space_idx = payload.find(b" ", pos)
            if space_idx == -1:
                break
            try:
                rec_len = int(payload[pos:space_idx])
            except ValueError:
                break
            record = payload[pos:pos + rec_len]
            pos += rec_len

            line = record.decode("utf-8", errors="replace").rstrip("\n")
            first_space = line.find(" ")
            if first_space != -1:
                kv = line[first_space + 1:]
                eq_idx = kv.find("=")
                if eq_idx != -1:
                    key = kv[:eq_idx]
                    val = kv[eq_idx + 1:]
                    attrs[key] = val
        return attrs

    def _index_zip_archive(self, archive_path: Path, container_id: int) -> int:
        """Indexes ZIP / ZIP64 / UFDR archive using Central Directory backward scan."""
        entries: List[VFSIndexEntry] = []
        file_size = archive_path.stat().st_size

        with open(archive_path, "rb") as f:
            # 1. Read last 65557 bytes to find EOCD
            scan_size = min(65557, file_size)
            f.seek(file_size - scan_size)
            tail = f.read(scan_size)

            eocd_pos_in_tail = tail.rfind(b"PK\x05\x06")
            if eocd_pos_in_tail == -1:
                return 0

            eocd_offset = (file_size - scan_size) + eocd_pos_in_tail

            # 2. Check for ZIP64 EOCD Locator immediately preceding EOCD
            is_zip64 = False
            cd_offset = 0
            cd_entries_count = 0

            locator_pos_in_tail = tail.rfind(b"PK\x06\x07", 0, eocd_pos_in_tail)
            if locator_pos_in_tail != -1:
                locator_offset = (file_size - scan_size) + locator_pos_in_tail
                f.seek(locator_offset)
                locator_bytes = f.read(20)
                if len(locator_bytes) == 20:
                    zip64_eocd_offset = struct.unpack("<Q", locator_bytes[8:16])[0]
                    f.seek(zip64_eocd_offset)
                    zip64_eocd = f.read(56)
                    if zip64_eocd.startswith(b"PK\x06\x06"):
                        is_zip64 = True
                        cd_entries_count = struct.unpack("<Q", zip64_eocd[32:40])[0]
                        cd_offset = struct.unpack("<Q", zip64_eocd[48:56])[0]

            if not is_zip64:
                f.seek(eocd_offset)
                eocd_bytes = f.read(22)
                cd_entries_count = struct.unpack("<H", eocd_bytes[10:12])[0]
                cd_offset = struct.unpack("<I", eocd_bytes[16:20])[0]

            # 3. Read Central Directory
            f.seek(cd_offset)
            for _ in range(cd_entries_count):
                cd_header = f.read(46)
                if len(cd_header) < 46 or not cd_header.startswith(b"PK\x01\x02"):
                    break

                comp_method_raw = struct.unpack("<H", cd_header[10:12])[0]
                comp_size = struct.unpack("<I", cd_header[20:24])[0]
                uncomp_size = struct.unpack("<I", cd_header[24:28])[0]
                name_len = struct.unpack("<H", cd_header[28:30])[0]
                extra_len = struct.unpack("<H", cd_header[30:32])[0]
                comment_len = struct.unpack("<H", cd_header[32:34])[0]
                local_header_offset = struct.unpack("<I", cd_header[42:46])[0]

                name_bytes = f.read(name_len)
                extra_bytes = f.read(extra_len)
                if comment_len > 0:
                    f.seek(comment_len, io.SEEK_CUR)

                try:
                    filename_raw = name_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    filename_raw = name_bytes.decode("cp437", errors="replace")

                # Parse ZIP64 extra field 0x0001
                pos = 0
                while pos + 4 <= len(extra_bytes):
                    ef_id, ef_len = struct.unpack("<HH", extra_bytes[pos:pos + 4])
                    pos += 4
                    if ef_id == 0x0001:
                        p = pos
                        if uncomp_size == 0xFFFFFFFF and p + 8 <= pos + ef_len:
                            uncomp_size = struct.unpack("<Q", extra_bytes[p:p + 8])[0]
                            p += 8
                        if comp_size == 0xFFFFFFFF and p + 8 <= pos + ef_len:
                            comp_size = struct.unpack("<Q", extra_bytes[p:p + 8])[0]
                            p += 8
                        if local_header_offset == 0xFFFFFFFF and p + 8 <= pos + ef_len:
                            local_header_offset = struct.unpack("<Q", extra_bytes[p:p + 8])[0]
                            p += 8
                    pos += ef_len

                # Determine compression enum
                if comp_method_raw == 0:
                    compression_method = CompressionMethod.RAW_STORED
                elif comp_method_raw == 8:
                    compression_method = CompressionMethod.ZIP_DEFLATE
                elif comp_method_raw == 93:
                    compression_method = CompressionMethod.ZIP_ZSTD
                else:
                    compression_method = CompressionMethod.ZIP_DEFLATE

                canonical = self.normalizer.normalize_path(filename_raw)
                parent_dir = str(Path(canonical).parent).replace("\\", "/")
                bname = Path(canonical).name
                ext = Path(bname).suffix.lstrip(".").lower() if "." in bname else None
                entry_type = EntryType.DIRECTORY if filename_raw.endswith("/") else EntryType.REGULAR_FILE

                entry = VFSIndexEntry(
                    container_id=container_id,
                    canonical_path=canonical,
                    parent_dir_path=parent_dir,
                    filename=bname,
                    file_extension=ext,
                    original_raw_path=filename_raw,
                    entry_type=entry_type,
                    symlink_target=None,
                    uncompressed_size=uncomp_size,
                    compressed_size=comp_size,
                    archive_data_offset=local_header_offset,
                    compression_method=compression_method,
                    backup_file_id_sha1=None,
                    is_encrypted_entry=0
                )
                entries.append(entry)

        return self._bulk_commit(entries)

    def _index_ios_backup(self, backup_dir: Path, container_id: int) -> int:
        """Indexes unencrypted or decrypted iOS Manifest.db SQLite database."""
        entries: List[VFSIndexEntry] = []
        manifest_db_path = backup_dir / "Manifest.db"
        if not manifest_db_path.exists():
            return 0

        conn = sqlite3.connect(manifest_db_path)
        cur = conn.cursor()
        cur.execute("SELECT fileID, domain, relativePath, flags, file FROM Files")
        rows = cur.fetchall()
        conn.close()

        for file_id, domain, rel_path, flags, file_blob in rows:
            canonical = self.normalizer.normalize_ios_domain(domain, rel_path)
            parent_dir = str(Path(canonical).parent).replace("\\", "/")
            bname = Path(canonical).name
            ext = Path(bname).suffix.lstrip(".").lower() if "." in bname else None

            uncomp_size = 0
            if file_blob:
                try:
                    plist_obj = plistlib.loads(file_blob)
                    if isinstance(plist_obj, dict):
                        objects = plist_obj.get("$objects", [])
                        for obj in objects:
                            if isinstance(obj, dict) and "Size" in obj:
                                uncomp_size = int(obj["Size"])
                                break
                except Exception:
                    # Fallback to physical file stat if accessible on disk
                    disk_target = backup_dir / file_id[:2] / file_id
                    if disk_target.exists():
                        uncomp_size = disk_target.stat().st_size

            entry = VFSIndexEntry(
                container_id=container_id,
                canonical_path=canonical,
                parent_dir_path=parent_dir,
                filename=bname,
                file_extension=ext,
                original_raw_path=f"{domain}:{rel_path}",
                entry_type=EntryType.REGULAR_FILE,
                symlink_target=None,
                uncompressed_size=uncomp_size,
                compressed_size=uncomp_size,
                archive_data_offset=0,
                compression_method=CompressionMethod.IOS_BACKUP_FILE,
                backup_file_id_sha1=file_id,
                is_encrypted_entry=0
            )
            entries.append(entry)

        return self._bulk_commit(entries)

    def _index_tar_gz(self, archive_path: Path, container_id: int) -> int:
        """Indexes GZIP compressed TAR archive."""
        entries: List[VFSIndexEntry] = []
        with tarfile.open(archive_path, mode="r:gz") as tar:
            for member in tar.getmembers():
                canonical = self.normalizer.normalize_path(member.name)
                parent_dir = str(Path(canonical).parent).replace("\\", "/")
                bname = Path(canonical).name
                ext = Path(bname).suffix.lstrip(".").lower() if "." in bname else None

                entry_type = EntryType.DIRECTORY if member.isdir() else EntryType.REGULAR_FILE
                entry = VFSIndexEntry(
                    container_id=container_id,
                    canonical_path=canonical,
                    parent_dir_path=parent_dir,
                    filename=bname,
                    file_extension=ext,
                    original_raw_path=member.name,
                    entry_type=entry_type,
                    symlink_target=member.linkname if member.issym() else None,
                    uncompressed_size=member.size,
                    compressed_size=member.size,
                    archive_data_offset=member.offset_data,
                    compression_method=CompressionMethod.TAR_GZ_STREAM,
                    backup_file_id_sha1=None,
                    is_encrypted_entry=0
                )
                entries.append(entry)

        return self._bulk_commit(entries)

    def _bulk_commit(self, entries: List[VFSIndexEntry]) -> int:
        """Commits entries in prepared-statement batches of 25,000 rows."""
        if not entries:
            return 0

        conn = sqlite3.connect(self.catalog_db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.execute("PRAGMA journal_mode = WAL;")

        insert_sql = """
            INSERT INTO vfs_index (
                container_id, canonical_path, parent_dir_path, filename, file_extension,
                original_raw_path, entry_type, symlink_target, uncompressed_size,
                compressed_size, archive_data_offset, compression_method,
                backup_file_id_sha1, is_encrypted_entry
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        total = len(entries)
        for i in range(0, total, self.BATCH_SIZE):
            batch = entries[i:i + self.BATCH_SIZE]
            cur.execute("BEGIN IMMEDIATE;")
            cur.executemany(insert_sql, [
                (
                    e.container_id,
                    e.canonical_path,
                    e.parent_dir_path,
                    e.filename,
                    e.file_extension,
                    e.original_raw_path,
                    e.entry_type.value,
                    e.symlink_target,
                    e.uncompressed_size,
                    e.compressed_size,
                    e.archive_data_offset,
                    e.compression_method.value,
                    e.backup_file_id_sha1,
                    e.is_encrypted_entry
                )
                for e in batch
            ])
            cur.execute("COMMIT;")

        conn.close()
        return total
