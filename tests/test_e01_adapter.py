"""
Unit and Integration Test Suite: E01 (Expert Witness Format) pyewf & pytsk3 Adapter.
Tests:
1. EwfImgInfo wrapping a mock pyewf handle (seek, read, get_size, close, unpacking).
2. open_ewf_image() globbing and handle initialization.
3. pytsk3 directory walker recursion and entry filtering.
4. Selective streaming of target SQLite databases to extracted_dbs/ with 8 MB chunking.
5. Skipping bulk media files (e.g. .mp4) to prevent disk and memory bloat.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from parsers.enterprise_1tb_chat_and_container_engine import (
    FORENSIC_TARGET_FILENAMES,
    should_materialize_artifact,
)
from parsers.ewf_adapter import (
    EwfImgInfo,
    open_ewf_image,
    stream_tsk_file_chunks,
    walk_pytsk3_directory,
)


class MockEwfHandle:
    """Mocks a pyewf.handle object with seekable in-memory byte storage."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self.is_closed = False
        self.opened_filenames = []

    def open(self, filenames: list) -> None:
        self.opened_filenames = list(filenames)

    def get_media_size(self) -> int:
        return len(self._data)

    def seek(self, offset: int, whence: int = 0) -> None:
        if whence == 0:
            self._pos = max(0, min(offset, len(self._data)))
        elif whence == 1:
            self._pos = max(0, min(self._pos + offset, len(self._data)))
        elif whence == 2:
            self._pos = max(0, min(len(self._data) + offset, len(self._data)))

    def read(self, size: int) -> bytes:
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        self.is_closed = True


class MockTskName:
    def __init__(self, name_bytes: bytes, flags: int = 1):
        self.name = name_bytes
        self.flags = flags


class MockTskMeta:
    def __init__(self, meta_type: int = 1, size: int = 0, addr: int = 100):
        self.type = meta_type
        self.size = size
        self.addr = addr


class MockTskInfo:
    def __init__(self, name_bytes: bytes, meta_type: int = 1, size: int = 0, addr: int = 100, flags: int = 1):
        self.name = MockTskName(name_bytes, flags)
        self.meta = MockTskMeta(meta_type, size, addr)


class MockTskFileEntry:
    """Mocks a pytsk3.File entry in a directory iteration."""

    def __init__(
        self,
        name: str,
        is_dir: bool = False,
        data: bytes = b"",
        inode: int = 100,
        children: list = None,
    ):
        self.name_str = name
        self.is_dir = is_dir
        self.data = data
        self.children = children or []
        self.read_chunk_sizes = []

        meta_type = 2 if is_dir else 1  # 2: DIR, 1: REG
        self.info = MockTskInfo(
            name_bytes=name.encode("utf-8"),
            meta_type=meta_type,
            size=len(data) if not is_dir else 0,
            addr=inode,
        )

    def as_directory(self):
        if not self.is_dir:
            raise ValueError("Not a directory")
        return self.children

    def read_random(self, offset: int, size: int) -> bytes:
        self.read_chunk_sizes.append(size)
        if offset >= len(self.data):
            return b""
        return self.data[offset : offset + size]


class TestEwfAdapter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bharat_e01_test_")
        self.extracted_dbs_dir = os.path.join(self.temp_dir, "extracted_dbs")
        os.makedirs(self.extracted_dbs_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. EwfImgInfo Unit Tests
    # --------------------------------------------------------------------------
    def test_ewf_img_info_basic_io(self):
        payload = b"EXPERT WITNESS FORMAT DISK DATA 1234567890" * 100
        mock_handle = MockEwfHandle(payload)
        img_info = EwfImgInfo(mock_handle)

        self.assertEqual(img_info.get_size(), len(payload))

        # Test offset read
        read_chunk = img_info.read(10, 20)
        self.assertEqual(read_chunk, payload[10:30])

        # Test unpacking as (handle, img_info)
        handle, adapter = img_info
        self.assertIs(handle, mock_handle)
        self.assertIs(adapter, img_info)

        # Test close
        self.assertFalse(mock_handle.is_closed)
        img_info.close()
        self.assertTrue(mock_handle.is_closed)

    def test_open_ewf_image_with_mocked_pyewf(self):
        dummy_e01 = os.path.join(self.temp_dir, "evidence.E01")
        with open(dummy_e01, "wb") as f:
            f.write(b"EVF\t\r\n\x00")

        mock_handle = MockEwfHandle(b"DISKCONTENT" * 50)
        mock_pyewf = MagicMock()
        mock_pyewf.glob.return_value = [dummy_e01]
        mock_pyewf.handle.return_value = mock_handle

        with patch("parsers.ewf_adapter.pyewf", mock_pyewf):
            img_info = open_ewf_image(dummy_e01)
            mock_pyewf.glob.assert_called_once_with(dummy_e01)
            self.assertEqual(mock_handle.opened_filenames, [dummy_e01])
            self.assertEqual(img_info.get_size(), len(b"DISKCONTENT" * 50))

    def test_open_ewf_image_nonexistent_raises_filenotfound(self):
        mock_pyewf = MagicMock()
        with patch("parsers.ewf_adapter.pyewf", mock_pyewf):
            with self.assertRaises(FileNotFoundError):
                open_ewf_image(os.path.join(self.temp_dir, "nonexistent.E01"))

    # --------------------------------------------------------------------------
    # 2. File System Walker & Selective Extraction Tests
    # --------------------------------------------------------------------------
    def test_pytsk3_walker_and_8mb_chunked_streaming(self):
        """
        Validates:
        1. Directory walker recursively descends into directories.
        2. High-value SQLite database (msgstore.db) is identified and extracted.
        3. 8 MB chunking is strictly adhered to (no chunk > 8MB).
        4. Bulk media (.mp4) is skipped from extraction to avoid OOM / disk bloat.
        """
        # Create a mock SQLite payload (10 MB to force multiple 8 MB chunks)
        sqlite_header = b"SQLite format 3\x00" + (b"\x00" * 84)
        mock_sqlite_data = sqlite_header + (b"\xAA" * (10 * 1024 * 1024 - 100))

        # Create a mock MP4 payload (5 MB)
        mock_video_data = b"ftypmp42" + (b"\xBB" * (5 * 1024 * 1024))

        # Construct file entries
        msgstore_entry = MockTskFileEntry("msgstore.db", is_dir=False, data=mock_sqlite_data, inode=101)
        video_entry = MockTskFileEntry("large_surveillance.mp4", is_dir=False, data=mock_video_data, inode=102)
        dot_entry = MockTskFileEntry(".", is_dir=True, inode=99)
        dotdot_entry = MockTskFileEntry("..", is_dir=True, inode=98)

        # Directory structure:
        # /
        #   databases/
        #     msgstore.db
        #     large_surveillance.mp4
        db_dir = MockTskFileEntry(
            "databases",
            is_dir=True,
            inode=100,
            children=[dot_entry, dotdot_entry, msgstore_entry, video_entry],
        )
        root_children = [dot_entry, dotdot_entry, db_dir]

        mock_fs = MagicMock()

        # Run directory walker
        discovered_files = list(walk_pytsk3_directory(mock_fs, root_children, "/"))

        # Walker should find both files (path, entry)
        paths = [p for p, _ in discovered_files]
        self.assertIn("/databases/msgstore.db", paths)
        self.assertIn("/databases/large_surveillance.mp4", paths)

        # Now simulate the TerabyteForensicContainerEngine selective ingestion logic
        materialized_files = []
        for vpath, entry in discovered_files:
            fsize = entry.info.meta.size
            if should_materialize_artifact(vpath, fsize):
                # Target artifact (SQLite DB)
                out_path = os.path.join(self.extracted_dbs_dir, vpath.lstrip("/\\"))
                bytes_written = stream_tsk_file_chunks(entry, out_path, chunk_size=8 * 1024 * 1024)
                materialized_files.append((vpath, out_path, bytes_written))

        # Assert: ONLY msgstore.db was materialized, large_surveillance.mp4 was filtered out
        self.assertEqual(len(materialized_files), 1)
        target_vpath, target_out_path, written_size = materialized_files[0]

        self.assertEqual(target_vpath, "/databases/msgstore.db")
        self.assertTrue(os.path.exists(target_out_path))
        self.assertEqual(written_size, len(mock_sqlite_data))

        # Verify extracted file contents match byte-for-byte
        with open(target_out_path, "rb") as f:
            disk_content = f.read()
        self.assertEqual(disk_content, mock_sqlite_data)

        # Assert 8 MB chunking: 10 MB total size should be split into 8 MB + 2 MB chunks
        self.assertEqual(msgstore_entry.read_chunk_sizes, [8 * 1024 * 1024, 2 * 1024 * 1024])
        self.assertTrue(all(sz <= 8 * 1024 * 1024 for sz in msgstore_entry.read_chunk_sizes))

        # Assert video file was NEVER read
        self.assertEqual(len(video_entry.read_chunk_sizes), 0)

    # --------------------------------------------------------------------------
    # 3. TerabyteForensicContainerEngine E01 Ingestion Integration
    # --------------------------------------------------------------------------
    def test_engine_e01_full_ingestion_and_on_demand_attachment(self):
        """
        Tests TerabyteForensicContainerEngine native ingestion on an .E01 image:
        1. Ingests .E01 container, detecting partition and file systems.
        2. Populates vfs_catalog.db with 'E01' container_format.
        3. Streams target SQLite database to extracted_dbs/ (is_materialized = 1).
        4. Leaves media attachment unmaterialized until extract_attachment_on_demand is called.
        """
        import sqlite3
        from parsers.enterprise_1tb_chat_and_container_engine import TerabyteForensicContainerEngine

        dummy_e01 = os.path.join(self.temp_dir, "suspect_device.E01")
        with open(dummy_e01, "wb") as f:
            f.write(b"EVF\t\r\n\x00" + b"\x00" * 512)

        sqlite_data = b"SQLite format 3\x00" + (b"\x11" * 400)
        jpg_data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + (b"\x22" * 1000)

        db_entry = MockTskFileEntry("msgstore.db", is_dir=False, data=sqlite_data, inode=201)
        jpg_entry = MockTskFileEntry("evidence_photo.jpg", is_dir=False, data=jpg_data, inode=202)
        dot_entry = MockTskFileEntry(".", is_dir=True, inode=199)
        dotdot_entry = MockTskFileEntry("..", is_dir=True, inode=198)

        mock_dir = MockTskFileEntry("databases", is_dir=True, inode=200, children=[dot_entry, dotdot_entry, db_entry, jpg_entry])
        root_children = [dot_entry, dotdot_entry, mock_dir]

        # Setup mock pytsk3 FS_Info and Volume_Info
        mock_img_info = MagicMock()
        mock_img_info.close = MagicMock()

        mock_fs = MagicMock()
        mock_fs.open_dir.return_value = root_children

        def mock_fs_open(path):
            norm = path.lstrip("/\\")
            if "evidence_photo.jpg" in norm:
                return jpg_entry
            if "msgstore.db" in norm:
                return db_entry
            raise FileNotFoundError(path)

        mock_fs.open.side_effect = mock_fs_open

        mock_pytsk3 = MagicMock()
        mock_pytsk3.TSK_FS_META_TYPE_DIR = 2
        mock_pytsk3.TSK_FS_META_TYPE_REG = 1
        mock_pytsk3.TSK_FS_NAME_FLAG_ALLOC = 1
        mock_pytsk3.TSK_VS_PART_FLAG_ALLOC = 1

        mock_part = MagicMock()
        mock_part.flags = 1
        mock_part.start = 2048
        mock_vol = MagicMock()
        mock_vol.block_size = 512
        mock_vol.__iter__.return_value = [mock_part]

        mock_pytsk3.Volume_Info.return_value = mock_vol
        mock_pytsk3.FS_Info.return_value = mock_fs

        workspace = os.path.join(self.temp_dir, "case_workspace")
        os.makedirs(workspace, exist_ok=True)

        with patch("parsers.ewf_adapter.open_ewf_image", return_value=mock_img_info), \
             patch("parsers.enterprise_1tb_chat_and_container_engine.open_ewf_image", return_value=mock_img_info), \
             patch.dict("sys.modules", {"pytsk3": mock_pytsk3}):

            engine = TerabyteForensicContainerEngine(dummy_e01, workspace)
            out_dir = engine.index_and_materialize_targets()

            self.assertEqual(out_dir, engine.extracted_dbs_dir)
            mock_img_info.close.assert_called()

            # Verify vfs_catalog.db
            cat_conn = sqlite3.connect(engine.catalog_db_path)
            rows = cat_conn.execute("SELECT vfs_path, container_format, file_name, file_size, is_materialized, local_disk_path FROM vfs_files ORDER BY file_name").fetchall()
            cat_conn.close()

            self.assertEqual(len(rows), 2)
            # Row 0: evidence_photo.jpg (not materialized)
            jpg_row = next(r for r in rows if r[2] == "evidence_photo.jpg")
            self.assertEqual(jpg_row[1], "E01")
            self.assertEqual(jpg_row[4], 0)  # is_materialized == 0
            self.assertEqual(jpg_row[5], "")  # local_disk_path empty

            # Row 1: msgstore.db (materialized)
            db_row = next(r for r in rows if r[2] == "msgstore.db")
            self.assertEqual(db_row[1], "E01")
            self.assertEqual(db_row[4], 1)  # is_materialized == 1
            self.assertTrue(os.path.exists(db_row[5]))
            with open(db_row[5], "rb") as f:
                self.assertEqual(f.read(), sqlite_data)

            # Test extract_attachment_on_demand for evidence_photo.jpg
            extracted_media = engine.extract_attachment_on_demand(jpg_row[0])
            self.assertIsNotNone(extracted_media)
            self.assertTrue(os.path.exists(extracted_media))
            with open(extracted_media, "rb") as f:
                self.assertEqual(f.read(), jpg_data)


if __name__ == "__main__":
    unittest.main()
