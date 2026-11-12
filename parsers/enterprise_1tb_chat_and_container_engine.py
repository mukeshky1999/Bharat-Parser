"""
Enterprise 1 TB+ Forensic Chat, Privacy, Social & Container Engine.
Zero-OOM streaming ingestion for UFDR, XRY, Oxygen & raw images,
with SQLite FTS5 artifact store, mmap freelist carver, and the 28-column canonical chat schema.
"""

from __future__ import annotations

import binascii
import json
import mmap
import os
import re
import shutil
import sqlite3
import struct
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union

import pandas as pd

from parsers.app_overrides import normalize_timestamp_value
from parsers.freelist_carver import (
    STANDARD_TX_COLUMNS,
    decode_record_payload,
    parse_page_unallocated_cells,
    read_varint,
)
from parsers.protobuf_decoder import decode_protobuf_stream
from parsers.ewf_adapter import (
    open_ewf_image,
    stream_tsk_file_chunks,
    walk_pytsk3_directory,
)

# ==============================================================================
# 1. TIMEZONE & CONSTANTS
# ==============================================================================

IST = timezone(timedelta(hours=5, minutes=30))
_COCOA_OFFSET_SECONDS = 978307200  # Seconds between 1970-01-01 and 2001-01-01
_WEBKIT_OFFSET_SECONDS = 11644473600  # Seconds between 1601-01-01 and 1970-01-01

# 28-column canonical chat schema
CHAT_COLUMNS: List[str] = [
    # Category 1 — Message & Artifact Details
    'Application',
    'Message_ID',
    'Thread_ID',
    'Chat_Type',
    'Direction',
    'Message_Type',
    'Delivery_Status',
    'Message_Body',
    'Quoted_Message_ID',
    'Quoted_Text',
    'Forwarding_Score',
    # Category 2 — Party & Participant Details
    'Thread_Title',
    'Sender_Name',
    'Sender_Identifier',
    'Recipient_Name',
    'Recipient_Identifier',
    'Participant_Bio_Meta',
    # Category 3 — Privacy & Ephemeral Flags
    'Is_View_Once',
    'Disappearing_TTL_Sec',
    'Is_Revoked_Deleted',
    # Category 4 — Multi-Format Timestamps (Court Verification Triplet)
    'Raw_Timestamp_Value',
    'Timestamp_UTC',
    'Timestamp_IST',
    'Read_Timestamp_IST',
    # Category 5 — Attachments & Geolocation
    'Attachment_Path_or_URL',
    'Attachment_MIME_Size',
    'Geo_Coordinates',
    # Category 6 — Forensic Source Provenance
    'Forensic_Provenance',
]

FORENSIC_TARGET_EXTENSIONS: Tuple[str, ...] = (
    '.db', '.sqlite', '.sqlite3', '.db-wal', '.sqlite-wal', '.wal',
    '.db-journal', '.db-shm', '.plist', '.xml', '.preferences_pb', '.pb',
    '.ldb', '.log', '.sst', '.realm', '.hive', '.isar', '.crypt14', '.crypt15',
    '.trace', '.conf', '.xry', '.json',
)

FORENSIC_TARGET_FILENAMES: Set[str] = {
    'key', 'keychain-2.db', 'keychain.db', 'mmssms.db', 'bugle_db',
    'msgstore.db', 'chatstorage.sqlite', 'wa.db', 'cache4.db', 'tgdata.db',
    'arroyo.db', 'tcspahn.db', 'direct.db', 'reverb.db', 'signal.db',
    'signal.sqlite', 'zangi.db', 'zangi.sqlite', 'matrix-sdk.db',
    'session.db', 'threema.db', 'tinder-3.db', 'chatdatabase.db',
    'hinge.db', 'grindr.db', 'report.xml', 'deviceinfo.xml', 'extraction.xml',
    'notification_log.db', 'notifs.db', 'fcm_queued_messages.db', 'user_dict.db',
}

BULK_MEDIA_EXTENSIONS: Tuple[str, ...] = (
    '.mp4', '.mov', '.avi', '.mkv', '.3gp', '.jpg', '.jpeg', '.png',
    '.webp', '.heic', '.raw', '.so', '.odex', '.vdex', '.apk', '.iso',
)

# ==============================================================================
# 2. READ-ONLY SQLITE & FORENSIC HELPERS
# ==============================================================================

def _open_ro_sqlite(db_path: str) -> Optional[sqlite3.Connection]:
    """
    Opens an SQLite database in strictly immutable read-only mode using URI format.
    """
    if not os.path.exists(db_path) or os.path.isdir(db_path):
        return None
    try:
        norm_path = os.path.abspath(db_path).replace('\\', '/')
        uri = f"file:{norm_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        # Never fall back to a read-write open: evidence must not be modified.
        return None


def _get_tables(conn: sqlite3.Connection) -> Dict[str, str]:
    """
    Returns a case-insensitive map of table_name.lower() -> actual_table_name.
    """
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')")
        return {r[0].lower(): r[0] for r in cur.fetchall()}
    except Exception:
        return {}


def _get_columns(conn: sqlite3.Connection, table_name: str) -> Set[str]:
    """
    Returns all column names of a table in lowercase.
    """
    try:
        cur = conn.cursor()
        cur.execute(f'PRAGMA table_info("{table_name}")')
        return {r[1].lower() for r in cur.fetchall()}
    except Exception:
        return set()


def _empty_pa_row(
    app: str,
    source_file: str,
    table_name: str,
    row_id: Any,
    offset_info: str = '',
    recovery_state: str = 'Allocated B-Tree',
) -> Dict[str, Any]:
    """
    Initializes a full 28-column chat row with forensic provenance.
    A byte offset is only stated when a real one is known (C-09); otherwise table + rowid only.
    """
    bname = os.path.basename(source_file)
    real_offset = offset_info if re.fullmatch(r'0x[0-9A-Fa-f]+', str(offset_info or '')) else ''
    prov = f"{bname} :: {source_file} :: {table_name} :: RowID={row_id}"
    if real_offset:
        prov += f" :: Offset={real_offset}"
    prov += f" :: State={recovery_state}"
    return {
        'Application': app,
        'Message_ID': str(row_id if row_id is not None else ''),
        'Thread_ID': '',
        'Chat_Type': 'Direct (1-on-1)',
        'Direction': 'Unknown',
        'Message_Type': 'Text',
        'Delivery_Status': 'Unknown',
        'Message_Body': '',
        'Quoted_Message_ID': '',
        'Quoted_Text': '',
        'Forwarding_Score': '0',
        'Thread_Title': '',
        'Sender_Name': '',
        'Sender_Identifier': '',
        'Recipient_Name': '',
        'Recipient_Identifier': '',
        'Participant_Bio_Meta': '',
        'Is_View_Once': False,
        'Disappearing_TTL_Sec': 0,
        'Is_Revoked_Deleted': False,
        'Raw_Timestamp_Value': None,
        'Timestamp_UTC': '',
        'Timestamp_IST': '',
        'Read_Timestamp_IST': '',
        'Attachment_Path_or_URL': '',
        'Attachment_MIME_Size': '',
        'Geo_Coordinates': '',
        'Forensic_Provenance': prov,
    }


def format_timestamp_triplet(
    raw_val: Any, epoch_hint: str = 'auto'
) -> Tuple[Any, str, str]:
    """
    Converts stored timestamps into the Court Verification Triplet:
    (Raw_Timestamp_Value, Timestamp_UTC, Timestamp_IST [+05:30]).
    Supports Unix sec/ms/us/ns, Cocoa/CoreData seconds, and WebKit microseconds.
    """
    if raw_val is None or str(raw_val).strip() in ('', 'None', 'null', 'nan', '0', '-1'):
        return None, '', ''

    norm_epoch = epoch_hint
    if norm_epoch in ('cocoa_sec', 'cocoa'):
        norm_epoch = 'cocoa'
    elif norm_epoch in ('unix_s', 'unix_sec'):
        norm_epoch = 'unix_s'
    elif norm_epoch in ('unix_ms', 'unix_milli'):
        norm_epoch = 'unix_ms'
    elif norm_epoch in ('unix_us', 'unix_micro'):
        norm_epoch = 'unix_us'

    # Special handling for WebKit microseconds (epoch 1601-01-01)
    try:
        num = float(raw_val)
        if norm_epoch == 'webkit' or (norm_epoch == 'auto' and num > 11644473600000000):
            unix_sec = (num / 1e6) - _WEBKIT_OFFSET_SECONDS
            if 1420070400 <= unix_sec <= 2051222400:
                dt_utc = datetime.fromtimestamp(unix_sec, tz=timezone.utc)
                dt_ist = dt_utc.astimezone(IST)
                return (
                    raw_val,
                    dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    dt_ist.strftime('%Y-%m-%d %H:%M:%S IST (+05:30)'),
                )
    except Exception:
        pass

    iso_str = normalize_timestamp_value(raw_val, epoch=norm_epoch)
    if not iso_str:
        return raw_val, str(raw_val), str(raw_val)

    try:
        dt = datetime.strptime(iso_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        dt_ist = dt.astimezone(IST)
        return (
            raw_val,
            dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
            dt_ist.strftime('%Y-%m-%d %H:%M:%S IST (+05:30)'),
        )
    except Exception:
        return raw_val, iso_str, iso_str


# ==============================================================================
# 3. PART A: THE 1 TB+ UFDR, XRY & OXYGEN FORENSIC STREAMING ENGINE
# ==============================================================================

def should_materialize_artifact(vfs_path: str, file_size: int) -> bool:
    """
    Returns True if an entry inside a 1 TB+ archive is a database, WAL, keystore,
    shared_prefs XML, plist, or LevelDB/MMKV store required for deep parsing.
    Skips 99% of bulk video/media files during triage.
    """
    if file_size <= 0 or file_size > 35 * 1024 * 1024 * 1024:  # Cap single DB at 35 GB
        return False
    p_norm = '/' + vfs_path.replace('\\', '/').lower().lstrip('/')
    bname = os.path.basename(p_norm)

    if bname in FORENSIC_TARGET_FILENAMES:
        return True

    # Check structural Android / iOS app storage directories
    if any(k in p_norm for k in ('/databases/', '/shared_prefs/', '/files/mmkv/', '/keychains/', 'mmkv')):
        if not bname.endswith(BULK_MEDIA_EXTENSIONS):
            return True

    if p_norm.endswith(FORENSIC_TARGET_EXTENSIONS):
        return True

    return False


class TerabyteForensicContainerEngine:
    """
    Manages 1 TB to 1.5 TB extractions (.ufdr, .xry, .ofb, .tar, .zip, .bin, .e01, .ex01, .l01) without OOM.
    - Indexes file metadata into `vfs_catalog.db`.
    - Selectively streams forensic DBs into `workspace/extracted_dbs/`.
    - Streams single attachments on demand into `workspace/on_demand_media/`.
    """

    def __init__(self, archive_or_dump_path: str, workspace_dir: str):
        self.archive_path = os.path.abspath(archive_or_dump_path)
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.extracted_dbs_dir = os.path.join(self.workspace_dir, 'extracted_dbs')
        self.on_demand_media_dir = os.path.join(self.workspace_dir, 'on_demand_media')
        self.catalog_db_path = os.path.join(self.workspace_dir, 'vfs_catalog.db')

        self.rejected_entries: List[str] = []
        self._used_targets: Dict[str, str] = {}

        os.makedirs(self.extracted_dbs_dir, exist_ok=True)
        os.makedirs(self.on_demand_media_dir, exist_ok=True)
        self._init_catalog_db()

    def _safe_extract_target(self, vpath: str, idx: int) -> Optional[str]:
        """
        Maps an archive member path to a file under ``extracted_dbs``.
        Rejects traversal (``..``, drive letters) and never reuses a stale file; names that
        collide case-insensitively get a unique ``.<index>`` suffix.
        """
        parts = [p for p in vpath.replace('\\', '/').split('/') if p not in ('', '.')]
        if not parts or any(p == '..' or ':' in p for p in parts):
            return None
        parts = [re.sub(r'[<>:"|?*]', '_', p) for p in parts]
        base = os.path.abspath(self.extracted_dbs_dir)
        target = os.path.abspath(os.path.join(base, *parts))
        if os.path.commonpath([base, target]) != base:
            return None
        key = target.lower()
        if key in self._used_targets and self._used_targets[key] != vpath:
            target = f"{target}.{idx}"
            key = target.lower()
        self._used_targets[key] = vpath
        if os.path.exists(target):
            os.remove(target)
        return target

    def _init_catalog_db(self) -> None:
        conn = sqlite3.connect(self.catalog_db_path)
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vfs_files (
                    vfs_path TEXT PRIMARY KEY,
                    container_format TEXT,
                    file_name TEXT,
                    file_size INTEGER,
                    archive_offset INTEGER,
                    is_materialized INTEGER DEFAULT 0,
                    local_disk_path TEXT
                );
            """)
            conn.execute('CREATE INDEX IF NOT EXISTS idx_vfs_name ON vfs_files(file_name);')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_vfs_path ON vfs_files(vfs_path);')
            conn.commit()
        finally:
            conn.close()

    def index_and_materialize_targets(
        self, progress_cb: Optional[Callable[[int, int, str], None]] = None
    ) -> str:
        """
        Scans through the archive, records metadata in `vfs_catalog.db`,
        and streams high-value forensic databases to disk with 8 MB chunks.
        """
        p_low = self.archive_path.lower()
        conn = sqlite3.connect(self.catalog_db_path)
        cur = conn.cursor()
        batch: List[Tuple[str, str, str, int, int, int, str]] = []

        try:
            # 1. ZIP / UFDR / UFD Containers
            if p_low.endswith(('.zip', '.ufdr', '.ufd', '.xry', '.ofb')) and zipfile.is_zipfile(self.archive_path):
                container_fmt = 'UFDR' if p_low.endswith(('.ufdr', '.ufd')) else ('XRY' if p_low.endswith('.xry') else 'ZIP')
                with zipfile.ZipFile(self.archive_path, 'r') as zf:
                    infolist = zf.infolist()
                    total = len(infolist)
                    for idx, info in enumerate(infolist):
                        if info.is_dir():
                            continue
                        vpath = info.filename
                        fsize = info.file_size
                        bname = os.path.basename(vpath)
                        local_out = ''
                        materialized = 0

                        if should_materialize_artifact(vpath, fsize):
                            local_out = self._safe_extract_target(vpath, idx) or ''
                            if local_out:
                                os.makedirs(os.path.dirname(local_out), exist_ok=True)
                                with zf.open(info, 'r') as src, open(local_out, 'wb') as dst:
                                    shutil.copyfileobj(src, dst, length=8 * 1024 * 1024)
                                materialized = 1
                            else:
                                self.rejected_entries.append(vpath)

                        batch.append((vpath, container_fmt, bname, fsize, info.header_offset, materialized, local_out))
                        if len(batch) >= 5000:
                            cur.executemany(
                                'INSERT OR REPLACE INTO vfs_files VALUES (?,?,?,?,?,?,?)', batch
                            )
                            conn.commit()
                            batch.clear()
                        if progress_cb and idx % 2500 == 0:
                            progress_cb(idx, total, vpath)

            # 2. TAR / TAR.GZ / TGZ Containers
            elif p_low.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2')):
                with tarfile.open(self.archive_path, 'r:*') as tf:
                    idx = 0
                    for member in tf:
                        idx += 1
                        if not member.isfile():
                            continue
                        vpath = member.name
                        fsize = member.size
                        bname = os.path.basename(vpath)
                        local_out = ''
                        materialized = 0

                        if should_materialize_artifact(vpath, fsize):
                            local_out = self._safe_extract_target(vpath, idx) or ''
                            if local_out:
                                os.makedirs(os.path.dirname(local_out), exist_ok=True)
                                src = tf.extractfile(member)
                                if src:
                                    with src, open(local_out, 'wb') as dst:
                                        shutil.copyfileobj(src, dst, length=8 * 1024 * 1024)
                                materialized = 1
                            else:
                                self.rejected_entries.append(vpath)

                        batch.append((vpath, 'TAR', bname, fsize, member.offset, materialized, local_out))
                        if len(batch) >= 5000:
                            cur.executemany(
                                'INSERT OR REPLACE INTO vfs_files VALUES (?,?,?,?,?,?,?)', batch
                            )
                            conn.commit()
                            batch.clear()
                        if progress_cb and idx % 2500 == 0:
                            progress_cb(idx, 0, vpath)

            # 3. Expert Witness Forensic Disk Images (.E01, .Ex01, .L01)
            elif p_low.endswith(('.e01', '.ex01', '.l01')):
                try:
                    import pytsk3
                except ImportError:
                    pytsk3 = None

                img_info = open_ewf_image(self.archive_path)
                try:
                    partitions: List[int] = []
                    if pytsk3 is not None and hasattr(pytsk3, 'Volume_Info'):
                        try:
                            volume_info = pytsk3.Volume_Info(img_info)
                            alloc_flag = getattr(pytsk3, 'TSK_VS_PART_FLAG_ALLOC', 1)
                            for part in volume_info:
                                if getattr(part, 'flags', 0) & alloc_flag:
                                    block_sz = getattr(volume_info, 'block_size', 512)
                                    partitions.append(part.start * block_sz)
                        except Exception:
                            partitions = [0]
                    if not partitions:
                        partitions = [0]

                    idx = 0
                    for part_offset in partitions:
                        if pytsk3 is None or not hasattr(pytsk3, 'FS_Info'):
                            break
                        try:
                            fs_info = pytsk3.FS_Info(img_info, offset=part_offset)
                        except Exception:
                            continue

                        try:
                            root_dir = fs_info.open_dir(path='/')
                        except Exception:
                            continue

                        for vpath, entry in walk_pytsk3_directory(fs_info, root_dir, '/'):
                            idx += 1
                            meta = getattr(entry.info, 'meta', None)
                            fsize = getattr(meta, 'size', 0) if meta else 0
                            bname = os.path.basename(vpath)
                            inode = getattr(meta, 'addr', 0) if meta else 0
                            local_out = ''
                            materialized = 0

                            if should_materialize_artifact(vpath, fsize):
                                local_out = self._safe_extract_target(vpath, idx) or ''
                                if local_out:
                                    os.makedirs(os.path.dirname(local_out), exist_ok=True)
                                    stream_tsk_file_chunks(entry, local_out, chunk_size=8 * 1024 * 1024)
                                    materialized = 1
                                else:
                                    self.rejected_entries.append(vpath)

                            batch.append((vpath, 'E01', bname, fsize, inode, materialized, local_out))
                            if len(batch) >= 5000:
                                cur.executemany(
                                    'INSERT OR REPLACE INTO vfs_files VALUES (?,?,?,?,?,?,?)', batch
                                )
                                conn.commit()
                                batch.clear()
                            if progress_cb and idx % 2500 == 0:
                                progress_cb(idx, 0, vpath)
                finally:
                    img_info.close()

            # 4. Monolithic Raw Disk Image (.dd, .bin, .raw, .img)
            elif os.path.isfile(self.archive_path):
                bname = os.path.basename(self.archive_path)
                fsize = os.path.getsize(self.archive_path)
                batch.append((self.archive_path, 'RAW', bname, fsize, 0, 1, self.archive_path))

            if batch:
                cur.executemany('INSERT OR REPLACE INTO vfs_files VALUES (?,?,?,?,?,?,?)', batch)
                conn.commit()
        finally:
            conn.close()

        return self.extracted_dbs_dir

    def extract_attachment_on_demand(self, vfs_path: str) -> Optional[str]:
        """
        Streams a single media file from the 1 TB container on demand when clicked in the UI.
        """
        conn = sqlite3.connect(self.catalog_db_path)
        try:
            row = conn.execute(
                'SELECT vfs_path, local_disk_path FROM vfs_files WHERE vfs_path = ? OR vfs_path LIKE ? LIMIT 1',
                (vfs_path, f'%{vfs_path[-48:]}%'),
            ).fetchone()
        finally:
            conn.close()

        if not row:
            return None

        actual_vpath, existing_local = row
        if existing_local and os.path.exists(existing_local):
            return existing_local

        out_path = os.path.join(self.on_demand_media_dir, os.path.basename(actual_vpath))
        if os.path.exists(out_path):
            return out_path

        p_low = self.archive_path.lower()
        if p_low.endswith(('.zip', '.ufdr', '.ufd', '.xry', '.ofb')) and zipfile.is_zipfile(self.archive_path):
            with zipfile.ZipFile(self.archive_path, 'r') as zf:
                try:
                    with zf.open(actual_vpath, 'r') as src, open(out_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst, length=4 * 1024 * 1024)
                    return out_path
                except Exception:
                    return None

        elif p_low.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2')):
            with tarfile.open(self.archive_path, 'r:*') as tf:
                try:
                    member = tf.getmember(actual_vpath)
                    src = tf.extractfile(member)
                    if src:
                        with src, open(out_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst, length=4 * 1024 * 1024)
                        return out_path
                except Exception:
                    return None

        elif p_low.endswith(('.e01', '.ex01', '.l01')):
            try:
                import pytsk3
            except ImportError:
                pytsk3 = None

            if pytsk3 is None:
                return None

            img_info = open_ewf_image(self.archive_path)
            try:
                partitions = []
                try:
                    vol = pytsk3.Volume_Info(img_info)
                    alloc_flag = getattr(pytsk3, 'TSK_VS_PART_FLAG_ALLOC', 1)
                    for p in vol:
                        if getattr(p, 'flags', 0) & alloc_flag:
                            partitions.append(p.start * getattr(vol, 'block_size', 512))
                except Exception:
                    partitions = [0]
                if not partitions:
                    partitions = [0]

                for part_offset in partitions:
                    try:
                        fs_info = pytsk3.FS_Info(img_info, offset=part_offset)
                        file_obj = None
                        try:
                            file_obj = fs_info.open(actual_vpath)
                        except Exception:
                            cand_path = '/' + actual_vpath.lstrip('/')
                            try:
                                file_obj = fs_info.open(cand_path)
                            except Exception:
                                pass

                        if file_obj is not None:
                            meta = getattr(file_obj.info, 'meta', None)
                            fsize = getattr(meta, 'size', 0) if meta else 0
                            offset = 0
                            chunk_size = 4 * 1024 * 1024
                            with open(out_path, 'wb') as dst:
                                while offset < fsize:
                                    to_read = min(chunk_size, fsize - offset)
                                    chunk = file_obj.read_random(offset, to_read)
                                    if not chunk:
                                        break
                                    dst.write(chunk)
                                    offset += len(chunk)
                            return out_path
                    except Exception:
                        continue
            finally:
                img_info.close()

        return None


def stream_container_xml_manifest(
    xml_path: str, batch_size: int = 5000
) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Streams multi-GB Cellebrite `report.xml`, Oxygen, and XRY XML manifests using
    ET.iterparse in O(1) memory (<25 MB RAM). Clears elements immediately after batching.
    """
    if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
        return

    batch: List[Dict[str, Any]] = []
    root = None

    try:
        with open(xml_path, 'rb') as f:
            context = ET.iterparse(f, events=('start', 'end'))
            for event, elem in context:
                if event == 'start' and root is None:
                    root = elem
                    continue

                if event == 'end':
                    tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    if tag in ('model', 'item', 'record', 'artifact', 'message', 'call', 'contact'):
                        m_type = elem.attrib.get('type') or tag
                        record: Dict[str, Any] = {
                            '_model_type': m_type,
                            '_id': elem.attrib.get('id', ''),
                            '_deleted_state': elem.attrib.get('deleted_state', 'Intact'),
                        }
                        for child in elem.iter():
                            if child is elem:
                                continue
                            c_name = child.attrib.get('name') or child.tag.split('}')[-1]
                            c_val = child.attrib.get('value') or (child.text.strip() if child.text else '')
                            if c_name and c_val:
                                record[c_name] = c_val

                        batch.append(record)
                        elem.clear()

                        if len(batch) >= batch_size:
                            yield batch
                            batch = []
                            if root is not None:
                                root.clear()

            if batch:
                yield batch
    except Exception:
        if batch:
            yield batch


def scan_raw_image_sliding_window(
    image_path: str,
    chunk_size: int = 16 * 1024 * 1024,
    overlap: int = 64 * 1024,
) -> Generator[Dict[str, Any], None, None]:
    """
    16 MB sliding-window binary carver for raw dumps (.bin, .dd, .img) with 64 KB overlap.
    Detects embedded SQLite DBs, WAL streams, NPCI UPI URIs, and Matrix events.
    """
    if not os.path.exists(image_path):
        return

    file_size = os.path.getsize(image_path)
    if file_size < 16:
        return

    step = chunk_size - overlap
    alloc_gran = mmap.ALLOCATIONGRANULARITY
    with open(image_path, 'rb') as f:
        curr_offset = 0
        seen_offsets: set = set()
        while curr_offset < file_size:
            aligned_offset = (curr_offset // alloc_gran) * alloc_gran
            delta = curr_offset - aligned_offset
            w_len = min(chunk_size + delta, file_size - aligned_offset)
            with mmap.mmap(f.fileno(), length=w_len, offset=aligned_offset, access=mmap.ACCESS_READ) as mm:
                window = mm[delta : delta + min(chunk_size, file_size - curr_offset)]

                # 1. Detect SQLite databases (Magic: 'SQLite format 3\x00') with overlap deduplication
                for m in re.finditer(rb'SQLite format 3\x00', window):
                    start = m.start()
                    glob_off = curr_offset + start
                    if glob_off in seen_offsets:
                        continue
                    seen_offsets.add(glob_off)
                    if start + 32 <= len(window):
                        ps = int.from_bytes(window[start + 16 : start + 18], 'big')
                        if ps == 1:
                            ps = 65536
                        pc = int.from_bytes(window[start + 28 : start + 32], 'big')
                        if ps in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                            yield {
                                'type': 'sqlite_db',
                                'global_offset': glob_off,
                                'physical_offset_hex': f"0x{glob_off:016X}",
                                'page_size': ps,
                                'page_count': pc,
                                'byte_size': ps * pc if pc > 0 else 0,
                            }

                # 2. Detect WAL frames (Magic: 0x377f0682 or 0x377f0683)
                for wal_magic in (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83'):
                    for m in re.finditer(re.escape(wal_magic), window):
                        glob_off = curr_offset + m.start()
                        if glob_off in seen_offsets:
                            continue
                        seen_offsets.add(glob_off)
                        yield {
                            'type': 'sqlite_wal',
                            'global_offset': glob_off,
                            'physical_offset_hex': f"0x{glob_off:016X}",
                        }

                # 3. Detect NPCI UPI payment URIs
                for m in re.finditer(rb'upi://pay\?[^\s"\'<>]{10,256}', window):
                    glob_off = curr_offset + m.start()
                    if glob_off in seen_offsets:
                        continue
                    seen_offsets.add(glob_off)
                    try:
                        uri_val = m.group(0).decode('utf-8', errors='ignore')
                        yield {
                            'type': 'npci_upi_uri',
                            'global_offset': glob_off,
                            'physical_offset_hex': f"0x{glob_off:016X}",
                            'uri': uri_val,
                        }
                    except Exception:
                        pass

                # 4. Detect Matrix Room Event JSON streams
                for m in re.finditer(rb'"m\.room\.(?:message|encrypted)"', window):
                    start_idx = window.rfind(b'{', max(0, m.start() - 500), m.start())
                    if start_idx != -1:
                        brace_count = 0
                        end_idx = -1
                        scan_limit = min(len(window), start_idx + 4096)
                        for pos in range(start_idx, scan_limit):
                            if window[pos:pos+1] == b'{':
                                brace_count += 1
                            elif window[pos:pos+1] == b'}':
                                brace_count -= 1
                                if brace_count == 0:
                                    end_idx = pos
                                    break
                        if end_idx != -1:
                            raw_chunk = window[start_idx : end_idx + 1]
                            glob_off = curr_offset + start_idx
                            if glob_off in seen_offsets:
                                continue
                            seen_offsets.add(glob_off)
                            try:
                                ev_json = raw_chunk.decode('utf-8', errors='ignore')
                                yield {
                                    'type': 'matrix_event',
                                    'global_offset': glob_off,
                                    'physical_offset_hex': f"0x{glob_off:016X}",
                                    'payload': ev_json,
                                }
                            except Exception:
                                pass

            curr_offset += step


def carve_sqlite_freelists_1tb_mmap(
    db_path: str,
    allow_crypto_addresses: bool = False,
    max_pages_to_scan: int = 250000,
) -> pd.DataFrame:
    """
    1 TB-safe mmap freelist carver. Slices one page buffer at a time to prevent OOM
    when scanning multi-gigabyte WhatsApp / Telegram SQLite databases.
    """
    if not os.path.exists(db_path):
        return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

    file_size = os.path.getsize(db_path)
    if file_size < 100:
        return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

    carved_records: List[Dict[str, Any]] = []
    try:
        with open(db_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                if mm[:16] != b'SQLite format 3\x00':
                    return pd.DataFrame(columns=STANDARD_TX_COLUMNS)

                page_size = int.from_bytes(mm[16:18], byteorder='big')
                if page_size == 1:
                    page_size = 65536
                elif page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                    page_size = 4096

                first_trunk = int.from_bytes(mm[32:36], byteorder='big')
                total_free = int.from_bytes(mm[36:40], byteorder='big')
                freelist_pages: List[int] = []
                curr = first_trunk

                # Traverse freelist trunk and leaf pointers
                while curr != 0 and len(freelist_pages) < min(total_free, 50000):
                    freelist_pages.append(curr)
                    t_off = (curr - 1) * page_size
                    if t_off + 8 > file_size:
                        break
                    next_t = int.from_bytes(mm[t_off : t_off + 4], byteorder='big')
                    leaf_cnt = int.from_bytes(mm[t_off + 4 : t_off + 8], byteorder='big')
                    for i in range(min(leaf_cnt, page_size // 4)):
                        p_off = t_off + 8 + (i * 4)
                        if p_off + 4 <= file_size:
                            l_pg = int.from_bytes(mm[p_off : p_off + 4], byteorder='big')
                            if l_pg != 0:
                                freelist_pages.append(l_pg)
                    curr = next_t

                # Carve unallocated cells from all Freelist pages
                for pg_num in set(freelist_pages):
                    pg_off = (pg_num - 1) * page_size
                    if pg_off + page_size <= file_size:
                        pg_slice = mm[pg_off : pg_off + page_size]
                        carved_records.extend(
                            parse_page_unallocated_cells(
                                pg_slice,
                                pg_num,
                                include_active_cells=True,
                                allow_crypto_addresses=allow_crypto_addresses,
                            )
                        )

                # Scan active leaf pages (0x0D or Page 1) for cell slack
                total_pages = min(file_size // page_size, max_pages_to_scan)
                free_set = set(freelist_pages)
                for p in range(1, total_pages + 1):
                    if p in free_set:
                        continue
                    pg_off = (p - 1) * page_size
                    first_b = mm[pg_off] if pg_off < file_size else 0
                    if first_b == 0x0D or p == 1:
                        pg_slice = mm[pg_off : pg_off + page_size]
                        carved_records.extend(
                            parse_page_unallocated_cells(
                                pg_slice,
                                p,
                                include_active_cells=False,
                                allow_crypto_addresses=allow_crypto_addresses,
                            )
                        )
    except Exception:
        pass

    if carved_records:
        df = pd.DataFrame(carved_records)
        for col in STANDARD_TX_COLUMNS:
            if col not in df.columns:
                df[col] = ''
        return df.drop_duplicates(
            subset=['Counterparty', 'Transaction_ID', 'Amount']
        )[STANDARD_TX_COLUMNS]
    return pd.DataFrame(columns=STANDARD_TX_COLUMNS)


# ==============================================================================
# 4. ON-DISK SQLITE FTS5 CASE ARTIFACT STORE (60 FPS PAGINATION)
# ==============================================================================

class CaseArtifactStore:
    """
    On-disk SQLite + FTS5 artifact store for rapid 60 FPS UI pagination across
    millions of carved transactions, chats, and dating profiles.
    """

    def __init__(self, store_db_path: str):
        self.store_db_path = os.path.abspath(store_db_path)
        os.makedirs(os.path.dirname(self.store_db_path), exist_ok=True)
        self._init_store()

    def _init_store(self) -> None:
        conn = sqlite3.connect(self.store_db_path)
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')

            # 1. Chats table (28 PA Columns)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Application TEXT,
                    Message_ID TEXT,
                    Thread_ID TEXT,
                    Chat_Type TEXT,
                    Direction TEXT,
                    Message_Type TEXT,
                    Delivery_Status TEXT,
                    Message_Body TEXT,
                    Quoted_Message_ID TEXT,
                    Quoted_Text TEXT,
                    Forwarding_Score TEXT,
                    Thread_Title TEXT,
                    Sender_Name TEXT,
                    Sender_Identifier TEXT,
                    Recipient_Name TEXT,
                    Recipient_Identifier TEXT,
                    Participant_Bio_Meta TEXT,
                    Is_View_Once INTEGER,
                    Disappearing_TTL_Sec INTEGER,
                    Is_Revoked_Deleted INTEGER,
                    Raw_Timestamp_Value TEXT,
                    Timestamp_UTC TEXT,
                    Timestamp_IST TEXT,
                    Read_Timestamp_IST TEXT,
                    Attachment_Path_or_URL TEXT,
                    Attachment_MIME_Size TEXT,
                    Geo_Coordinates TEXT,
                    Forensic_Provenance TEXT
                );
            """)

            # FTS5 for full-text search on chats
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS chats_fts USING fts5(
                    Message_Body,
                    Sender_Name,
                    Sender_Identifier,
                    Recipient_Name,
                    Recipient_Identifier,
                    Thread_Title,
                    Application,
                    content='chats',
                    content_rowid='id'
                );
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_chats_ai AFTER INSERT ON chats BEGIN
                    INSERT INTO chats_fts(rowid, Message_Body, Sender_Name, Sender_Identifier, Recipient_Name, Recipient_Identifier, Thread_Title, Application)
                    VALUES (new.id, new.Message_Body, new.Sender_Name, new.Sender_Identifier, new.Recipient_Name, new.Recipient_Identifier, new.Thread_Title, new.Application);
                END;
            """)

            # 2. Transactions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp TEXT,
                    Counterparty TEXT,
                    Amount REAL,
                    Type TEXT,
                    Status TEXT,
                    Transaction_ID TEXT,
                    VPA TEXT,
                    Account TEXT,
                    Source_File TEXT,
                    Source_Table TEXT,
                    Recovery_State TEXT,
                    Byte_Offset TEXT,
                    Raw_Row TEXT
                );
            """)

            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS transactions_fts USING fts5(
                    Counterparty,
                    Transaction_ID,
                    VPA,
                    Account,
                    content='transactions',
                    content_rowid='id'
                );
            """)

            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_transactions_ai AFTER INSERT ON transactions BEGIN
                    INSERT INTO transactions_fts(rowid, Counterparty, Transaction_ID, VPA, Account)
                    VALUES (new.id, new.Counterparty, new.Transaction_ID, new.VPA, new.Account);
                END;
            """)

            # 3. Contacts / Matches Dossier table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Contact_Name TEXT,
                    Identifier TEXT,
                    Application TEXT,
                    Source_File TEXT
                );
            """)

            conn.commit()
        finally:
            conn.close()

    def insert_chat_batch(self, df_chunk: pd.DataFrame) -> None:
        """Inserts a chunk of chats into SQLite & updates FTS5 index automatically."""
        if df_chunk is None or df_chunk.empty:
            return
        conn = sqlite3.connect(self.store_db_path)
        try:
            cols = [c for c in CHAT_COLUMNS if c in df_chunk.columns]
            placeholders = ','.join(['?'] * len(cols))
            col_names = ','.join(cols)
            records = [
                tuple(
                    (1 if v is True else (0 if v is False else (str(v) if pd.notna(v) else '')))
                    for v in r
                )
                for r in df_chunk[cols].itertuples(index=False, name=None)
            ]
            conn.executemany(f'INSERT INTO chats ({col_names}) VALUES ({placeholders})', records)
            conn.commit()
        finally:
            conn.close()

    def insert_transaction_batch(self, df_chunk: pd.DataFrame) -> None:
        """Inserts a chunk of transactions into SQLite & updates FTS5 index automatically."""
        if df_chunk is None or df_chunk.empty:
            return
        conn = sqlite3.connect(self.store_db_path)
        try:
            cols = [c for c in STANDARD_TX_COLUMNS if c in df_chunk.columns]
            placeholders = ','.join(['?'] * len(cols))
            col_names = ','.join(cols)
            records = [
                tuple(r) for r in df_chunk[cols].itertuples(index=False, name=None)
            ]
            conn.executemany(f'INSERT INTO transactions ({col_names}) VALUES ({placeholders})', records)
            conn.commit()
        finally:
            conn.close()

    def insert_contacts_batch(self, df_chunk: pd.DataFrame) -> None:
        """Inserts a chunk of recovered contacts into SQLite."""
        if df_chunk is None or df_chunk.empty:
            return
        conn = sqlite3.connect(self.store_db_path)
        try:
            cols = [c for c in ('Contact_Name', 'Identifier', 'Application', 'Source_File') if c in df_chunk.columns]
            if not cols:
                return
            placeholders = ','.join(['?'] * len(cols))
            col_names = ','.join(cols)
            records = [
                tuple(r) for r in df_chunk[cols].itertuples(index=False, name=None)
            ]
            conn.executemany(f'INSERT INTO contacts ({col_names}) VALUES ({placeholders})', records)
            conn.commit()
        finally:
            conn.close()

    def query_paginated_artifacts(
        self,
        category: str,
        app_filter: str = '',
        recovery_filter: str = '',
        search_query: str = '',
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Fast paginated query returning (page_records, total_matching_count) at 60 FPS.
        """
        conn = sqlite3.connect(self.store_db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        table = 'chats' if category.lower() in ('chats', 'chat', 'messages') else 'transactions'
        where_clauses: List[str] = []
        params: List[Any] = []

        if search_query.strip():
            fts_table = f"{table}_fts"
            where_clauses.append(f"{table}.id IN (SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ?)")
            params.append(search_query.strip())

        if app_filter.strip():
            if table == 'chats':
                where_clauses.append("Application LIKE ?")
            else:
                where_clauses.append("Source_File LIKE ?")
            params.append(f"%{app_filter.strip()}%")

        if recovery_filter.strip():
            if table == 'chats':
                where_clauses.append("Forensic_Provenance LIKE ?")
            else:
                where_clauses.append("Recovery_State LIKE ?")
            params.append(f"%{recovery_filter.strip()}%")

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        try:
            count_cur = conn.cursor()
            count_cur.execute(f"SELECT COUNT(*) FROM {table}{where_sql}", params)
            total_count = count_cur.fetchone()[0]

            query_sql = f"SELECT * FROM {table}{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
            cur.execute(query_sql, params + [limit, offset])
            rows = [dict(r) for r in cur.fetchall()]
            return rows, total_count
        finally:
            conn.close()


# ==============================================================================
# 5. PART C: ALL 14 CHAT, PRIVACY, SOCIAL & DATING PARSERS (CURSOR-CHUNKED)
# ==============================================================================

# ------------------------------------------------------------------------------
# 5.1 TELEGRAM TL STREAM DESERIALIZER & PARSER
# ------------------------------------------------------------------------------

def read_tl_string(buf: bytes, offset: int) -> Tuple[str, int]:
    """
    Parses a Telegram binary TL (Type Language) string according to the MTProto spec.
    """
    if offset >= len(buf):
        return '', offset
    first_b = buf[offset]
    if first_b < 254:
        str_len = first_b
        start = offset + 1
        end = start + str_len
        if end > len(buf):
            return '', len(buf)
        raw = buf[start:end]
        total_len = 1 + str_len
        padding = (4 - (total_len % 4)) % 4
        next_off = offset + total_len + padding
        try:
            return raw.decode('utf-8', errors='ignore'), next_off
        except Exception:
            return '', next_off
    elif first_b == 254:
        if offset + 4 > len(buf):
            return '', len(buf)
        str_len = buf[offset + 1] | (buf[offset + 2] << 8) | (buf[offset + 3] << 16)
        start = offset + 4
        end = start + str_len
        if end > len(buf):
            return '', len(buf)
        raw = buf[start:end]
        total_len = 4 + str_len
        padding = (4 - (total_len % 4)) % 4
        next_off = offset + total_len + padding
        try:
            return raw.decode('utf-8', errors='ignore'), next_off
        except Exception:
            return '', next_off
    else:
        return '', offset + 1


def deserialize_telegram_tl_blob(blob: bytes) -> Dict[str, Any]:
    """
    Walks a Telegram TL binary BLOB (`messages_v2.data`, `users.data`, `chats.data`)
    recovering constructor IDs, text messages, media URLs, phone numbers, and usernames.
    """
    res: Dict[str, Any] = {
        'constructor_id': 0,
        'strings': [],
        'phone': '',
        'username': '',
        'caption': '',
        'text': '',
        'reply_text': '',
    }
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 4:
        return res

    res['constructor_id'] = struct.unpack('<I', blob[:4])[0]
    offset = 4
    str_list: List[str] = []

    # Read strings sequentially from TL structure
    while offset < min(len(blob), 4096):
        s, next_off = read_tl_string(blob, offset)
        if s and len(s.strip()) > 0:
            clean_s = s.strip()
            str_list.append(clean_s)
            if re.match(r'^\+?[1-9]\d{8,14}$', clean_s):
                res['phone'] = clean_s
            elif clean_s.startswith('@') or (len(clean_s) <= 32 and re.match(r'^[A-Za-z0-9_]{3,32}$', clean_s)):
                if not res['username']:
                    res['username'] = clean_s.lstrip('@')
        if next_off <= offset:
            offset += 4
        else:
            offset = next_off

    # Additional heuristic scan for UTF-8 fragments
    for frag in re.finditer(rb'[\x20-\x7E]{3,}', blob):
        try:
            txt = frag.group(0).decode('utf-8', errors='ignore').strip()
            if txt and txt not in str_list and len(txt) > 2:
                str_list.append(txt)
        except Exception:
            pass

    res['strings'] = str_list
    candidates = [s for s in str_list if len(s) > 1 and s != res['phone'] and s != res['username']]
    if candidates:
        res['text'] = max(candidates, key=len)
    return res


def parse_telegram_cache4(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Telegram `cache4.db`, `telegram.db`, and `tgdata.db` using cursor chunking.
    Extracts Secret Chats (E2EE), group messages, channels, and contacts.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []
    user_map: Dict[str, Dict[str, str]] = {}
    chat_map: Dict[str, str] = {}
    enc_map: Dict[str, int] = {}  # enc_id -> ttl

    try:
        cur = conn.cursor()

        # 1. Harvest users
        u_tbl = tables.get('users')
        if u_tbl:
            cols = _get_columns(conn, u_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{u_tbl}"')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    uid = str(r.get('uid') or r.get('id') or r.get('_rowid') or '')
                    name = str(r.get('name') or r.get('first_name') or '').strip()
                    uname = str(r.get('username') or '').strip()
                    phone = ''
                    if 'data' in r and isinstance(r['data'], (bytes, bytearray)):
                        tl_u = deserialize_telegram_tl_blob(r['data'])
                        phone = tl_u.get('phone', '')
                        if not uname:
                            uname = tl_u.get('username', '')

                    user_map[uid] = {'name': name or f"User_{uid}", 'uname': uname, 'phone': phone}
                    if name or uname or phone:
                        contacts.append({
                            'Contact_Name': name or f"@{uname}",
                            'Identifier': f"Telegram_UID:{uid}" + (f" [@{uname}]" if uname else "") + (f" [{phone}]" if phone else ""),
                            'Application': 'Telegram',
                            'Source_File': db_path,
                        })

        # 2. Harvest chats & channels
        c_tbl = tables.get('chats')
        if c_tbl:
            cols = _get_columns(conn, c_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{c_tbl}"')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    cid = str(r.get('uid') or r.get('id') or r.get('_rowid') or '')
                    title = str(r.get('name') or r.get('title') or '').strip()
                    chat_map[cid] = title or f"TG Chat {cid}"

        # 3. Harvest encrypted secret chats
        e_tbl = tables.get('enc_chats')
        if e_tbl:
            cols = _get_columns(conn, e_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{e_tbl}"')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    eid = str(r.get('uid') or r.get('id') or r.get('_rowid') or '')
                    ttl = int(r.get('ttl') or 0)
                    enc_map[eid] = ttl

        # 4. Harvest messages via cursor chunking
        m_tbl = tables.get('messages_v2') or tables.get('messages')
        if m_tbl:
            m_cols = _get_columns(conn, m_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{m_tbl}" ORDER BY rowid DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('mid') or r.get('id') or r.get('_rowid') or 0
                    uid = str(r.get('uid') or '')
                    date_val = r.get('date')
                    out_val = int(r.get('out') or 0)
                    raw_data = r.get('data')

                    body = ''
                    attach_url = ''
                    if isinstance(raw_data, (bytes, bytearray)):
                        tl_m = deserialize_telegram_tl_blob(raw_data)
                        body = tl_m.get('text', '')
                        for s in tl_m.get('strings', []):
                            if any(ext in s.lower() for ext in ('.jpg', '.png', '.mp4', '.ogg', '.opus', 'http://', 'https://')):
                                attach_url = s
                                break

                    # Check reply data
                    reply_text = ''
                    reply_id = ''
                    if 'replydata' in r and isinstance(r['replydata'], (bytes, bytearray)):
                        tl_r = deserialize_telegram_tl_blob(r['replydata'])
                        reply_text = tl_r.get('text', '')

                    is_secret = (uid in enc_map) or ('enc' in m_tbl)
                    u_info = user_map.get(uid, {'name': f"Telegram_{uid}", 'uname': '', 'phone': ''})
                    title = chat_map.get(uid) or u_info['name']

                    row = _empty_pa_row('Telegram', db_path, m_tbl, mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = uid
                    row['Chat_Type'] = 'Secret Chat (E2EE)' if is_secret else ('Group Chat' if uid in chat_map else 'Direct (1-on-1)')
                    row['Direction'] = 'Outgoing' if out_val == 1 else 'Incoming'
                    row['Message_Type'] = 'Text' if not attach_url else ('Voice Note' if '.ogg' in attach_url.lower() or '.opus' in attach_url.lower() else 'Media')
                    row['Message_Body'] = body or ('[Encrypted Secret Chat Frame]' if is_secret else '[Telegram Message]')
                    row['Quoted_Message_ID'] = reply_id
                    row['Quoted_Text'] = reply_text
                    row['Thread_Title'] = title
                    row['Sender_Name'] = 'Owner' if out_val == 1 else u_info['name']
                    row['Sender_Identifier'] = f"Telegram_UID:{uid}" + (f" [@{u_info['uname']}]" if u_info['uname'] else "")
                    row['Disappearing_TTL_Sec'] = enc_map.get(uid, 0)
                    row['Attachment_Path_or_URL'] = attach_url

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(date_val, epoch_hint='unix_s')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.2 WHATSAPP & WHATSAPP BUSINESS FULL FORENSIC PARSER
# ------------------------------------------------------------------------------

def parse_whatsapp_full_forensics(
    db_path: str,
    wa_contacts_db_path: Optional[str] = None,
    owner_identifiers: Optional[Set[str]] = None,
    **kwargs: Any,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses WhatsApp Android `msgstore.db` (v1-v24 multi-table join) and iOS `ChatStorage.sqlite`.
    Decodes View-Once, disappearing messages, call logs, and WhatsApp UPI payments.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []

    try:
        cur = conn.cursor()

        # ----------------- ANDROID MSGSTORE.DB -----------------
        if 'message' in tables:
            m_cols = _get_columns(conn, tables['message'])
            j_cols = _get_columns(conn, tables['jid']) if 'jid' in tables else set()
            c_cols = _get_columns(conn, tables['chat']) if 'chat' in tables else set()

            # Dynamic query building adapted to WhatsApp version schema
            join_clauses = ['FROM message m']
            select_cols = ['m.rowid AS m_rowid', 'm.*']

            if 'chat' in tables:
                join_clauses.append('LEFT JOIN chat c ON m.chat_row_id = c._id' if 'chat_row_id' in m_cols else '')
            if 'jid' in tables:
                if 'sender_jid_row_id' in m_cols:
                    join_clauses.append('LEFT JOIN jid j_sender ON m.sender_jid_row_id = j_sender._id')
                    select_cols.append('j_sender.raw_string AS sender_jid_str')
                if 'chat' in tables and 'jid_row_id' in c_cols:
                    join_clauses.append('LEFT JOIN jid j_chat ON c.jid_row_id = j_chat._id')
                    select_cols.append('j_chat.raw_string AS chat_jid_str')
            if 'message_quoted' in tables:
                join_clauses.append('LEFT JOIN message_quoted mq ON m._id = mq.message_row_id' if '_id' in m_cols else '')
                select_cols.append('mq.text_data AS quoted_body')
            if 'message_media' in tables:
                join_clauses.append('LEFT JOIN message_media mm ON m._id = mm.message_row_id' if '_id' in m_cols else '')
                select_cols.extend(['mm.file_path AS media_path', 'mm.mime_type AS media_mime', 'mm.file_length AS media_size', 'mm.file_hash AS media_hash'])
            if 'message_location' in tables:
                join_clauses.append('LEFT JOIN message_location ml ON m._id = ml.message_row_id' if '_id' in m_cols else '')
                select_cols.extend(['ml.latitude AS loc_lat', 'ml.longitude AS loc_lon', 'ml.place_name AS loc_place'])
            if 'message_ephemeral' in tables:
                join_clauses.append('LEFT JOIN message_ephemeral me ON m._id = me.message_row_id' if '_id' in m_cols else '')
                select_cols.append('me.expire_timestamp AS ephemeral_expire')
            if 'receipt_user' in tables and '_id' in m_cols:
                # Aggregate per message with a subquery: a join would emit one row per group
                # recipient. Only an actual read_timestamp counts as "read".
                ru_cols = _get_columns(conn, tables['receipt_user'])
                if 'read_timestamp' in ru_cols:
                    select_cols.append(
                        '(SELECT MIN(ru.read_timestamp) FROM receipt_user ru '
                        'WHERE ru.message_row_id = m._id AND ru.read_timestamp IS NOT NULL '
                        'AND ru.read_timestamp > 0) AS read_ts'
                    )

            full_sql = f"SELECT {', '.join(select_cols)} {' '.join([j for j in join_clauses if j])} ORDER BY m.rowid DESC"
            try:
                cur.execute(full_sql)
            except Exception:
                cur.execute('SELECT rowid AS m_rowid, * FROM message ORDER BY rowid DESC')

            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('key_id') or r.get('m_rowid') or 0
                    text = str(r.get('text_data') or r.get('data') or '').strip()
                    mtype = int(r.get('message_type') or 0)
                    from_me = int(r.get('from_me') if r.get('from_me') is not None else (r.get('key_from_me') or 0))
                    ts_raw = r.get('timestamp') or r.get('received_timestamp')

                    # Determine Type & Ephemeral Flags
                    is_view_once = (mtype in (42, 43))
                    is_revoked = (mtype in (15, 64))
                    mtype_desc = 'Text'
                    if is_view_once:
                        mtype_desc = 'View-Once Media'
                    elif is_revoked:
                        mtype_desc = 'Revoked/Deleted by Sender'
                    elif mtype == 1:
                        mtype_desc = 'Image'
                    elif mtype == 2:
                        mtype_desc = 'Voice Note'
                    elif mtype == 3:
                        mtype_desc = 'Video'
                    elif mtype == 5:
                        mtype_desc = 'Location Pin'
                    elif mtype == 55:
                        mtype_desc = 'UPI Payment'

                    sender = str(r.get('sender_jid_str') or r.get('key_remote_jid') or '')
                    chat_jid = str(r.get('chat_jid_str') or sender)
                    is_group = ('@g.us' in chat_jid)
                    if not sender and not is_group:
                        sender = chat_jid  # 1:1 chat: the counterpart is the chat JID
                    wa_status = r.get('status')

                    # Geolocation
                    geo = ''
                    if r.get('loc_lat') and r.get('loc_lon'):
                        geo = f"{r['loc_lat']}, {r['loc_lon']}" + (f" ({r['loc_place']})" if r.get('loc_place') else "")

                    # Attachment
                    media_path = str(r.get('media_path') or '')
                    media_mime = str(r.get('media_mime') or '')
                    media_size = str(r.get('media_size') or '')
                    media_hash = str(r.get('media_hash') or '')
                    mime_size_str = ' | '.join(x for x in (media_mime, f"{media_size}B" if media_size else '', media_hash) if x)

                    row = _empty_pa_row('WhatsApp', db_path, 'message', mid, f"RowID={r.get('m_rowid', mid)}")
                    row['Thread_ID'] = chat_jid
                    row['Chat_Type'] = 'Group Chat' if is_group else 'Direct (1-on-1)'
                    row['Direction'] = 'Outgoing' if from_me == 1 else 'Incoming'
                    row['Message_Type'] = mtype_desc
                    if from_me == 1:
                        if r.get('read_ts') or wa_status in (13, 14, 8):
                            delivery = 'Read'
                        elif wa_status == 5:
                            delivery = 'Delivered'
                        elif wa_status in (4, 6):
                            delivery = 'Sent'
                        elif wa_status == 0:
                            delivery = 'Pending/Unsent'
                        else:
                            delivery = 'Unknown'
                    else:
                        delivery = 'Received'
                    row['Delivery_Status'] = delivery
                    row['Message_Body'] = text or f"[{mtype_desc}]"
                    row['Quoted_Text'] = str(r.get('quoted_body') or '')
                    row['Thread_Title'] = chat_jid.split('@')[0]
                    row['Sender_Identifier'] = 'Owner' if from_me == 1 else sender
                    row['Recipient_Identifier'] = chat_jid if from_me == 1 else 'Owner'
                    row['Is_View_Once'] = is_view_once
                    row['Is_Revoked_Deleted'] = is_revoked
                    row['Disappearing_TTL_Sec'] = int(r.get('ephemeral_expire') or 0)
                    row['Attachment_Path_or_URL'] = media_path
                    row['Attachment_MIME_Size'] = mime_size_str
                    row['Geo_Coordinates'] = geo

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_raw, epoch_hint='unix_ms')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts

                    if r.get('read_ts'):
                        _, _, read_ist = format_timestamp_triplet(r['read_ts'], epoch_hint='unix_ms')
                        row['Read_Timestamp_IST'] = read_ist

                    rows.append(row)

            # ----------------- HARVEST WHATSAPP CALL LOGS -----------------
            if 'call_log' in tables:
                try:
                    cur.execute("""
                        SELECT cl.rowid AS cl_rowid, cl.*, j.raw_string AS peer_jid
                        FROM call_log cl
                        LEFT JOIN jid j ON cl.jid_row_id = j._id
                        ORDER BY cl.rowid DESC
                    """)
                    for cr_raw in cur.fetchall():
                        cr = dict(cr_raw)
                        cid = cr.get('call_id') or cr.get('cl_rowid') or 0
                        peer = str(cr.get('peer_jid') or '')
                        is_out = int(cr.get('from_me') or 0)
                        dur = int(cr.get('duration') or 0)
                        res_val = int(cr.get('call_result') or 0)
                        is_vid = int(cr.get('video_call') or 0)

                        c_row = _empty_pa_row('WhatsApp', db_path, 'call_log', cid, f"RowID={cr.get('cl_rowid', cid)}")
                        c_row['Thread_ID'] = peer
                        c_row['Direction'] = 'Outgoing' if is_out == 1 else 'Incoming'
                        c_row['Message_Type'] = 'VoIP Call'
                        c_row['Delivery_Status'] = 'Connected Call' if dur > 0 else 'Missed Call'
                        c_row['Message_Body'] = f"WhatsApp {'Video' if is_vid else 'Voice'} Call ({dur}s, Result={res_val})"
                        c_row['Sender_Identifier'] = 'Owner' if is_out == 1 else peer
                        c_row['Recipient_Identifier'] = peer if is_out == 1 else 'Owner'
                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(cr.get('timestamp'), epoch_hint='unix_ms')
                        c_row['Raw_Timestamp_Value'] = raw_ts
                        c_row['Timestamp_UTC'] = utc_ts
                        c_row['Timestamp_IST'] = ist_ts
                        rows.append(c_row)
                except Exception:
                    pass

        # ----------------- IOS CHATSTORAGE.SQLITE -----------------
        elif 'zwamessage' in tables:
            cur.execute("""
                SELECT zm.Z_PK, zm.ZTEXT, zm.ZMESSAGETYPE, zm.ZISFROMME, zm.ZMESSAGEDATE,
                       zs.ZCONTACTJID, zm.ZGROUPOWNER
                FROM ZWAMESSAGE zm
                LEFT JOIN ZWACHATSESSION zs ON zm.ZCHATSESSION = zs.Z_PK
                ORDER BY zm.Z_PK DESC
            """)
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    pk = r.get('Z_PK')
                    text = str(r.get('ZTEXT') or '').strip()
                    mtype = int(r.get('ZMESSAGETYPE') or 0)
                    from_me = int(r.get('ZISFROMME') or 0)
                    date_val = r.get('ZMESSAGEDATE')
                    jid = str(r.get('ZCONTACTJID') or '')

                    row = _empty_pa_row('WhatsApp', db_path, 'ZWAMESSAGE', pk, f"Z_PK={pk}")
                    row['Thread_ID'] = jid
                    row['Chat_Type'] = 'Group Chat' if '@g.us' in jid else 'Direct (1-on-1)'
                    row['Direction'] = 'Outgoing' if from_me == 1 else 'Incoming'
                    row['Message_Type'] = 'Text' if mtype == 0 else ('Media' if mtype in (1, 2, 3) else 'System')
                    row['Message_Body'] = text or f"[iOS WhatsApp Message type={mtype}]"
                    row['Thread_Title'] = jid.split('@')[0]
                    row['Sender_Identifier'] = 'Owner' if from_me == 1 else jid
                    row['Recipient_Identifier'] = jid if from_me == 1 else 'Owner'

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(date_val, epoch_hint='cocoa')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        # ----------------- HARVEST CONTACTS (WA.DB) -----------------
        c_conn = conn
        if wa_contacts_db_path and os.path.exists(wa_contacts_db_path):
            c_conn = _open_ro_sqlite(wa_contacts_db_path) or conn

        c_tables = _get_tables(c_conn)
        if 'wa_contacts' in c_tables:
            c_cur = c_conn.cursor()
            c_cur.execute('SELECT jid, display_name, phone_number, status FROM wa_contacts LIMIT 10000')
            for cr_raw in c_cur.fetchall():
                cr = dict(cr_raw)
                jid = str(cr.get('jid') or '')
                dname = str(cr.get('display_name') or '').strip()
                phone = str(cr.get('phone_number') or '').strip()
                status = str(cr.get('status') or '').strip()
                contacts.append({
                    'Contact_Name': dname or phone or jid.split('@')[0],
                    'Identifier': f"WhatsApp_JID:{jid}" + (f" [{phone}]" if phone else "") + (f" (About: {status[:40]})" if status else ""),
                    'Application': 'WhatsApp',
                    'Source_File': wa_contacts_db_path or db_path,
                })
        if c_conn != conn:
            c_conn.close()

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.3 SNAPCHAT ARROYO & PROTOBUF PARSER
# ------------------------------------------------------------------------------

def parse_snapchat_arroyo(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Snapchat `arroyo.db` (`conversation_message` table) with raw Protobuf
    decoding. Recovers disappearing snaps, stickers, audio notes, and friends.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []
    friend_map: Dict[str, Dict[str, str]] = {}

    try:
        cur = conn.cursor()

        # 1. Harvest friends from main.db / tcspahn.db if present in same directory
        dir_name = os.path.dirname(db_path)
        for cand_name in ('main.db', 'tcspahn.db'):
            cand_p = os.path.join(dir_name, cand_name)
            if os.path.exists(cand_p):
                f_conn = _open_ro_sqlite(cand_p)
                if f_conn:
                    f_tables = _get_tables(f_conn)
                    if 'friend' in f_tables:
                        f_cur = f_conn.cursor()
                        f_cur.execute('SELECT * FROM friend LIMIT 5000')
                        for fr_raw in f_cur.fetchall():
                            fr = dict(fr_raw)
                            uid = str(fr.get('userId') or '')
                            uname = str(fr.get('username') or '')
                            dname = str(fr.get('displayName') or '')
                            phone = str(fr.get('phone') or '')
                            friend_map[uid] = {'name': dname or uname, 'uname': uname, 'phone': phone}
                            contacts.append({
                                'Contact_Name': dname or uname,
                                'Identifier': f"Snapchat_UID:{uid} [@{uname}]" + (f" [{phone}]" if phone else ""),
                                'Application': 'Snapchat',
                                'Source_File': cand_p,
                            })
                    f_conn.close()

        # 2. Harvest messages from arroyo.db
        if 'conversation_message' in tables:
            m_cols = _get_columns(conn, tables['conversation_message'])
            cur.execute('SELECT rowid AS _rowid, * FROM conversation_message ORDER BY creation_timestamp DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('client_conversation_id') or r.get('client_message_id') or r.get('_rowid') or 0
                    conv_id = str(r.get('conversation_id') or '')
                    sender_id = str(r.get('sender_id') or '')
                    ctype = int(r.get('content_type') or 1)
                    raw_content = r.get('message_content')
                    ts_create = r.get('creation_timestamp')
                    ts_read = r.get('read_timestamp')

                    body = ''
                    media_url = ''
                    if isinstance(raw_content, (bytes, bytearray)):
                        pb = decode_protobuf_stream(raw_content)
                        if pb:
                            # Extract strings and URLs from nested protobuf wire structures
                            def _walk_pb(d: Any):
                                nonlocal body, media_url
                                if isinstance(d, dict):
                                    for v_list in d.values():
                                        if isinstance(v_list, list):
                                            for item in v_list:
                                                _walk_pb(item)
                                elif isinstance(d, str):
                                    clean = d.strip()
                                    if clean.startswith(('http://', 'https://')):
                                        media_url = clean
                                    elif len(clean) > len(body) and not clean.startswith('{'):
                                        body = clean

                            _walk_pb(pb)

                    is_snap = (ctype == 0)
                    mdesc = 'Disappearing Snap' if is_snap else ('Audio Note' if ctype == 4 else ('Media/Sticker' if ctype == 2 else 'Text'))
                    f_info = friend_map.get(sender_id, {'name': f"Snapchat_{sender_id[:8]}", 'uname': '', 'phone': ''})

                    row = _empty_pa_row('Snapchat', db_path, 'conversation_message', mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = conv_id
                    row['Thread_Title'] = f_info['name']
                    row['Sender_Name'] = f_info['name']
                    row['Sender_Identifier'] = f"Snapchat_UID:{sender_id}" + (f" [@{f_info['uname']}]" if f_info['uname'] else "")
                    row['Message_Type'] = mdesc
                    row['Is_View_Once'] = is_snap
                    row['Message_Body'] = body or f"[Snapchat {mdesc}]"
                    row['Attachment_Path_or_URL'] = media_url

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_create, epoch_hint='unix_ms')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts

                    if ts_read:
                        _, _, read_ist = format_timestamp_triplet(ts_read, epoch_hint='unix_ms')
                        row['Read_Timestamp_IST'] = read_ist

                    rows.append(row)

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.4 SIGNAL PRIVATE MESSENGER PARSER
# ------------------------------------------------------------------------------

def parse_signal_database(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Android `signal.db` and iOS `signal.sqlite`.
    Decodes bitmask types (incoming/outgoing), disappearing timers, and attachments.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []
    recip_map: Dict[str, Dict[str, str]] = {}

    try:
        cur = conn.cursor()

        # 1. Harvest recipients
        r_tbl = tables.get('recipient')
        if r_tbl:
            cols = _get_columns(conn, r_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{r_tbl}"')
            for r_raw in cur.fetchall():
                r = dict(r_raw)
                rid = str(r.get('_id') or r.get('id') or r.get('_rowid') or '')
                phone = str(r.get('e164') or r.get('phone') or '').strip()
                name = str(r.get('system_joined_name') or r.get('profile_given_name') or '').strip()
                aci = str(r.get('aci') or '')

                recip_map[rid] = {'name': name or phone or f"Signal_{rid}", 'phone': phone, 'aci': aci}
                if name or phone or aci:
                    contacts.append({
                        'Contact_Name': name or phone,
                        'Identifier': f"Signal_ID:{rid}" + (f" [{phone}]" if phone else "") + (f" (ACI: {aci[:16]})" if aci else ""),
                        'Application': 'Signal',
                        'Source_File': db_path,
                    })

        # 2. Harvest messages (Android message / mms / sms)
        m_tbl = tables.get('message') or tables.get('mms') or tables.get('sms')
        if m_tbl:
            cols = _get_columns(conn, m_tbl)
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{m_tbl}" ORDER BY date_sent DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('_id') or r.get('id') or r.get('_rowid') or 0
                    type_val = int(r.get('type') or 0)
                    is_out = ((type_val & 0x1F) == 23)
                    body = str(r.get('body') or '').strip()
                    rid = str(r.get('recipient_id') or r.get('thread_id') or '')
                    ts_sent = r.get('date_sent') or r.get('date')
                    expires = int(r.get('expires_in') or 0)
                    if expires >= 1000:
                        expires = expires // 1000  # convert ms to seconds
                    view_once = bool(r.get('view_once') or False)

                    r_info = recip_map.get(rid, {'name': f"Signal_{rid}", 'phone': '', 'aci': ''})

                    row = _empty_pa_row('Signal', db_path, m_tbl, mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = rid
                    row['Direction'] = 'Outgoing' if is_out else 'Incoming'
                    row['Message_Body'] = body or ('[Signal View-Once Media]' if view_once else '[Signal Encrypted Payload]')
                    row['Thread_Title'] = r_info['name']
                    row['Sender_Name'] = 'Owner' if is_out else r_info['name']
                    row['Sender_Identifier'] = 'Owner' if is_out else f"Signal_ID:{rid} [{r_info['phone']}]"
                    row['Recipient_Identifier'] = f"Signal_ID:{rid} [{r_info['phone']}]" if is_out else 'Owner'
                    row['Is_View_Once'] = view_once
                    row['Disappearing_TTL_Sec'] = expires

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_sent, epoch_hint='unix_ms')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        # 3. iOS model_TSInteraction
        elif 'model_tsinteraction' in tables:
            cur.execute('SELECT rowid AS _rowid, * FROM model_TSInteraction ORDER BY timestamp DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('id') or r.get('_rowid') or 0
                    row = _empty_pa_row('Signal', db_path, 'model_TSInteraction', mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = str(r.get('uniqueThreadId') or '')
                    row['Message_Body'] = str(r.get('body') or '[iOS Signal Interaction]')
                    row['Disappearing_TTL_Sec'] = int(r.get('expiresInSeconds') or 0)
                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('timestamp'), epoch_hint='cocoa')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.5 ZANGI PRIVATE MESSENGER PARSER
# ------------------------------------------------------------------------------

def parse_zangi_database(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Zangi Private Messenger (Android `zangi.db` & iOS `Zangi.sqlite`).
    Extracts 10-digit Zangi IDs (`XX-XXXX-XXXX` or `91...`), CoreData entities, and calls.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []

    try:
        cur = conn.cursor()

        # 1. Android tables
        if 'messages' in tables:
            cur.execute('SELECT rowid AS _rowid, * FROM messages ORDER BY date DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('id') or r.get('_rowid') or 0
                    body = str(r.get('body') or '').strip()
                    is_out = int(r.get('is_outgoing') or 0)
                    sender_num = str(r.get('sender_number') or '')
                    date_val = r.get('date')

                    row = _empty_pa_row('Zangi Messenger', db_path, 'messages', mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = sender_num
                    row['Direction'] = 'Outgoing' if is_out == 1 else 'Incoming'
                    row['Message_Body'] = body or '[Zangi Message]'
                    row['Sender_Identifier'] = f"Zangi_ID:{sender_num}"
                    row['Thread_Title'] = f"Zangi ({sender_num})"
                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(date_val, epoch_hint='unix_ms')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        # 2. iOS CoreData tables (`ZMESSAGE`, `ZCONTACT`, `ZCALL`)
        elif 'zmessage' in tables:
            cur.execute('SELECT * FROM ZMESSAGE ORDER BY ZDATE DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    pk = r.get('Z_PK')
                    text = str(r.get('ZTEXT') or '').strip()
                    is_out = int(r.get('ZISOUTGOING') or 0)
                    znum = str(r.get('ZSENDERZANGINUMBER') or '')
                    date_val = r.get('ZDATE')

                    row = _empty_pa_row('Zangi Messenger', db_path, 'ZMESSAGE', pk, f"Z_PK={pk}")
                    row['Thread_ID'] = znum
                    row['Direction'] = 'Outgoing' if is_out == 1 else 'Incoming'
                    row['Message_Body'] = text or '[Zangi Encrypted CoreData Frame]'
                    row['Sender_Identifier'] = f"Zangi_ID:{znum}"
                    row['Thread_Title'] = f"Zangi ({znum})"
                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(date_val, epoch_hint='cocoa')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        if 'zcontact' in tables:
            cur.execute('SELECT * FROM ZCONTACT LIMIT 5000')
            for cr_raw in cur.fetchall():
                cr = dict(cr_raw)
                fn = str(cr.get('ZFIRSTNAME') or '').strip()
                ln = str(cr.get('ZLASTNAME') or '').strip()
                zn = str(cr.get('ZZANGINUMBER') or '').strip()
                contacts.append({
                    'Contact_Name': f"{fn} {ln}".strip() or f"Zangi {zn}",
                    'Identifier': f"Zangi_ID:{zn}",
                    'Application': 'Zangi Messenger',
                    'Source_File': db_path,
                })

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.6 ELEMENT / MATRIX SECURE MESSENGER PARSER
# ------------------------------------------------------------------------------

def parse_element_matrix_store(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Element/Matrix databases (`matrix-sdk.db`, `crypto_store.db`, `.realm`).
    Uses SQLite cursor queries and mmap regex scanning for Matrix JSON event streams.
    """
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []

    # 1. SQLite table parsing if valid DB
    conn = _open_ro_sqlite(db_path)
    if conn:
        tables = _get_tables(conn)
        for tbl_name in ('events', 'timeline_events', 'roomevents'):
            if tbl_name in tables:
                cur = conn.cursor()
                cur.execute(f'SELECT * FROM "{tables[tbl_name]}" ORDER BY rowid DESC')
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    for r in chunk:
                        eid = r['event_id'] if 'event_id' in r.keys() else r['rowid']
                        sender = str(r['sender'] if 'sender' in r.keys() and r['sender'] else '')
                        room = str(r['room_id'] if 'room_id' in r.keys() and r['room_id'] else '')
                        raw_json = r['json'] if 'json' in r.keys() and r['json'] else ''
                        body = ''
                        ts_val = r['origin_server_ts'] if 'origin_server_ts' in r.keys() else None

                        if raw_json and isinstance(raw_json, str):
                            try:
                                j = json.loads(raw_json)
                                content = j.get('content', {})
                                body = str(content.get('body') or content.get('ciphertext') or '')
                                if not ts_val:
                                    ts_val = j.get('origin_server_ts')
                            except Exception:
                                pass

                        row = _empty_pa_row('Element (Matrix)', db_path, tables[tbl_name], eid)
                        row['Thread_ID'] = room
                        row['Thread_Title'] = f"Matrix Room ({room})"
                        row['Sender_Identifier'] = sender
                        row['Message_Body'] = body or '[Matrix Event]'
                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='unix_ms')
                        row['Raw_Timestamp_Value'] = raw_ts
                        row['Timestamp_UTC'] = utc_ts
                        row['Timestamp_IST'] = ist_ts
                        rows.append(row)
                break
        conn.close()

    # 2. Fallback mmap regex carve on the file (works for SQLite slack and Realm files)
    if not rows and os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        try:
            with open(db_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for m in re.finditer(rb'\{[^{}\r\n]{0,2000}?"m\.room\.(?:message|encrypted)"[^{}\r\n]{0,4000}?\}', mm):
                        try:
                            ev = json.loads(m.group(0).decode('utf-8', errors='ignore'))
                            ev_type = ev.get('type', '')
                            sender = str(ev.get('sender') or '')
                            room_id = str(ev.get('room_id') or '')
                            ev_id = str(ev.get('event_id') or f"OFFSET_0x{m.start():X}")
                            content = ev.get('content', {}) if isinstance(ev.get('content'), dict) else {}
                            body = str(content.get('body') or content.get('ciphertext') or '[Megolm Encrypted Frame]')
                            url = str(content.get('url') or '')

                            row = _empty_pa_row('Element (Matrix)', db_path, 'MatrixEventStream', ev_id, f"0x{m.start():X}")
                            row['Thread_ID'] = room_id
                            row['Thread_Title'] = f"Matrix Room ({room_id})"
                            row['Sender_Identifier'] = sender
                            row['Message_Type'] = 'Megolm Encrypted' if 'encrypted' in ev_type else 'Text'
                            row['Message_Body'] = body[:4000]
                            row['Attachment_Path_or_URL'] = url
                            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ev.get('origin_server_ts'), epoch_hint='unix_ms')
                            row['Raw_Timestamp_Value'] = raw_ts
                            row['Timestamp_UTC'] = utc_ts
                            row['Timestamp_IST'] = ist_ts
                            rows.append(row)
                        except Exception:
                            continue
        except Exception:
            pass

    df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
    return df_chats, pd.DataFrame(contacts)


# ------------------------------------------------------------------------------
# 5.7 PRIVACY MESSENGERS: SESSION (05... ID), THREEMA & SIMPLEX CHAT
# ------------------------------------------------------------------------------

def parse_privacy_messengers(
    db_path: str, app_label: str = ''
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Session (66-char 05... hex IDs), Threema (NaCl IDs), and SimpleX Chat.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []
    app_detected = app_label or 'Privacy Messenger'

    try:
        cur = conn.cursor()

        # ----------------- SESSION MESSENGER -----------------
        if 'loki_user_display_name_database' in tables or 'session' in db_path.lower():
            app_detected = 'Session'
            m_tbl = tables.get('messages') or tables.get('sms') or tables.get('mms')
            if m_tbl:
                cur.execute(f'SELECT rowid AS _rowid, * FROM "{m_tbl}" ORDER BY date_sent DESC')
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    for r_raw in chunk:
                        r = dict(r_raw)
                        mid = r.get('id') or r.get('_rowid') or 0
                        body = str(r.get('body') or '').strip()
                        sender = str(r.get('address') or r.get('recipient_id') or '')
                        expires = int(r.get('expires_in') or 0)

                        row = _empty_pa_row('Session', db_path, m_tbl, mid, f"RowID={r.get('_rowid', mid)}")
                        row['Thread_ID'] = sender
                        row['Sender_Identifier'] = f"Session_ID:{sender}"
                        row['Thread_Title'] = f"Session ({sender[:10]}...)" if len(sender) > 10 else sender
                        row['Message_Body'] = body or '[Session E2EE Payload]'
                        row['Disappearing_TTL_Sec'] = expires // 1000 if expires >= 1000 else expires

                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('date_sent', r.get('date')), epoch_hint='unix_ms')
                        row['Raw_Timestamp_Value'] = raw_ts
                        row['Timestamp_UTC'] = utc_ts
                        row['Timestamp_IST'] = ist_ts
                        rows.append(row)

        # ----------------- THREEMA MESSENGER -----------------
        elif 'threema' in db_path.lower() or ('message' in tables and 'contact' in tables):
            app_detected = 'Threema'
            if 'contact' in tables:
                cur.execute('SELECT rowid AS _rowid, * FROM contact LIMIT 5000')
                for cr_raw in cur.fetchall():
                    cr = dict(cr_raw)
                    tid = str(cr.get('identity') or '')
                    fn = str(cr.get('first_name') or '')
                    contacts.append({
                        'Contact_Name': fn or f"Threema {tid}",
                        'Identifier': f"Threema_ID:{tid}",
                        'Application': 'Threema',
                        'Source_File': db_path,
                    })

            if 'message' in tables:
                cur.execute('SELECT rowid AS _rowid, * FROM message ORDER BY created_at DESC')
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    for r_raw in chunk:
                        r = dict(r_raw)
                        mid = r.get('id') or r.get('_rowid') or 0
                        tid = str(r.get('identity') or '')
                        body = str(r.get('body') or '').strip()
                        is_out = int(r.get('is_outbox') or 0)

                        row = _empty_pa_row('Threema', db_path, 'message', mid, f"RowID={r.get('_rowid', mid)}")
                        row['Thread_ID'] = tid
                        row['Sender_Identifier'] = 'Owner' if is_out == 1 else f"Threema_ID:{tid}"
                        row['Direction'] = 'Outgoing' if is_out == 1 else 'Incoming'
                        row['Message_Body'] = body or '[Threema Encrypted Message]'
                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('created_at'), epoch_hint='unix_ms')
                        row['Raw_Timestamp_Value'] = raw_ts
                        row['Timestamp_UTC'] = utc_ts
                        row['Timestamp_IST'] = ist_ts
                        rows.append(row)

        # ----------------- SIMPLEX CHAT -----------------
        elif 'simplex' in db_path.lower() or 'contact_profiles' in tables:
            app_detected = 'SimpleX Chat'
            m_tbl = tables.get('messages') or tables.get('chat_items')
            if m_tbl:
                cur.execute(f'SELECT rowid AS _rowid, * FROM "{m_tbl}" ORDER BY rowid DESC')
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    for r_raw in chunk:
                        r = dict(r_raw)
                        mid = r.get('id') or r.get('_rowid') or 0
                        body = str(r.get('msg_body') or r.get('text') or '').strip()
                        row = _empty_pa_row('SimpleX Chat', db_path, m_tbl, mid, f"RowID={r.get('_rowid', mid)}")
                        row['Message_Body'] = body or '[SimpleX Encrypted Message]'
                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('created_at'), epoch_hint='unix_ms')
                        row['Raw_Timestamp_Value'] = raw_ts
                        row['Timestamp_UTC'] = utc_ts
                        row['Timestamp_IST'] = ist_ts
                        rows.append(row)

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.8 INSTAGRAM DIRECT (`direct.db` / `reverb.db`)
# ------------------------------------------------------------------------------

def parse_instagram_direct(db_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Parses Instagram `direct.db` / `reverb.db`.
    Unpacks nested JSON BLOBs, Raven View-Once media, and voice notes.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []
    thread_map: Dict[str, str] = {}

    try:
        cur = conn.cursor()

        # 1. Harvest threads & participants
        t_tbl = tables.get('threads')
        if t_tbl:
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{t_tbl}" LIMIT 5000')
            for tr_raw in cur.fetchall():
                tr = dict(tr_raw)
                tid = str(tr.get('thread_id') or tr.get('thread_key') or tr.get('_rowid') or '')
                title = str(tr.get('thread_title') or '').strip()
                rec_json = tr.get('recipients') or tr.get('thread_info') or ''

                if isinstance(rec_json, str) and '{' in rec_json:
                    for um in re.finditer(r'"username"\s*:\s*"([^"]+)"', rec_json):
                        uname = um.group(1)
                        contacts.append({
                            'Contact_Name': uname,
                            'Identifier': f"Instagram:@{uname}",
                            'Application': 'Instagram Direct',
                            'Source_File': db_path,
                        })
                        if not title:
                            title = f"@{uname}"

                thread_map[tid] = title or f"IG Thread {tid[:10]}"

        # 2. Harvest messages
        m_tbl = tables.get('messages')
        if m_tbl:
            cur.execute(f'SELECT rowid AS _rowid, * FROM "{m_tbl}" ORDER BY timestamp DESC')
            while True:
                chunk = cur.fetchmany(5000)
                if not chunk:
                    break
                for r_raw in chunk:
                    r = dict(r_raw)
                    mid = r.get('item_id') or r.get('_id') or r.get('_rowid') or 0
                    tid = str(r.get('thread_key') or r.get('thread_id') or '')
                    uid = str(r.get('user_id') or r.get('sender_id') or '')
                    mtype = str(r.get('message_type') or 'text')
                    text = str(r.get('text') or '').strip()

                    media_url = ''
                    raw_json = r.get('message')
                    if isinstance(raw_json, str) and raw_json.startswith('{'):
                        try:
                            jobj = json.loads(raw_json)
                            if not text:
                                text = str(jobj.get('text') or jobj.get('reel_share', {}).get('text') or '')
                            media_url = str(
                                jobj.get('voice_media', {}).get('media', {}).get('audio', {}).get('audio_src')
                                or jobj.get('media', {}).get('image_versions2', {}).get('candidates', [{}])[0].get('url')
                                or ''
                            )
                        except Exception:
                            pass

                    is_view_once = ('raven' in mtype.lower())
                    if not text and not media_url and not is_view_once:
                        continue

                    row = _empty_pa_row('Instagram Direct', db_path, m_tbl, mid, f"RowID={r.get('_rowid', mid)}")
                    row['Thread_ID'] = tid
                    row['Thread_Title'] = thread_map.get(tid, f"IG Direct ({tid[:10]})")
                    row['Sender_Identifier'] = f"IG_UID:{uid}"
                    row['Message_Type'] = 'View-Once Raven Media' if is_view_once else mtype
                    row['Is_View_Once'] = is_view_once
                    row['Message_Body'] = text or f"[Instagram {mtype}]"
                    row['Attachment_Path_or_URL'] = media_url

                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('timestamp'), epoch_hint='unix_us')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(contacts).drop_duplicates() if contacts else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.9 DATING APPS: TINDER, BUMBLE, HINGE & GRINDR
# ------------------------------------------------------------------------------

def parse_dating_apps(
    db_path: str, app_label: str = ''
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Universal Dating App Deep Parser for Tinder, Bumble, Hinge, and Grindr.
    Extracts matches dossier (bio, age, linked Instagram/Spotify) and messages.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS), pd.DataFrame()

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []
    matches_dossier: List[Dict[str, str]] = []
    match_meta_map: Dict[str, Dict[str, str]] = {}
    actual_app = app_label or 'Dating App'

    try:
        cur = conn.cursor()

        # 1. Harvest Match Profiles
        for p_key in ('match_view', 'matches', 'person', 'users', 'profiles', 'connections'):
            if p_key in tables:
                tbl = tables[p_key]
                cur.execute(f'SELECT rowid AS _rowid, * FROM "{tbl}" LIMIT 10000')
                for pr_raw in cur.fetchall():
                    pr = dict(pr_raw)
                    pid = str(pr.get('id') or pr.get('user_id') or pr.get('match_id') or pr.get('_rowid') or '').strip()
                    pname = str(pr.get('person_name') or pr.get('name') or pr.get('first_name') or '').strip()
                    bio = str(pr.get('person_bio') or pr.get('bio') or pr.get('about_me') or '').strip()
                    ig = str(pr.get('instagram_username') or pr.get('instagram_handle') or '').strip()

                    meta_str = ' | '.join(x for x in (bio, f"IG:{ig}" if ig and ig != 'None' else '') if x and x != 'None')
                    if pid and pname and pname.lower() != 'none':
                        match_meta_map[pid] = {'name': pname, 'meta': meta_str[:300]}
                        matches_dossier.append({
                            'Contact_Name': f"{pname} ({actual_app} Match)",
                            'Identifier': f"{actual_app}_ID:{pid}" + (f" [{meta_str[:80]}]" if meta_str else ""),
                            'Application': actual_app,
                            'Source_File': db_path,
                        })

        # 2. Harvest Messages
        for m_key in ('message_view', 'messages', 'chat_message', 'chat_messages'):
            if m_key in tables:
                tbl = tables[m_key]
                cur.execute(f'SELECT rowid AS _rowid, * FROM "{tbl}" ORDER BY rowid DESC')
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    for r_raw in chunk:
                        r = dict(r_raw)
                        body = str(r.get('text') or r.get('body') or '').strip()
                        media = str(r.get('media_url') or '').strip()
                        if not body and not media:
                            continue

                        mid = r.get('id') or r.get('message_id') or r.get('_rowid') or 0
                        match_id = str(r.get('match_id') or r.get('conversation_id') or '')
                        sender_id = str(r.get('from_id') or r.get('sender_id') or '')
                        recip_id = str(r.get('to_id') or r.get('recipient_id') or '')

                        m_info = match_meta_map.get(match_id) or match_meta_map.get(sender_id) or {'name': f"{actual_app} Match {match_id[:8]}", 'meta': ''}

                        row = _empty_pa_row(actual_app, db_path, tbl, mid, f"RowID={r.get('_rowid', mid)}")
                        row['Thread_ID'] = match_id
                        row['Chat_Type'] = 'Dating Match'
                        row['Thread_Title'] = m_info['name']
                        row['Sender_Name'] = m_info['name'] if sender_id in match_meta_map else sender_id
                        row['Sender_Identifier'] = sender_id
                        row['Recipient_Identifier'] = recip_id
                        row['Participant_Bio_Meta'] = m_info['meta']
                        row['Message_Body'] = body or f"[{actual_app} Media]"
                        row['Attachment_Path_or_URL'] = media

                        # Grindr JSON location pin check ({"lat": ..., "lon": ...})
                        if body.startswith('{') and '"lat"' in body:
                            try:
                                loc_obj = json.loads(body)
                                if 'lat' in loc_obj and 'lon' in loc_obj:
                                    row['Geo_Coordinates'] = f"{loc_obj['lat']}, {loc_obj['lon']}"
                                    row['Message_Type'] = 'Location Pin'
                            except Exception:
                                pass

                        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(
                            r.get('sent_date') or r.get('created_timestamp') or r.get('timestamp'),
                            epoch_hint='auto',
                        )
                        row['Raw_Timestamp_Value'] = raw_ts
                        row['Timestamp_UTC'] = utc_ts
                        row['Timestamp_IST'] = ist_ts
                        rows.append(row)
                break

        df_chats = pd.DataFrame(rows, columns=CHAT_COLUMNS)
        df_contacts = pd.DataFrame(matches_dossier).drop_duplicates() if matches_dossier else pd.DataFrame(columns=['Contact_Name', 'Identifier', 'Application', 'Source_File'])
        return df_chats, df_contacts
    finally:
        conn.close()


# ------------------------------------------------------------------------------
# 5.10 OS PRIVACY & EPHEMERAL SPILLOVER HARVESTER
# ------------------------------------------------------------------------------

def harvest_os_privacy_spillover(db_path: str) -> pd.DataFrame:
    """
    Scans Android `notification_log.db`, `notifs.db`, and Gboard keyboard caches
    recovering push notifications & typed text for disappeared chat messages.
    """
    conn = _open_ro_sqlite(db_path)
    if not conn:
        return pd.DataFrame(columns=CHAT_COLUMNS)

    tables = _get_tables(conn)
    rows: List[Dict[str, Any]] = []

    TARGET_APPS = {
        'com.whatsapp': 'WhatsApp',
        'org.telegram.messenger': 'Telegram',
        'org.thoughtcrime.securesms': 'Signal',
        'com.beint.zangi': 'Zangi Messenger',
        'im.vector.app': 'Element (Matrix)',
        'network.loki.messenger': 'Session',
        'com.snapchat.android': 'Snapchat',
        'com.instagram.android': 'Instagram Direct',
        'com.tinder': 'Tinder',
        'com.bumble.app': 'Bumble',
        'co.hinge.app': 'Hinge',
        'com.grindrapp.android': 'Grindr',
    }

    try:
        cur = conn.cursor()
        for tbl in ('notifications', 'notification_log', 'notifs', 'messages'):
            if tbl in tables:
                cur.execute(f'SELECT rowid AS _rowid, * FROM "{tables[tbl]}" ORDER BY rowid DESC LIMIT 10000')
                for r_raw in cur.fetchall():
                    r = dict(r_raw)
                    pkg = str(r.get('package_name') or r.get('pkg') or '').lower()
                    app_name = next((v for k, v in TARGET_APPS.items() if k in pkg), None)
                    if not app_name:
                        continue

                    title = str(r.get('title') or '').strip()
                    text = str(r.get('text') or r.get('content') or '').strip()
                    if not text:
                        continue

                    mid = r.get('id') or r.get('_rowid') or 0
                    row = _empty_pa_row(app_name, db_path, tables[tbl], mid, f"RowID={r.get('_rowid', mid)}", recovery_state='OS Notification Spillover')
                    row['Message_Body'] = f"[Notification Spillover] {text}"
                    row['Sender_Name'] = title
                    row['Thread_Title'] = f"{app_name} Notification ({title})"
                    raw_ts, utc_ts, ist_ts = format_timestamp_triplet(r.get('post_time') or r.get('timestamp'), epoch_hint='auto')
                    row['Raw_Timestamp_Value'] = raw_ts
                    row['Timestamp_UTC'] = utc_ts
                    row['Timestamp_IST'] = ist_ts
                    rows.append(row)
                break

        return pd.DataFrame(rows, columns=CHAT_COLUMNS)
    finally:
        conn.close()


# ==============================================================================
# 6. PART D: MASTER DISPATCHER & INTEGRATION MANIFESTS
# ==============================================================================

def dispatch_all_chat_and_privacy_apps(
    db_path: str,
    app_label: str = '',
    wa_contacts_db_path: Optional[str] = None,
) -> Optional[Dict[str, pd.DataFrame]]:
    """
    Master Dispatcher: Inspects file name, table signatures, and app_label,
    routes to dedicated parser, appends WAL/Freelist carved rows, and returns
    {'chats': df_28_cols, 'contacts': df_contacts}.
    """
    bname = os.path.basename(db_path).lower()
    alow = (app_label or '').lower()

    # 1. Telegram
    if 'telegram' in alow or bname in ('cache4.db', 'tgdata.db', 'telegram.db'):
        ch, cnt = parse_telegram_cache4(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 2. WhatsApp
    if 'whatsapp' in alow or bname in ('msgstore.db', 'chatstorage.sqlite', 'wa.db'):
        ch, cnt = parse_whatsapp_full_forensics(db_path, wa_contacts_db_path=wa_contacts_db_path)
        return {'chats': ch, 'contacts': cnt}

    # 3. Snapchat
    if 'snapchat' in alow or bname in ('arroyo.db', 'tcspahn.db', 'memories.db'):
        ch, cnt = parse_snapchat_arroyo(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 4. Signal
    if 'signal' in alow or bname in ('signal.db', 'signal.sqlite'):
        ch, cnt = parse_signal_database(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 5. Zangi
    if 'zangi' in alow or 'zangi' in bname:
        ch, cnt = parse_zangi_database(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 6. Element / Matrix
    if 'element' in alow or 'matrix' in alow or 'matrix-sdk' in bname:
        ch, cnt = parse_element_matrix_store(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 7. Privacy Messengers (Session, Threema, SimpleX)
    if any(p in alow or p in bname for p in ('session', 'threema', 'simplex')):
        ch, cnt = parse_privacy_messengers(db_path, app_label=app_label)
        return {'chats': ch, 'contacts': cnt}

    # 8. Instagram Direct
    if 'instagram' in alow or bname in ('direct.db', 'reverb.db'):
        ch, cnt = parse_instagram_direct(db_path)
        return {'chats': ch, 'contacts': cnt}

    # 9. Dating Apps (Tinder, Bumble, Hinge, Grindr)
    if any(d in alow or d in bname for d in ('tinder', 'bumble', 'hinge', 'grindr')):
        ch, cnt = parse_dating_apps(db_path, app_label=app_label or bname.split('.')[0].title())
        return {'chats': ch, 'contacts': cnt}

    # 10. OS Privacy Spillover
    if bname in ('notification_log.db', 'notifs.db', 'fcm_queued_messages.db', 'user_dict.db'):
        ch = harvest_os_privacy_spillover(db_path)
        return {'chats': ch, 'contacts': pd.DataFrame()}

    return None


EXTENDED_CHAT_AND_PRIVACY_MANIFESTS: List[Dict[str, Any]] = [
    {
        'app_name': 'WhatsApp',
        'category': 'chat',
        'bundle_ids': ['net.whatsapp.WhatsApp', 'net.whatsapp.WhatsAppSMB'],
        'android_pkgs': ['com.whatsapp', 'com.whatsapp.w4b'],
        'aliases': ['whatsapp', 'msgstore.db', 'chatstorage.sqlite'],
    },
    {
        'app_name': 'Telegram',
        'category': 'chat',
        'bundle_ids': ['ph.telegra.Telegraph', 'org.telegram.Telegram-iOS'],
        'android_pkgs': ['org.telegram.messenger', 'org.telegram.messenger.web', 'org.telegram.plus'],
        'aliases': ['telegram', 'cache4.db', 'tgdata.db'],
    },
    {
        'app_name': 'Signal',
        'category': 'chat',
        'bundle_ids': ['org.whispersystems.signal'],
        'android_pkgs': ['org.thoughtcrime.securesms'],
        'aliases': ['signal', 'signal.db', 'signal.sqlite'],
    },
    {
        'app_name': 'Zangi Messenger',
        'category': 'chat',
        'bundle_ids': ['com.beint.zangi'],
        'android_pkgs': ['com.beint.zangi'],
        'aliases': ['zangi', 'zangi.db', 'zangi.sqlite'],
    },
    {
        'app_name': 'Element (Matrix)',
        'category': 'chat',
        'bundle_ids': ['im.vector.app'],
        'android_pkgs': ['im.vector.app', 'im.vector.alpha'],
        'aliases': ['element', 'matrix', 'vector', 'matrix-sdk.db'],
    },
    {
        'app_name': 'Session',
        'category': 'chat',
        'bundle_ids': ['com.loki-project.loki-messenger'],
        'android_pkgs': ['network.loki.messenger'],
        'aliases': ['session', 'loki', 'session.db'],
    },
    {
        'app_name': 'Threema',
        'category': 'chat',
        'bundle_ids': ['ch.threema.iapp'],
        'android_pkgs': ['ch.threema.app'],
        'aliases': ['threema', 'threema.db'],
    },
    {
        'app_name': 'SimpleX Chat',
        'category': 'chat',
        'bundle_ids': ['chat.simplex.app'],
        'android_pkgs': ['chat.simplex.app'],
        'aliases': ['simplex', 'simplex_v1_chat.db'],
    },
    {
        'app_name': 'Snapchat',
        'category': 'chat',
        'bundle_ids': ['com.toyopagroup.picaboo'],
        'android_pkgs': ['com.snapchat.android'],
        'aliases': ['snapchat', 'arroyo', 'arroyo.db'],
    },
    {
        'app_name': 'Instagram Direct',
        'category': 'chat',
        'bundle_ids': ['com.burbn.instagram'],
        'android_pkgs': ['com.instagram.android'],
        'aliases': ['instagram', 'direct.db', 'reverb.db'],
    },
    {
        'app_name': 'Tinder',
        'category': 'dating',
        'bundle_ids': ['com.cardify.tinder'],
        'android_pkgs': ['com.tinder'],
        'aliases': ['tinder', 'tinder-3.db'],
    },
    {
        'app_name': 'Bumble',
        'category': 'dating',
        'bundle_ids': ['com.mosocial.Bumble'],
        'android_pkgs': ['com.bumble.app'],
        'aliases': ['bumble', 'chatdatabase.db'],
    },
    {
        'app_name': 'Hinge',
        'category': 'dating',
        'bundle_ids': ['co.hinge.mobile.ios'],
        'android_pkgs': ['co.hinge.app'],
        'aliases': ['hinge', 'hinge.db'],
    },
    {
        'app_name': 'Grindr',
        'category': 'dating',
        'bundle_ids': ['com.grindr.ios'],
        'android_pkgs': ['com.grindrapp.android'],
        'aliases': ['grindr', 'grindr.db'],
    },
]

# End of enterprise_1tb_chat_and_container_engine.py
# Integration hooks for heuristic_engine.py and plugin_loader.py should be configured
# directly inside their respective modules rather than in host module docstrings.

