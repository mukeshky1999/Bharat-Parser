"""
Phase 5B.8: media in the case file.

What is recorded for each media file the case holds on disk
* SHA-256 and MD5 of the file (always).
* For images Pillow can open: width, height, format, the EXIF fields below, a 64-bit difference hash (dHash) and a
  small JPEG thumbnail kept in the case workspace.
* For video: the hashes and size only. No frame is decoded, and the record says so.

What the tool says about it
* Hash-set match: the file's SHA-256 or MD5 equals an entry of a list the examiner imported. That is an exact match
  on the value, nothing more. The tool ships no list of its own and does not say what a list means.
* Visual similarity: the dHash of two images differs in at most N bits. That is a lead. It does not show the images
  are the same picture, and a different picture can fall inside the distance.
* EXIF time is the camera's local clock with no zone, so it is stored as it was written and labelled as such. It
  is not converted and it is not placed on the timeline. A missing field stays NULL.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic")
VIDEO_EXTS = (".mp4", ".mov", ".3gp", ".avi", ".mkv", ".webm")
MAX_PIXELS = 100_000_000
MAX_SET_ENTRIES = 2_000_000
THUMB_SIDE = 256
SIMILAR_MAX_DISTANCE = 6
SET_KINDS = ("known_ignorable", "known_notable")

SCHEMA = """
CREATE TABLE IF NOT EXISTS media_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Evidence_Item TEXT,
    Vfs_Path TEXT NOT NULL,
    File_Name TEXT,
    File_Size INTEGER,
    Kind TEXT,
    SHA256 TEXT,
    MD5 TEXT,
    Width INTEGER,
    Height INTEGER,
    Format TEXT,
    Camera_Make TEXT,
    Camera_Model TEXT,
    Software TEXT,
    Exif_Clock TEXT,
    Gps_Lat REAL,
    Gps_Lon REAL,
    Exif_Json TEXT,
    DHash TEXT,
    Thumb_Path TEXT,
    Status TEXT NOT NULL,
    Status_Detail TEXT,
    Decoded_By TEXT,
    Analysed_At_UTC TEXT NOT NULL,
    UNIQUE(Evidence_Item, Vfs_Path)
);
CREATE INDEX IF NOT EXISTS idx_media_sha ON media_items(SHA256);
CREATE INDEX IF NOT EXISTS idx_media_md5 ON media_items(MD5);
CREATE TABLE IF NOT EXISTS hash_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Name TEXT NOT NULL UNIQUE,
    Kind TEXT NOT NULL,
    Entries INTEGER NOT NULL,
    Skipped_Lines INTEGER NOT NULL DEFAULT 0,
    Source_Note TEXT,
    Imported_At_UTC TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hash_set_entries (
    Set_Id INTEGER NOT NULL,
    Hash TEXT NOT NULL,
    PRIMARY KEY (Set_Id, Hash)
);
CREATE INDEX IF NOT EXISTS idx_hse_hash ON hash_set_entries(Hash);
"""


class MediaError(ValueError):
    """The request cannot be carried out; the message says why."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def media_kind(name: str) -> Optional[str]:
    n = str(name).lower()
    if n.endswith(IMAGE_EXTS):
        return "image"
    if n.endswith(VIDEO_EXTS):
        return "video"
    return None


# ------------------------------------------------------------------------------------------------ hash sets
_HEX = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{32})\b")


def import_hash_set(conn: sqlite3.Connection, name: str, kind: str, text: str, source_note: str = "") -> Dict[str, Any]:
    """Import a list of MD5 / SHA-256 values (one per line; anything else on the line, such as a file name, is ignored).

    A line that holds no 32- or 64-digit hexadecimal value is counted as skipped and not guessed at.
    """
    name = " ".join(str(name or "").split())
    if not name or len(name) > 80:
        raise MediaError("Give the list a name of 1 to 80 characters.")
    if kind not in SET_KINDS:
        raise MediaError(f"Unknown list kind {kind!r}. Use one of: {', '.join(SET_KINDS)}.")
    if conn.execute("SELECT 1 FROM hash_sets WHERE Name = ?", (name,)).fetchone():
        raise MediaError(f"A list named {name!r} already exists. Remove it first, or use another name.")
    values, skipped = set(), 0
    for line in str(text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _HEX.search(s)
        if not m:
            skipped += 1
            continue
        values.add(m.group(1).lower())
        if len(values) > MAX_SET_ENTRIES:
            raise MediaError(f"A list can hold at most {MAX_SET_ENTRIES:,} values. Nothing was imported.")
    if not values:
        raise MediaError("No MD5 or SHA-256 values were found in the list. Nothing was imported.")
    cur = conn.execute("INSERT INTO hash_sets(Name, Kind, Entries, Skipped_Lines, Source_Note, Imported_At_UTC) VALUES (?,?,?,?,?,?)",
                       (name, kind, len(values), skipped, (source_note or "")[:500], _now()))
    sid = cur.lastrowid
    conn.executemany("INSERT INTO hash_set_entries(Set_Id, Hash) VALUES (?,?)", ((sid, v) for v in sorted(values)))
    conn.commit()
    return {"id": sid, "name": name, "kind": kind, "entries": len(values), "skipped_lines": skipped,
            "matching_files_now": conn.execute(
                "SELECT COUNT(*) FROM media_items m WHERE EXISTS (SELECT 1 FROM hash_set_entries e WHERE e.Set_Id = ? "
                "AND (e.Hash = lower(m.SHA256) OR e.Hash = lower(m.MD5)))", (sid,)).fetchone()[0]}


def list_hash_sets(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT id, Name AS name, Kind AS kind, Entries AS entries, Skipped_Lines AS skipped_lines, "
        "Source_Note AS source_note, Imported_At_UTC AS imported_at_utc FROM hash_sets ORDER BY id")]


def remove_hash_set(conn: sqlite3.Connection, name: str) -> Dict[str, Any]:
    row = conn.execute("SELECT id FROM hash_sets WHERE Name = ?", (name,)).fetchone()
    if not row:
        raise MediaError(f"No list named {name!r}.")
    conn.execute("DELETE FROM hash_set_entries WHERE Set_Id = ?", (row[0],))
    conn.execute("DELETE FROM hash_sets WHERE id = ?", (row[0],))
    conn.commit()
    return {"removed": name}


# ------------------------------------------------------------------------------------------------ analysis
def _hash_file(path: str) -> tuple:
    sha, md = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
            md.update(chunk)
    return sha.hexdigest(), md.hexdigest()


def _rational(v: Any) -> Optional[float]:
    try:
        f = float(v)
        return f if f == f and abs(f) != float("inf") else None
    except Exception:
        return None


def _gps(ifd: Dict[int, Any]) -> tuple:
    """(lat, lon) in degrees, or (None, None) when the fields are missing or out of range. Never guessed."""
    try:
        lat_ref, lat, lon_ref, lon = ifd.get(1), ifd.get(2), ifd.get(3), ifd.get(4)
        if not (lat and lon and lat_ref in ("N", "S") and lon_ref in ("E", "W")) or len(lat) != 3 or len(lon) != 3:
            return None, None
        la = [_rational(x) for x in lat]
        lo = [_rational(x) for x in lon]
        if None in la or None in lo:
            return None, None
        lat_d = la[0] + la[1] / 60 + la[2] / 3600
        lon_d = lo[0] + lo[1] / 60 + lo[2] / 3600
        lat_d = -lat_d if lat_ref == "S" else lat_d
        lon_d = -lon_d if lon_ref == "W" else lon_d
        if not (-90 <= lat_d <= 90 and -180 <= lon_d <= 180) or (lat_d == 0 and lon_d == 0):
            return None, None            # (0, 0) is what a camera writes when it has no fix
        return round(lat_d, 6), round(lon_d, 6)
    except Exception:
        return None, None


def _clean(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = (v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)).replace("\x00", "").strip()
    return s[:200] or None


def pillow_available() -> Optional[str]:
    try:
        import PIL
        return PIL.__version__
    except Exception:
        return None


def _analyse_image(path: str, thumb_path: str) -> Dict[str, Any]:
    from PIL import Image, ImageOps
    from src.geospatial_media_and_tamper.perceptual_dhash_clustering import PerceptualDHashClusterer
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    out: Dict[str, Any] = {}
    with Image.open(path) as im:
        out["Format"], out["Width"], out["Height"] = im.format, im.width, im.height
        if im.width * im.height > MAX_PIXELS:
            raise MediaError(f"Image is larger than {MAX_PIXELS:,} pixels; not decoded.")
        ex = im.getexif()
        exif: Dict[str, Any] = {}
        if ex:
            out["Camera_Make"], out["Camera_Model"], out["Software"] = _clean(ex.get(0x010F)), _clean(ex.get(0x0110)), _clean(ex.get(0x0131))
            try:
                sub = ex.get_ifd(0x8769)
            except Exception:
                sub = {}
            # Only DateTimeOriginal is the capture clock. DateTime (0x0132) is when the file was last written, often by an
            # editor, and is kept in Exif_Json under its own name.
            out["Exif_Clock"] = _clean(sub.get(0x9003))
            try:
                out["Gps_Lat"], out["Gps_Lon"] = _gps(dict(ex.get_ifd(0x8825)))
            except Exception:
                out["Gps_Lat"] = out["Gps_Lon"] = None
            for k, label in ((0x010F, "Make"), (0x0110, "Model"), (0x0131, "Software"), (0x0132, "DateTime"), (0x0112, "Orientation")):
                if ex.get(k) is not None:
                    exif[label] = _clean(ex.get(k))
            for k, label in ((0x9003, "DateTimeOriginal"), (0x9004, "DateTimeDigitized")):
                if sub.get(k) is not None:
                    exif[label] = _clean(sub.get(k))
        out["Exif_Json"] = json.dumps(exif, sort_keys=True) if exif else None
        im.seek(0)
        gray = ImageOps.exif_transpose(im).convert("L").resize((9, 8), Image.LANCZOS)
        px = list(gray.tobytes())
        rows = [px[i * 9:(i + 1) * 9] for i in range(8)]
        out["DHash"] = f"{PerceptualDHashClusterer().compute_dhash_uint64(rows):016x}"
        thumb = ImageOps.exif_transpose(im).convert("RGB")
        thumb.thumbnail((THUMB_SIDE, THUMB_SIDE))
        os.makedirs(os.path.dirname(thumb_path), exist_ok=True)
        thumb.save(thumb_path, "JPEG", quality=80)
        out["Thumb_Path"] = thumb_path
    return out


_MEDIA_COLUMNS = ["Evidence_Item", "Vfs_Path", "File_Name", "File_Size", "Kind", "SHA256", "MD5", "Width", "Height", "Format",
                  "Camera_Make", "Camera_Model", "Software", "Exif_Clock", "Gps_Lat", "Gps_Lon", "Exif_Json", "DHash", "Thumb_Path",
                  "Status", "Status_Detail", "Decoded_By", "Analysed_At_UTC"]


def remove_item_media(conn: sqlite3.Connection, evidence_item: Optional[str] = None) -> int:
    """Deletes the media rows of one evidence item (all items when None) and the thumbnail files nothing else uses."""
    if evidence_item is None:
        paths = [r[0] for r in conn.execute("SELECT Thumb_Path FROM media_items WHERE Thumb_Path IS NOT NULL")]
        n = conn.execute("DELETE FROM media_items").rowcount
    else:
        paths = [r[0] for r in conn.execute("SELECT Thumb_Path FROM media_items WHERE Evidence_Item = ? AND Thumb_Path IS NOT NULL", (evidence_item,))]
        n = conn.execute("DELETE FROM media_items WHERE Evidence_Item = ?", (evidence_item,)).rowcount
    for p in set(paths):
        if not conn.execute("SELECT 1 FROM media_items WHERE Thumb_Path = ? LIMIT 1", (p,)).fetchone():
            try:
                os.remove(p)
            except OSError:
                pass                           # already gone
    return n


def analyse_files(conn: sqlite3.Connection, files: Sequence[Dict[str, Any]], thumb_dir: str, redo: bool = False) -> Dict[str, Any]:
    """Record hashes and, for images, details. ``files``: dicts with evidence_item, vfs_path, file_name, local_path."""
    ver = pillow_available()
    counts = {"analysed": 0, "already_done": 0, "unreadable": 0, "not_decoded": 0, "video": 0}
    for f in files:
        item, vpath = f.get("evidence_item") or "", f["vfs_path"]
        if not redo and conn.execute("SELECT 1 FROM media_items WHERE Evidence_Item = ? AND Vfs_Path = ?", (item, vpath)).fetchone():
            counts["already_done"] += 1
            continue
        kind = media_kind(f.get("file_name") or vpath)
        if kind is None:
            continue
        row: Dict[str, Any] = {"Evidence_Item": item, "Vfs_Path": vpath, "File_Name": f.get("file_name"), "Kind": kind,
                               "Status": "OK", "Status_Detail": None, "Decoded_By": None, "Analysed_At_UTC": _now()}
        try:
            row["File_Size"] = os.path.getsize(f["local_path"])
            row["SHA256"], row["MD5"] = _hash_file(f["local_path"])
        except OSError as exc:
            row.update(Status="UNREADABLE", Status_Detail=f"File could not be read: {exc.__class__.__name__}")
            counts["unreadable"] += 1
        else:
            if kind == "video":
                row.update(Status="HASHED_ONLY", Status_Detail="Video: hashes and size only. No frame was decoded.",
                           Decoded_By="hashlib")
                counts["video"] += 1
            elif ver is None:
                row.update(Status="HASHED_ONLY", Status_Detail="Image library (Pillow) is not installed: hashes only.", Decoded_By="hashlib")
                counts["not_decoded"] += 1
            else:
                try:
                    row.update(_analyse_image(f["local_path"], os.path.join(thumb_dir, f"{row['SHA256']}.jpg")))
                    row["Decoded_By"] = f"Pillow {ver} + dHash"
                    counts["analysed"] += 1
                except Exception as exc:               # corrupt, truncated, unsupported (for example HEIC) or too large
                    row.update(Status="NOT_DECODED", Status_Detail=f"{exc.__class__.__name__}: {str(exc)[:160]}", Decoded_By="hashlib")
                    counts["not_decoded"] += 1
        # Updated in place, so the id of a file (and any link that uses it) survives analysing it again; columns the new
        # analysis does not fill go back to empty rather than keeping an earlier result.
        full = {c: row.get(c) for c in _MEDIA_COLUMNS}
        updates = ",".join(f"{c}=excluded.{c}" for c in _MEDIA_COLUMNS if c not in ("Evidence_Item", "Vfs_Path"))
        conn.execute(f"INSERT INTO media_items({','.join(_MEDIA_COLUMNS)}) VALUES ({','.join('?' * len(_MEDIA_COLUMNS))}) "
                     f"ON CONFLICT(Evidence_Item, Vfs_Path) DO UPDATE SET {updates}", [full[c] for c in _MEDIA_COLUMNS])
    conn.commit()
    counts["pillow"] = ver
    return counts


# ------------------------------------------------------------------------------------------------ queries
_MATCH_SQL = ("(SELECT group_concat(s.Name || ' (' || s.Kind || ')', '; ') FROM hash_set_entries e JOIN hash_sets s ON s.id = e.Set_Id "
              "WHERE e.Hash = lower(m.SHA256) OR e.Hash = lower(m.MD5))")


def list_media(conn: sqlite3.Connection, evidence_item: Optional[str] = None, kind: Optional[str] = None,
               in_set: Optional[str] = None, set_kind: Optional[str] = None, outside_sets: bool = False,
               has_gps: Optional[bool] = None, status: Optional[str] = None,
               limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    where, params = [], []
    if evidence_item:
        where.append("m.Evidence_Item = ?"); params.append(evidence_item)
    if kind:
        if kind not in ("image", "video"):
            raise MediaError("kind must be image or video.")
        where.append("m.Kind = ?"); params.append(kind)
    if status:
        where.append("m.Status = ?"); params.append(status)
    if has_gps is not None:
        where.append("m.Gps_Lat IS NOT NULL" if has_gps else "m.Gps_Lat IS NULL")
    if in_set:
        where.append("EXISTS (SELECT 1 FROM hash_set_entries e JOIN hash_sets s ON s.id = e.Set_Id WHERE s.Name = ? "
                     "AND (e.Hash = lower(m.SHA256) OR e.Hash = lower(m.MD5)))")
        params.append(in_set)
    if set_kind:
        if set_kind not in SET_KINDS:
            raise MediaError(f"set_kind must be one of: {', '.join(SET_KINDS)}.")
        where.append("EXISTS (SELECT 1 FROM hash_set_entries e JOIN hash_sets s ON s.id = e.Set_Id WHERE s.Kind = ? "
                     "AND (e.Hash = lower(m.SHA256) OR e.Hash = lower(m.MD5)))")
        params.append(set_kind)
    if outside_sets:
        where.append(f"{_MATCH_SQL} IS NULL")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM media_items m{w}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT m.id, m.Evidence_Item AS evidence_item, m.Vfs_Path AS vfs_path, m.File_Name AS file_name, m.File_Size AS file_size, "
        f"m.Kind AS kind, m.SHA256 AS sha256, m.MD5 AS md5, m.Width AS width, m.Height AS height, m.Format AS format, "
        f"m.Camera_Make AS camera_make, m.Camera_Model AS camera_model, m.Software AS software, m.Exif_Clock AS exif_clock, "
        f"m.Gps_Lat AS gps_lat, m.Gps_Lon AS gps_lon, m.DHash AS dhash, (m.Thumb_Path IS NOT NULL) AS has_thumbnail, "
        f"m.Status AS status, m.Status_Detail AS status_detail, m.Decoded_By AS decoded_by, {_MATCH_SQL} AS hash_set_matches "
        f"FROM media_items m{w} ORDER BY m.id LIMIT ? OFFSET ?", params + [max(1, min(int(limit), 500)), max(0, int(offset))]).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["has_thumbnail"] = bool(d["has_thumbnail"])
        d["hash_set_matches"] = d["hash_set_matches"].split("; ") if d["hash_set_matches"] else []
        d["exif_clock_note"] = "Camera local clock, no zone recorded; not converted." if d["exif_clock"] else None
        items.append(d)
    return {"total": total, "offset": offset, "items": items,
            "note": "A hash-set match is an exact match of the file's MD5 or SHA-256 with a value in a list you imported. "
                    "It says nothing about what the list means."}


def thumbnail_path(conn: sqlite3.Connection, media_id: int) -> Optional[str]:
    row = conn.execute("SELECT Thumb_Path FROM media_items WHERE id = ?", (int(media_id),)).fetchone()
    return row[0] if row and row[0] else None


def similar(conn: sqlite3.Connection, media_id: int, max_distance: int = SIMILAR_MAX_DISTANCE, limit: int = 50) -> Dict[str, Any]:
    """Images whose 64-bit fingerprint is within ``max_distance`` bits of this one. A lead, never an identity."""
    if not 0 <= int(max_distance) <= 16:
        raise MediaError("max_distance must be between 0 and 16 bits.")
    base = conn.execute("SELECT id, DHash, SHA256 FROM media_items WHERE id = ?", (int(media_id),)).fetchone()
    if base is None:
        raise MediaError(f"No media item {media_id}.")
    if not base["DHash"]:
        raise MediaError("This item has no image fingerprint (it is a video, or the image was not decoded).")
    h = int(base["DHash"], 16)
    found = []
    for r in conn.execute("SELECT id, DHash, Evidence_Item, Vfs_Path, File_Name, SHA256 FROM media_items WHERE DHash IS NOT NULL AND id <> ?",
                          (base["id"],)):
        dist = (h ^ int(r["DHash"], 16)).bit_count()
        if dist <= int(max_distance):
            found.append({"id": r["id"], "distance": dist, "evidence_item": r["Evidence_Item"], "vfs_path": r["Vfs_Path"],
                          "file_name": r["File_Name"], "sha256": r["SHA256"], "identical_bytes": r["SHA256"] == base["SHA256"]})
    found.sort(key=lambda x: (x["distance"], x["id"]))
    return {"id": base["id"], "max_distance": int(max_distance), "total": len(found), "matches": found[:max(1, min(int(limit), 500))],
            "label": "LEAD",
            "note": "Visual similarity of a 64-bit fingerprint. A lead for the examiner to look at; it does not show the images are the same picture."}


def summary(conn: sqlite3.Connection) -> Dict[str, Any]:
    by_status = {s: n for s, n in conn.execute("SELECT Status, COUNT(*) FROM media_items GROUP BY Status")}
    return {"total": sum(by_status.values()), "by_status": by_status, "pillow": pillow_available(),
            "with_gps": conn.execute("SELECT COUNT(*) FROM media_items WHERE Gps_Lat IS NOT NULL").fetchone()[0],
            "hash_sets": list_hash_sets(conn)}
