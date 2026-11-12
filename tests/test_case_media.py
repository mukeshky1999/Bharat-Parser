"""5B.8 media: hashes, EXIF, thumbnails, hash-set matching, similarity (a lead), honest statuses."""
import hashlib
import json
import os
import sqlite3

import pytest
from PIL import Image

from parsers import case_media


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(str(tmp_path / "m.db"))
    c.row_factory = sqlite3.Row
    c.executescript(case_media.SCHEMA)
    yield c
    c.close()


def _gradient(path, size=(64, 48), flip=False, exif=None, fmt="JPEG"):
    im = Image.new("RGB", size)
    px = im.load()
    for x in range(size[0]):
        for y in range(size[1]):
            v = int(255 * x / size[0])
            px[x, y] = (v, v, v) if not flip else (255 - v, 255 - v, 255 - v)
    kw = {"exif": exif} if exif is not None else {}
    im.save(path, fmt, **kw)
    return path


def _exif(lat=(12, 58, 30.0), lat_ref="N", lon=(77, 35, 0.0), lon_ref="E", clock="2026:02:01 10:00:00"):
    ex = Image.Exif()
    ex[0x010F], ex[0x0110] = "Acme", "Cam 1"
    sub = ex.get_ifd(0x8769)
    sub[0x9003] = clock
    gps = ex.get_ifd(0x8825)
    gps[1], gps[2], gps[3], gps[4] = lat_ref, lat, lon_ref, lon
    return ex.tobytes()


def _f(tmp_path, name, **kw):
    p = str(tmp_path / name)
    _gradient(p, **kw)
    return {"evidence_item": "EV-001", "vfs_path": "/dcim/" + name, "file_name": name, "local_path": p}


def test_image_gets_hashes_exif_thumbnail_and_dhash(conn, tmp_path):
    f = _f(tmp_path, "a.jpg", exif=_exif())
    r = case_media.analyse_files(conn, [f], str(tmp_path / "thumbs"))
    assert r["analysed"] == 1
    m = case_media.list_media(conn)["items"][0]
    assert m["sha256"] == hashlib.sha256(open(f["local_path"], "rb").read()).hexdigest()
    assert m["md5"] == hashlib.md5(open(f["local_path"], "rb").read()).hexdigest()
    assert (m["width"], m["height"], m["format"]) == (64, 48, "JPEG")
    assert (m["camera_make"], m["camera_model"]) == ("Acme", "Cam 1")
    assert m["exif_clock"] == "2026:02:01 10:00:00" and "no zone" in m["exif_clock_note"]
    assert abs(m["gps_lat"] - 12.975) < 1e-6 and abs(m["gps_lon"] - 77.583333) < 1e-5
    assert len(m["dhash"]) == 16 and m["has_thumbnail"] and m["status"] == "OK" and m["decoded_by"].startswith("Pillow")
    assert os.path.isfile(case_media.thumbnail_path(conn, m["id"]))
    with Image.open(case_media.thumbnail_path(conn, m["id"])) as t:
        assert max(t.size) <= case_media.THUMB_SIDE


def test_missing_exif_stays_null_and_zero_zero_gps_is_not_a_location(conn, tmp_path):
    plain = _f(tmp_path, "p.jpg")
    nofix = _f(tmp_path, "z.jpg", exif=_exif(lat=(0, 0, 0.0), lon=(0, 0, 0.0)))
    case_media.analyse_files(conn, [plain, nofix], str(tmp_path / "t"))
    for m in case_media.list_media(conn)["items"]:
        assert m["gps_lat"] is None and m["gps_lon"] is None
    p = [m for m in case_media.list_media(conn)["items"] if m["file_name"] == "p.jpg"][0]
    assert p["exif_clock"] is None and p["camera_make"] is None and p["exif_clock_note"] is None


def test_southern_western_hemisphere_signs(conn, tmp_path):
    f = _f(tmp_path, "s.jpg", exif=_exif(lat_ref="S", lon_ref="W"))
    case_media.analyse_files(conn, [f], str(tmp_path / "t"))
    m = case_media.list_media(conn)["items"][0]
    assert m["gps_lat"] < 0 and m["gps_lon"] < 0


def test_video_is_hashed_only_and_says_no_frame_decoded(conn, tmp_path):
    p = tmp_path / "v.mp4"
    p.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"x" * 50)
    r = case_media.analyse_files(conn, [{"evidence_item": "EV-001", "vfs_path": "/v.mp4", "file_name": "v.mp4", "local_path": str(p)}],
                                 str(tmp_path / "t"))
    assert r["video"] == 1
    m = case_media.list_media(conn)["items"][0]
    assert m["status"] == "HASHED_ONLY" and "No frame was decoded" in m["status_detail"] and m["dhash"] is None and m["sha256"]


def test_corrupt_image_and_missing_file_are_reported_not_hidden(conn, tmp_path):
    bad = tmp_path / "bad.jpg"
    bad.write_bytes(b"not a jpeg at all")
    r = case_media.analyse_files(conn, [
        {"evidence_item": "EV-001", "vfs_path": "/bad.jpg", "file_name": "bad.jpg", "local_path": str(bad)},
        {"evidence_item": "EV-001", "vfs_path": "/gone.jpg", "file_name": "gone.jpg", "local_path": str(tmp_path / "gone.jpg")}],
        str(tmp_path / "t"))
    assert r["not_decoded"] == 1 and r["unreadable"] == 1
    st = {m["file_name"]: m for m in case_media.list_media(conn)["items"]}
    assert st["bad.jpg"]["status"] == "NOT_DECODED" and st["bad.jpg"]["sha256"]          # still hashed
    assert st["gone.jpg"]["status"] == "UNREADABLE" and st["gone.jpg"]["sha256"] is None


def test_analysis_is_not_repeated_unless_asked(conn, tmp_path):
    f = _f(tmp_path, "a.jpg")
    assert case_media.analyse_files(conn, [f], str(tmp_path / "t"))["analysed"] == 1
    assert case_media.analyse_files(conn, [f], str(tmp_path / "t"))["already_done"] == 1
    assert case_media.analyse_files(conn, [f], str(tmp_path / "t"), redo=True)["analysed"] == 1
    assert case_media.list_media(conn)["total"] == 1


# ------------------------------------------------------------------------------------------------ hash sets
def test_hash_set_matches_exact_values_only_and_updates_with_the_list(conn, tmp_path):
    f = _f(tmp_path, "a.jpg")
    g = _f(tmp_path, "b.jpg", flip=True)
    case_media.analyse_files(conn, [f, g], str(tmp_path / "t"))
    sha = hashlib.sha256(open(f["local_path"], "rb").read()).hexdigest()
    md5_other = hashlib.md5(open(g["local_path"], "rb").read()).hexdigest()
    text = f"# my list\n{sha.upper()}  a.jpg\nnot a hash line\n{md5_other},b.jpg\n{sha}\n"
    r = case_media.import_hash_set(conn, "Lab list", "known_notable", text, "from the lab")
    assert r["entries"] == 2 and r["skipped_lines"] == 1 and r["matching_files_now"] == 2
    items = {m["file_name"]: m for m in case_media.list_media(conn)["items"]}
    assert items["a.jpg"]["hash_set_matches"] == ["Lab list (known_notable)"] and items["b.jpg"]["hash_set_matches"] == ["Lab list (known_notable)"]
    assert case_media.list_media(conn, in_set="Lab list")["total"] == 2
    assert case_media.list_media(conn, set_kind="known_ignorable")["total"] == 0
    assert case_media.list_media(conn, outside_sets=True)["total"] == 0
    case_media.remove_hash_set(conn, "Lab list")
    assert case_media.list_media(conn, outside_sets=True)["total"] == 2
    assert all(not m["hash_set_matches"] for m in case_media.list_media(conn)["items"])


def test_hash_set_refusals(conn):
    with pytest.raises(case_media.MediaError):
        case_media.import_hash_set(conn, "x", "known_notable", "nothing here\nat all")
    with pytest.raises(case_media.MediaError):
        case_media.import_hash_set(conn, "", "known_notable", "a" * 32)
    with pytest.raises(case_media.MediaError):
        case_media.import_hash_set(conn, "x", "bad_kind", "a" * 32)
    case_media.import_hash_set(conn, "x", "known_ignorable", "a" * 32)
    with pytest.raises(case_media.MediaError):
        case_media.import_hash_set(conn, "x", "known_ignorable", "b" * 32)           # same name twice
    with pytest.raises(case_media.MediaError):
        case_media.remove_hash_set(conn, "missing")


# ------------------------------------------------------------------------------------------------ similarity
def test_similar_is_a_lead_and_finds_recompressed_copy_not_the_inverse(conn, tmp_path):
    a = _f(tmp_path, "a.jpg")
    b_path = str(tmp_path / "b.jpg")
    Image.open(a["local_path"]).resize((128, 96)).save(b_path, "JPEG", quality=40)       # recompressed, rescaled copy
    b = {"evidence_item": "EV-001", "vfs_path": "/dcim/b.jpg", "file_name": "b.jpg", "local_path": b_path}
    c = _f(tmp_path, "c.jpg", flip=True)
    case_media.analyse_files(conn, [a, b, c], str(tmp_path / "t"))
    ids = {m["file_name"]: m["id"] for m in case_media.list_media(conn)["items"]}
    r = case_media.similar(conn, ids["a.jpg"])
    assert r["label"] == "LEAD" and "does not show" in r["note"]
    assert [m["file_name"] for m in r["matches"]] == ["b.jpg"] and r["matches"][0]["identical_bytes"] is False
    assert case_media.similar(conn, ids["a.jpg"], max_distance=16)["total"] >= 1
    with pytest.raises(case_media.MediaError):
        case_media.similar(conn, 9999)
    with pytest.raises(case_media.MediaError):
        case_media.similar(conn, ids["a.jpg"], max_distance=99)


def test_similar_refuses_item_without_fingerprint(conn, tmp_path):
    p = tmp_path / "v.mp4"
    p.write_bytes(b"x" * 40)
    case_media.analyse_files(conn, [{"evidence_item": "E", "vfs_path": "/v.mp4", "file_name": "v.mp4", "local_path": str(p)}], str(tmp_path / "t"))
    with pytest.raises(case_media.MediaError) as e:
        case_media.similar(conn, case_media.list_media(conn)["items"][0]["id"])
    assert "no image fingerprint" in str(e.value)


def test_filters_and_summary(conn, tmp_path):
    a = _f(tmp_path, "a.jpg", exif=_exif())
    b = _f(tmp_path, "b.jpg")
    case_media.analyse_files(conn, [a, b], str(tmp_path / "t"))
    assert case_media.list_media(conn, has_gps=True)["total"] == 1 and case_media.list_media(conn, has_gps=False)["total"] == 1
    assert case_media.list_media(conn, kind="video")["total"] == 0
    with pytest.raises(case_media.MediaError):
        case_media.list_media(conn, kind="audio")
    s = case_media.summary(conn)
    assert s["total"] == 2 and s["with_gps"] == 1 and s["by_status"] == {"OK": 2}


# ------------------------------------------------------------------------------------------------ endpoints
def test_media_endpoints_end_to_end(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from parsers import api_server
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    monkeypatch.setitem(api_server._case_state, "loaded", False)       # other tests leave a case loaded
    client = TestClient(api_server.app)
    assert client.get("/api/case/media").status_code == 412
    ev = tmp_path / "phone" / "DCIM"
    ev.mkdir(parents=True)
    a = _gradient(str(ev / "a.jpg"), exif=_exif())
    _gradient(str(ev / "b.jpg"), flip=True)
    sqlite3.connect(tmp_path / "phone" / "x.db").close()
    assert client.post("/api/case/ingest", json={"evidence_path": str(tmp_path / "phone"), "case_id": "M-1"}).json()["success"]
    r = client.post("/api/case/media/analyse", json={}).json()
    assert r["analysed"] == 2 and r["remaining"] == 0
    assert client.post("/api/case/media/analyse", json={}).json()["analysed"] == 0            # nothing new
    items = client.get("/api/case/media").json()["items"]
    assert len(items) == 2 and any(i["gps_lat"] for i in items)
    mid = [i for i in items if i["file_name"] == "a.jpg"][0]["id"]
    th = client.get(f"/api/case/media/{mid}/thumbnail")
    assert th.status_code == 200 and th.headers["content-type"] == "image/jpeg" and th.content[:2] == b"\xff\xd8"
    assert th.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/case/media/99999/thumbnail").status_code == 404
    sha = hashlib.sha256(open(a, "rb").read()).hexdigest()
    imp = client.post("/api/case/hashsets", json={"name": "L", "kind": "known_notable", "text": sha}).json()
    assert imp["entries"] == 1 and imp["matching_files_now"] == 1
    assert client.post("/api/case/hashsets", json={"name": "L", "kind": "known_notable", "text": sha}).status_code == 422
    assert client.get("/api/case/media", params={"in_set": "L"}).json()["total"] == 1
    assert client.get(f"/api/case/media/{mid}/similar").json()["label"] == "LEAD"
    assert client.get(f"/api/case/media/{mid}/similar", params={"max_distance": 99}).status_code == 422
    assert client.get("/api/case/media/summary").json()["total"] == 2
    assert client.post("/api/case/hashsets/remove", json={"name": "L"}).json() == {"removed": "L"}
    log = json.dumps(client.get("/api/audit").json())
    assert "hash_set_imported" in log and "media_analysed" in log


# ---------------------------------------------------------------- review step 9
def test_modification_time_is_not_reported_as_the_camera_clock(conn, tmp_path):
    ex = Image.Exif()
    ex[0x0132] = "2026:03:03 03:03:03"                  # DateTime: when the file was last written
    f = _f(tmp_path, "edited.jpg", exif=ex.tobytes())
    case_media.analyse_files(conn, [f], str(tmp_path / "thumbs"))
    m = case_media.list_media(conn)["items"][0]
    assert m["exif_clock"] is None
    assert "2026:03:03 03:03:03" in conn.execute("SELECT Exif_Json FROM media_items").fetchone()[0]


def test_analysing_again_keeps_the_id_and_clears_old_results(conn, tmp_path):
    f = _f(tmp_path, "a.jpg", exif=_exif())
    case_media.analyse_files(conn, [f], str(tmp_path / "thumbs"))
    first = conn.execute("SELECT id FROM media_items").fetchone()[0]
    Image.new("RGB", (8, 8)).save(f["local_path"], "JPEG")          # now a picture with no EXIF
    case_media.analyse_files(conn, [f], str(tmp_path / "thumbs"), redo=True)
    row = conn.execute("SELECT id, Camera_Make, Exif_Clock, Gps_Lat FROM media_items").fetchone()
    assert row["id"] == first and row["Camera_Make"] is None and row["Exif_Clock"] is None and row["Gps_Lat"] is None
    assert conn.execute("SELECT COUNT(*) FROM media_items").fetchone()[0] == 1


def test_thumbnails_go_with_their_item_unless_another_row_uses_them(conn, tmp_path):
    a = _f(tmp_path, "a.jpg")
    case_media.analyse_files(conn, [a], str(tmp_path / "thumbs"))
    thumb = conn.execute("SELECT Thumb_Path FROM media_items").fetchone()[0]
    assert os.path.isfile(thumb)
    b = dict(a, evidence_item="EV-002")                              # same bytes in another device: same thumbnail file
    case_media.analyse_files(conn, [b], str(tmp_path / "thumbs"))
    case_media.remove_item_media(conn, "EV-001")
    assert os.path.isfile(thumb)
    case_media.remove_item_media(conn, "EV-002")
    assert not os.path.isfile(thumb)
