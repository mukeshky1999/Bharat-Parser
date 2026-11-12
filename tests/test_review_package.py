"""Portable review package: fail-closed decisions, masking, safe names, honest manifest."""
import hashlib
import json
import os

import pytest
from fastapi import HTTPException

from parsers import api_server, review_package as rp
from parsers.review_package import INCLUDE, WITHHOLD_PRIVILEGED, WITHHOLD_SENSITIVE, PackageItem, PackageRefused


def _file(tmp_path, name, data=b"payload"):
    p = tmp_path / "src" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(data)
    return str(p)


def _tree(root):
    return sorted(os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs)


def test_item_without_a_decision_aborts_and_writes_nothing(tmp_path):
    out = tmp_path / "pkg"
    items = [PackageItem(_file(tmp_path, "a.jpg"), INCLUDE), PackageItem(_file(tmp_path, "b.jpg"), None)]
    with pytest.raises(PackageRefused) as e:
        rp.build_package("C1", items, str(out))
    assert "b.jpg" in str(e.value)
    assert not out.exists()


def test_unknown_decision_and_missing_file_are_refused(tmp_path):
    with pytest.raises(PackageRefused):
        rp.build_package("C", [PackageItem(_file(tmp_path, "a"), "MAYBE")], str(tmp_path / "o1"))
    with pytest.raises(PackageRefused):
        rp.build_package("C", [PackageItem(str(tmp_path / "gone"), INCLUDE)], str(tmp_path / "o2"))
    assert not (tmp_path / "o1").exists() and not (tmp_path / "o2").exists()


def test_included_file_is_copied_byte_for_byte_withheld_file_is_not_copied(tmp_path):
    a = _file(tmp_path, "a.bin", b"visible bytes")
    b = _file(tmp_path, "b.bin", b"SECRET BYTES")
    res = rp.build_package("C", [PackageItem(a, INCLUDE), PackageItem(b, WITHHOLD_SENSITIVE, note="n")], str(tmp_path / "pkg"))
    assert (res.included, res.withheld) == (1, 1)
    files = _tree(tmp_path / "pkg")
    assert any(f.endswith("001_a.bin") for f in files)
    for f in files:
        assert b"SECRET BYTES" not in open(tmp_path / "pkg" / f, "rb").read()
    card = next(f for f in files if f.endswith("_WITHHELD.txt"))
    text = open(tmp_path / "pkg" / card, encoding="utf-8").read()
    assert hashlib.sha256(b"SECRET BYTES").hexdigest() in text      # the hash of the original is the reference
    assert open(tmp_path / "pkg" / "exhibits" / "001_a.bin", "rb").read() == b"visible bytes"


def test_manifest_hashes_are_of_the_originals_and_root_is_recorded(tmp_path):
    b = _file(tmp_path, "b.bin", b"abc")
    res = rp.build_package("C", [PackageItem(b, WITHHOLD_PRIVILEGED)], str(tmp_path / "pkg"), audit_head="f" * 64)
    meta = json.load(open(res.manifest_path, encoding="utf-8"))
    assert meta["items"][0]["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert meta["merkle_root"] == res.merkle_root and len(res.merkle_root) == 64
    assert meta["audit_head_hash"] == "f" * 64
    assert "not altered" in meta["masking"]


def test_masking_is_case_insensitive_in_names_notes_cards_and_viewer(tmp_path):
    p = _file(tmp_path, "Priya Sharma photo.jpg")
    res = rp.build_package("C", [PackageItem(p, WITHHOLD_SENSITIVE, note="photo of PRIYA SHARMA")], str(tmp_path / "pkg"),
                           mask_terms=["priya sharma"])
    blob = ""
    for f in _tree(tmp_path / "pkg"):
        blob += f + "\n" + open(tmp_path / "pkg" / f, encoding="utf-8", errors="ignore").read()
    assert "riya" not in blob.lower().replace("redacted", "")
    assert "[REDACTED_01]" in blob


def test_path_traversal_in_a_name_stays_inside(tmp_path):
    p = _file(tmp_path, "x.txt")
    res = rp.build_package("C", [PackageItem(p, INCLUDE, display_name="../../ESCAPED.txt")], str(tmp_path / "a" / "b" / "pkg"))
    assert not (tmp_path / "ESCAPED.txt").exists() and not (tmp_path / "a" / "ESCAPED.txt").exists()
    assert all(f.startswith(("exhibits", "index", "manifest")) for f in _tree(res.directory))


def test_viewer_is_escaped_and_blocks_scripts(tmp_path):
    p = _file(tmp_path, "x.txt")
    res = rp.build_package("<img src=x onerror=alert(1)>", [PackageItem(p, INCLUDE, note="<script>alert(1)</script>")],
                           str(tmp_path / "pkg"))
    html = open(res.viewer_path, encoding="utf-8").read()
    assert "<script>" not in html and "<img src=x" not in html
    assert "default-src 'none'" in html


def test_existing_nonempty_folder_is_not_reused(tmp_path):
    out = tmp_path / "pkg"
    out.mkdir()
    (out / "stale.txt").write_text("old")
    with pytest.raises(PackageRefused):
        rp.build_package("C", [PackageItem(_file(tmp_path, "a"), INCLUDE)], str(out))
    assert (out / "stale.txt").read_text() == "old"


def test_api_requires_decisions_confines_paths_and_audits(tmp_path, monkeypatch):
    import sqlite3
    folder = tmp_path / "ev"
    folder.mkdir()
    conn = sqlite3.connect(folder / "msgstore.db")
    conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT)")
    conn.commit()
    conn.close()
    (folder / "pic.jpg").write_bytes(b"jpegbytes")
    monkeypatch.setattr(api_server, "_case_state", api_server._case_state)
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    api_server._execute_ingestion_pipeline(str(folder), "CASE-PKG", "Pkg", "Ex", "Ag")
    pic = str(folder / "pic.jpg")

    with pytest.raises(HTTPException) as e:                       # no decision: refused
        api_server.build_review_package(api_server.PackageRequest(items=[api_server.PackageItemIn(path=pic)]))
    assert e.value.status_code == 422

    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    with pytest.raises(HTTPException) as e:                       # outside the case: refused
        api_server.build_review_package(api_server.PackageRequest(
            items=[api_server.PackageItemIn(path=str(outside), disposition=INCLUDE)]))
    assert e.value.status_code in (403, 404)

    res = api_server.build_review_package(api_server.PackageRequest(
        items=[api_server.PackageItemIn(path=pic, disposition=INCLUDE)]))
    assert res["included"] == 1 and os.path.isfile(res["viewer_path"])
    assert "package_built" in [x["action"] for x in api_server.get_audit_log()["entries"]]
