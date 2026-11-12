"""
Phase 5B.10: the validation record.

A lab that works to ISO/IEC 17025 has to show that a tool gives the right answer on material whose answer is known.
This module runs known-answer checks and writes a dated report that says, for each check, what was expected, what
the tool produced, and how the expected value was fixed.

What it is
* Every built-in case is made on the spot from a few bytes or rows whose answer follows from how the case is built
  (three payments inserted means three payments expected). No third-party data is shipped.
* The expected value is written into this file before the tool is run. The report never "learns" the expected
  value from the tool's own output.
* An examiner can add a reference corpus of their own (for example a public reference image set whose licence
  allows it) with ``--corpus DIR``; its manifest declares the expected hashes and counts. The tool ships none.

What it is not
* It does not show the tool is right on devices it has not seen. The report says so on its face.
* A check that errors out is reported as ERROR, never as a pass, and a report with any FAIL or ERROR says so first.

Run:  python -m parsers.validation [--out DIR] [--corpus DIR]    (exit status 1 if anything did not pass)
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import html
import json
import os
import sqlite3
import struct
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

SCHEMA_VERSION = 1

NOT_COVERED = [
    "Real device extractions: the built-in cases are small synthetic files.",
    "Deleted-record recovery (freelist, WAL, carving): its result depends on how a real database was written, "
    "so it is checked by the reference corpus an examiner supplies, not by a built-in case.",
    "Any application version, phone model or extraction format not present in the cases below or in the supplied corpus.",
    "Amounts: the unit of an amount column is assumed in some parsers and is labelled as assumed (see the "
    "review findings); a built-in case cannot settle it.",
]


def _check(cid: str, what: str, how: str, expected: Any, fn: Callable[[], Any]) -> Dict[str, Any]:
    row: Dict[str, Any] = {"id": cid, "what": what, "how_expected_was_fixed": how, "expected": expected}
    try:
        actual = fn()
        row["actual"] = actual
        row["status"] = "PASS" if actual == expected else "FAIL"
    except ValidationBusy:
        raise
    except Exception as exc:                                     # an error is not a pass
        row["actual"] = None
        row["status"] = "ERROR"
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


# ---------------------------------------------------------------- built-in cases ------------------------------------

def _case_hash_known_answer(tmp: str) -> Any:
    from parsers import case_media
    p = os.path.join(tmp, "abc.bin")
    with open(p, "wb") as f:
        f.write(b"abc")
    sha, md5 = case_media._hash_file(p)          # (sha256, md5)
    return {"md5": md5, "sha256": sha}


def _case_crc32c_known_answer(tmp: str) -> Any:
    from src.nonsqlite.leveldb import crc32c
    return hex(crc32c(b"123456789"))


def _case_leveldb_crc(tmp: str) -> Any:
    from src.nonsqlite.leveldb import LevelDBDecoder, crc32c, mask_crc

    def varint(n: int) -> bytes:
        out = bytearray()
        while n >= 0x80:
            out.append((n & 0x7F) | 0x80)
            n >>= 7
        out.append(n)
        return bytes(out)

    def chunk(seq: int, val: bytes, good: bool) -> bytes:
        key = b"k"
        batch = struct.pack("<QI", seq, 1) + b"\x01" + varint(len(key)) + key + varint(len(val)) + val
        crc = mask_crc(crc32c(b"\x01" + batch))
        if not good:
            crc ^= 0xFFFF
        return struct.pack("<IHB", crc, len(batch), 1) + batch

    d = os.path.join(tmp, "ldb")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "000001.log"), "wb") as f:
        f.write(chunk(1, b"intact", True) + chunk(2, b"damaged", False))
    dec = LevelDBDecoder()
    recs = dec.decode_leveldb_directory(d)
    return {"records": len(recs), "unverified": sorted(r.decoded_value_text_or_json for r in recs
                                                        if getattr(r.recovery_classification, "value", r.recovery_classification) == "UNVERIFIED_FRAGMENT"),
            "checksum_failures": len(dec.crc_failures)}


def _case_whatsapp_direction(tmp: str) -> Any:
    from parsers.enterprise_1tb_chat_and_container_engine import parse_whatsapp_full_forensics
    db = os.path.join(tmp, "msgstore.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, key_id TEXT, chat_row_id INTEGER, sender_jid_row_id INTEGER, "
              "from_me INTEGER, text_data TEXT, message_type INTEGER, timestamp INTEGER)")
    c.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
    c.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
    c.execute("INSERT INTO jid VALUES (1, '919876543210@s.whatsapp.net')")
    c.execute("INSERT INTO chat VALUES (1, 1)")
    for i, flag in enumerate((None, 0, 1)):
        c.execute("INSERT INTO message VALUES (?, ?, 1, 1, ?, ?, 0, ?)", (i + 1, f"K{i}", flag, f"m{i}", 1700000000000 + i * 1000))
    c.commit()
    c.close()
    df, _ = parse_whatsapp_full_forensics(db)
    out: Dict[str, int] = {}
    for d in df["Direction"]:
        out[d] = out.get(d, 0) + 1
    return dict(sorted(out.items()))


def _case_entity_harvest(tmp: str) -> Any:
    from parsers.vpa_harvester import harvest_entities_from_file
    p = os.path.join(tmp, "blob.bin")
    with open(p, "wb") as f:
        f.write(b"\x00 alice@okaxis \x00 bob@ybl \x00 alice@okaxis \x00 9876543217 \x00 8123456781 \x00")
    vpas, phones = harvest_entities_from_file(p)
    return {"vpas": {r["UPI_VPA"]: int(r["Occurrences"]) for _, r in vpas.iterrows()},
            "phones": {r["Phone_Number"]: int(r["Occurrences"]) for _, r in phones.iterrows()}}


def _case_media_hashes_and_status(tmp: str) -> Any:
    from parsers import case_media
    ws = os.path.join(tmp, "media_ws")
    os.makedirs(ws, exist_ok=True)
    p = os.path.join(tmp, "clip.mp4")
    with open(p, "wb") as f:
        f.write(b"abc")
    bad = os.path.join(tmp, "broken.jpg")
    with open(bad, "wb") as f:
        f.write(b"this is not an image")
    conn = sqlite3.connect(os.path.join(ws, "m.db"))
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(case_media.SCHEMA)
        res = case_media.analyse_files(conn, [
            {"evidence_item": "EV-001", "vfs_path": "/clip.mp4", "file_name": "clip.mp4", "local_path": p},
            {"evidence_item": "EV-001", "vfs_path": "/broken.jpg", "file_name": "broken.jpg", "local_path": bad},
        ], os.path.join(ws, "thumbs"))
        rows = case_media.list_media(conn)["items"]
        return {"statuses": sorted((r["file_name"], r["status"]) for r in rows), "video": res.get("video"), "not_decoded": res.get("not_decoded")}
    finally:
        conn.close()


NONCE: Optional[str] = None   # set by the server for the duration of a run started through the API


def _client(api_server: Any) -> Any:
    """A test client for the server's own app. When the server was started with an access token (as the desktop app
    does), the client carries it, because the validation talks to the same app in the same process."""
    from fastapi.testclient import TestClient
    token = os.environ.get("BHARAT_API_TOKEN", "")
    headers = {"X-Bharat-Token": token} if token else {}
    if NONCE:
        headers["X-Validation-Nonce"] = NONCE
    return TestClient(api_server.app, headers=headers or None)


class ValidationBusy(RuntimeError):
    """An ingest is running, so the validation cannot borrow the server's state."""


@contextlib.contextmanager
def isolated_api(workspace_root: str):
    """Lets the validation run the real ingest in a scratch workspace and puts the server's own state back afterwards:
    the open case, the case store, the progress record and the workspace root."""
    from parsers import api_server
    if getattr(api_server._ingest_progress, "state", "") == "running":
        raise ValidationBusy("An evidence ingest is running. Run the validation after it has finished.")
    saved = (api_server._case_state, dict(api_server._case_state), api_server._active_store,
             api_server._ingest_progress, api_server.DEFAULT_WORKSPACE_ROOT)
    api_server.DEFAULT_WORKSPACE_ROOT = workspace_root
    try:
        yield api_server
    finally:
        state_obj, state_copy, store, progress, root = saved
        state_obj.clear()
        state_obj.update(state_copy)
        api_server._case_state = state_obj
        api_server._active_store = store
        api_server._ingest_progress = progress
        api_server.DEFAULT_WORKSPACE_ROOT = root


def _case_pipeline(tmp: str) -> Any:
    """End to end through the real ingest: three payments, one file that cannot be decoded."""
    from fastapi.testclient import TestClient

    with isolated_api(os.path.join(tmp, "cases")) as api_server:
        ev = os.path.join(tmp, "evidence")
        os.makedirs(ev, exist_ok=True)
        c = sqlite3.connect(os.path.join(ev, "payments.db"))
        c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
        for i, amt in enumerate((100.0, 250.5, 900.0)):
            c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', (f"t{i}", amt, "me@ybl", "x@ybl", f"1000000000{i}1", "2026-02-01 09:00:00"))
        c.commit()
        c.close()
        with open(os.path.join(ev, "mystery.bin"), "wb") as f:
            f.write(b"\x00\x01\x02" * 50)
        client = _client(api_server)
        res = client.post("/api/case/ingest", json={"evidence_path": ev, "case_id": "VALIDATION"}).json()
        rows = client.get("/api/artifacts/query", params={"category": "upi_transactions"}).json().get("rows", [])
        cov = client.get("/api/case/coverage").json()
        audit = client.get("/api/audit").json()
        return {
            "ingest_succeeded": bool(res.get("success")),
            "integrity_match": res.get("integrity_match"),
            "payments": len(rows),
            "payment_amounts": sorted(r["Amount"] for r in rows),
            "payment_time_zone_basis": sorted({r["Timestamp_Basis"] for r in rows}),
            "coverage_by_outcome": cov.get("summary", {}).get("by_outcome"),
            "audit_chain_verified": bool(audit.get("verified")),
        }


BUILTIN = [
    ("VAL-HASH-01", "MD5 and SHA-256 of the three bytes 'abc'",
     "Published test vectors for MD5 and SHA-256 of 'abc'",
     {"md5": "900150983cd24fb0d6963f7d28e17f72",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}, _case_hash_known_answer),
    ("VAL-CRC-01", "CRC-32C of '123456789'", "The standard CRC-32C check value", "0xe3069283", _case_crc32c_known_answer),
    ("VAL-LDB-01", "LevelDB: one intact log record and one with a damaged checksum",
     "Two records written, the checksum of the second deliberately altered",
     {"records": 2, "unverified": ["damaged"], "checksum_failures": 1}, _case_leveldb_crc),
    ("VAL-WA-01", "WhatsApp direction flag: NULL, 0 and 1 give Unknown, Incoming and Outgoing",
     "Three messages inserted with from_me NULL, 0 and 1",
     {"Incoming": 1, "Outgoing": 1, "Unknown": 1}, _case_whatsapp_direction),
    ("VAL-ENT-01", "Entity harvest: VPAs and mobile numbers in a byte blob, each counted by occurrence",
     "The blob holds alice@okaxis twice, bob@ybl once, and two valid mobile numbers once each",
     {"vpas": {"alice@okaxis": 2, "bob@ybl": 1}, "phones": {"9876543217": 1, "8123456781": 1}}, _case_entity_harvest),
    ("VAL-MED-01", "Media: a video is hashed only, an unreadable image gets its own status",
     "One 3-byte .mp4 and one .jpg that is plain text",
     {"statuses": [("broken.jpg", "NOT_DECODED"), ("clip.mp4", "HASHED_ONLY")], "video": 1, "not_decoded": 1}, _case_media_hashes_and_status),
    ("VAL-PIPE-01", "Ingest end to end: three payments in, three payments out, one undecoded file reported, audit chain intact",
     "Three payments inserted with amounts 100.0, 250.5 and 900.0; one 150-byte file the tool cannot decode",
     {"ingest_succeeded": True, "integrity_match": True, "payments": 3, "payment_amounts": [100.0, 250.5, 900.0],
      "payment_time_zone_basis": ["LOCAL_ZONE_UNKNOWN"], "coverage_by_outcome": {"DECODED": 1, "NOT_DECODED": 1},
      "audit_chain_verified": True}, _case_pipeline),
]


# ---------------------------------------------------------------- supplied corpus -----------------------------------

def _corpus_checks(corpus_dir: str) -> List[Dict[str, Any]]:
    """A reference corpus the examiner supplies. ``manifest.json`` declares what is expected; nothing here is guessed."""
    out: List[Dict[str, Any]] = []
    mpath = os.path.join(corpus_dir, "manifest.json")
    if not os.path.isfile(mpath):
        return [{"id": "CORPUS-00", "what": "Corpus manifest", "how_expected_was_fixed": "manifest.json in the corpus folder",
                 "expected": "present", "actual": "missing", "status": "ERROR", "error": f"{mpath} not found"}]
    try:
        with open(mpath, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("items", []), list):
            raise ValueError("manifest.json must be an object with an 'items' list")
    except (OSError, ValueError) as exc:
        return [{"id": "CORPUS-00", "what": "Corpus manifest", "how_expected_was_fixed": "manifest.json in the corpus folder",
                 "expected": "a readable manifest", "actual": "unreadable", "status": "ERROR",
                 "error": f"{type(exc).__name__}: {exc}"}]
    for i, item in enumerate(manifest.get("items", []), 1):
        if not isinstance(item, dict):
            out.append({"id": f"CORPUS-{i:02d}", "what": f"item {i}", "how_expected_was_fixed": "manifest", "expected": "an object",
                        "actual": type(item).__name__, "status": "ERROR", "error": "manifest item is not an object"})
            continue
        rel = str(item.get("path", ""))
        full = os.path.normpath(os.path.join(corpus_dir, rel))
        try:
            outside = os.path.commonpath([os.path.abspath(full), os.path.abspath(corpus_dir)]) != os.path.abspath(corpus_dir)
        except ValueError:                      # another drive
            outside = True
        if outside:
            out.append({"id": f"CORPUS-{i:02d}", "what": rel, "how_expected_was_fixed": "manifest", "expected": "inside the corpus folder",
                        "actual": "outside", "status": "ERROR", "error": "path leaves the corpus folder"})
            continue
        if item.get("sha256"):
            def sha(p=full) -> str:
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for blk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(blk)
                return h.hexdigest()
            out.append(_check(f"CORPUS-{i:02d}-SHA", f"SHA-256 of {rel}",
                              f"Declared in the corpus manifest ({manifest.get('source_note') or 'source not stated'})",
                              str(item["sha256"]).lower(), sha))
    expected_counts = manifest.get("expected_counts") or {}
    if expected_counts:
        def run() -> Any:
            from fastapi.testclient import TestClient
            with tempfile.TemporaryDirectory() as tmp, isolated_api(os.path.join(tmp, "cases")) as api_server:
                client = _client(api_server)
                res = client.post("/api/case/ingest", json={"evidence_path": corpus_dir, "case_id": "VALIDATION-CORPUS"}).json()
                if not res.get("success"):
                    raise RuntimeError(res.get("error") or "ingest failed")
                counts = res.get("counts") or {}
                return {k: (counts.get(k) or {}).get("total") for k in expected_counts}
        out.append(_check("CORPUS-COUNTS", "Record counts after ingesting the corpus",
                          "Declared in the corpus manifest", dict(expected_counts), run))
    return out


# ---------------------------------------------------------------- report --------------------------------------------

def _environment() -> Dict[str, Any]:
    from parsers import api_server
    return api_server._tool_environment()


def run_validation(corpus_dir: Optional[str] = None) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        for cid, what, how, expected, fn in BUILTIN:
            sub = os.path.join(tmp, cid)
            os.makedirs(sub, exist_ok=True)
            checks.append(_check(cid, what, how, expected, lambda fn=fn, sub=sub: fn(sub)))
    if corpus_dir:
        checks.extend(_corpus_checks(corpus_dir))
    tally = {"PASS": 0, "FAIL": 0, "ERROR": 0}
    for c in checks:
        tally[c["status"]] += 1
    now = datetime.now(timezone.utc)
    report: Dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": _environment(),
        "corpus": corpus_dir or None,
        "result": "ALL CHECKS PASSED" if tally["FAIL"] == 0 and tally["ERROR"] == 0 else "NOT ALL CHECKS PASSED",
        "tally": tally,
        "checks": checks,
        "not_covered": NOT_COVERED,
        "statement": ("These are known-answer checks. They show the tool gave the expected result on these inputs on the "
                      "date and build above. They do not show it is right on any other input."),
    }
    body = json.dumps({k: report[k] for k in ("schema", "environment", "tally", "checks")}, sort_keys=True, default=str)
    report["content_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return report


def render_html(r: Dict[str, Any]) -> str:
    e = html.escape
    rows = []
    for c in r["checks"]:
        rows.append(
            f"<tr class='{c['status'].lower()}'><td>{e(c['id'])}</td><td>{e(c['what'])}<br><small>{e(c['how_expected_was_fixed'])}</small></td>"
            f"<td><code>{e(json.dumps(c['expected'], default=str))}</code></td>"
            f"<td><code>{e(json.dumps(c.get('actual'), default=str))}</code>{('<br>' + e(c['error'])) if c.get('error') else ''}</td>"
            f"<td>{e(c['status'])}</td></tr>")
    env = "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in r["environment"].items())
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Validation record</title>"
        "<style>body{font:14px system-ui,sans-serif;margin:2rem;max-width:70rem}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #888;padding:.35rem .5rem;text-align:left;vertical-align:top}.fail td,.error td{background:#fdd}"
        ".pass td:last-child{font-weight:600}code{word-break:break-all}</style></head><body>"
        f"<h1>Validation record</h1><p><strong>{e(r['result'])}</strong>: {r['tally']['PASS']} passed, {r['tally']['FAIL']} failed, "
        f"{r['tally']['ERROR']} errored. Generated {e(r['generated_utc'])} (UTC).</p><p>{e(r['statement'])}</p>"
        f"<h2>Build</h2><table>{env}</table><h2>Checks</h2>"
        "<table><tr><th>ID</th><th>Check</th><th>Expected</th><th>Actual</th><th>Result</th></tr>" + "".join(rows) + "</table>"
        "<h2>Not covered by this record</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in r["not_covered"]) + "</ul>"
        f"<p>Content hash (SHA-256 of the build, tally and checks): <code>{e(r['content_sha256'])}</code></p></body></html>")


def write_report(r: Dict[str, Any], out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stem = f"validation_{r['generated_utc'].replace(':', '').replace('-', '')}_v{r['environment'].get('Tool version', 'x')}"
    jp, hp = os.path.join(out_dir, stem + ".json"), os.path.join(out_dir, stem + ".html")
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(r, f, indent=2, default=str)
    with open(hp, "w", encoding="utf-8") as f:
        f.write(render_html(r))
    return {"json": jp, "html": hp}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m parsers.validation", description="Run the known-answer validation and write a dated report.")
    ap.add_argument("--out", default="validation_reports", help="folder for the report files")
    ap.add_argument("--corpus", default=None, help="folder holding a reference corpus with manifest.json (supplied by the examiner)")
    a = ap.parse_args(argv)
    report = run_validation(a.corpus)
    paths = write_report(report, a.out)
    print(f"{report['result']}: {report['tally']['PASS']} passed, {report['tally']['FAIL']} failed, {report['tally']['ERROR']} errored")
    for c in report["checks"]:
        if c["status"] != "PASS":
            print(f"  {c['status']} {c['id']}: expected {c['expected']!r}, got {c.get('actual')!r} {c.get('error', '')}")
    print("report:", paths["html"])
    return 0 if report["tally"]["FAIL"] == 0 and report["tally"]["ERROR"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
