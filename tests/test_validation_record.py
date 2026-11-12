"""5B.10: the validation record. A check only passes when the tool's result equals an expected value fixed in advance."""
import hashlib
import json

from parsers import api_server, validation


def test_builtin_known_answer_checks_all_pass_and_leave_no_case_loaded():
    before = api_server._case_state.get("loaded")
    r = validation.run_validation()
    assert r["tally"] == {"PASS": len(validation.BUILTIN), "FAIL": 0, "ERROR": 0}, [c for c in r["checks"] if c["status"] != "PASS"]
    assert r["result"] == "ALL CHECKS PASSED"
    assert api_server._case_state.get("loaded") == before                 # the run did not leave its test case open
    assert "do not show it is right on any other input" in r["statement"]
    assert r["not_covered"] and r["environment"]["Tool version"]


def test_wrong_expectation_fails_and_exception_is_error_not_pass():
    assert validation._check("X", "w", "h", 3, lambda: 4)["status"] == "FAIL"
    assert validation._check("X", "w", "h", 3, lambda: 3)["status"] == "PASS"
    boom = validation._check("X", "w", "h", 3, lambda: 1 / 0)
    assert boom["status"] == "ERROR" and "ZeroDivisionError" in boom["error"]


def test_report_is_hashed_and_rendered_with_failures_first_in_the_headline(tmp_path):
    r = validation.run_validation()
    body = json.dumps({k: r[k] for k in ("schema", "environment", "tally", "checks")}, sort_keys=True, default=str)
    assert r["content_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    r["checks"][0]["status"] = "FAIL"; r["tally"] = {"PASS": 6, "FAIL": 1, "ERROR": 0}; r["result"] = "NOT ALL CHECKS PASSED"
    html = validation.render_html(r)
    assert "NOT ALL CHECKS PASSED" in html and "Not covered by this record" in html
    paths = validation.write_report(r, str(tmp_path / "out"))
    assert json.load(open(paths["json"]))["result"] == "NOT ALL CHECKS PASSED"


def test_supplied_corpus_checks_hash_and_refuses_paths_outside(tmp_path):
    good = tmp_path / "ref.bin"; good.write_bytes(b"known")
    (tmp_path / "manifest.json").write_text(json.dumps({"source_note": "unit test", "items": [
        {"path": "ref.bin", "sha256": hashlib.sha256(b"known").hexdigest()},
        {"path": "ref.bin", "sha256": "0" * 64},
        {"path": "../escape.bin", "sha256": "0" * 64}]}))
    st = [c["status"] for c in validation._corpus_checks(str(tmp_path))]
    assert st == ["PASS", "FAIL", "ERROR"]


def test_missing_corpus_manifest_is_error(tmp_path):
    assert validation._corpus_checks(str(tmp_path))[0]["status"] == "ERROR"


def test_cli_exit_status_reflects_result(tmp_path):
    assert validation.main(["--out", str(tmp_path / "r")]) == 0
    assert validation.main(["--out", str(tmp_path / "r2"), "--corpus", str(tmp_path / "nope")]) == 1


def test_running_the_validation_leaves_the_open_case_alone(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import sqlite3
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    ev = tmp_path / "ev"; ev.mkdir()
    c = sqlite3.connect(ev / "p.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("t", 10.0, "a@ybl", "b@ybl", "100000000011", "2026-02-01 09:00:00")); c.commit(); c.close()
    client = TestClient(api_server.app)
    assert client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "KEEP-1"}).json()["success"]
    store, state_id = api_server._active_store, api_server._case_state.get("case_id")
    r = client.post("/api/validation/run")
    assert r.status_code == 200 and r.json()["report"]["result"] == "ALL CHECKS PASSED" and "Validation record" in r.json()["html"]
    assert api_server._active_store is store and api_server._case_state.get("case_id") == state_id == "KEEP-1"
    assert client.get("/api/artifacts/query", params={"category": "upi_transactions"}).json()["rows"]        # the case still answers


def test_validation_refuses_while_an_ingest_is_running(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setattr(api_server._ingest_progress, "state", "running")
    assert TestClient(api_server.app).post("/api/validation/run").status_code == 409


def test_validation_works_when_the_server_requires_an_access_token(monkeypatch):
    """The desktop app starts the server with a per-launch token; the validation must carry it (found in the running app)."""
    monkeypatch.setenv("BHARAT_API_TOKEN", "t" * 32)
    r = validation.run_validation()
    assert r["tally"]["FAIL"] == 0 and r["tally"]["ERROR"] == 0, [c for c in r["checks"] if c["status"] != "PASS"]


def test_bad_corpus_manifest_is_an_error_result_not_a_crash(tmp_path):
    from parsers import validation
    (tmp_path / "manifest.json").write_text("{not json")
    out = validation._corpus_checks(str(tmp_path))
    assert out[0]["status"] == "ERROR" and out[0]["id"] == "CORPUS-00"
    (tmp_path / "manifest.json").write_text('{"items": [{"path": "D:/elsewhere/x", "sha256": "a"}, 5]}')
    out = validation._corpus_checks(str(tmp_path))
    assert [c["status"] for c in out] == ["ERROR", "ERROR"]
