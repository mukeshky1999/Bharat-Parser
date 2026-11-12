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
