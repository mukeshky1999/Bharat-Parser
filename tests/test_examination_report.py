"""Examination report, facts annexure and audit log wiring (Phase 5A). The report states recorded facts only."""
import json
import re
import sqlite3

import pytest
from fastapi import HTTPException

from parsers import api_server, examination_report
from parsers.api_server import ReportParticulars

# Words that belong to a legal form or to a particular institution. The tool must not print them itself.
FORBIDDEN = re.compile(
    r"Section\s*63|Section\s*230|Bharatiya|\bBSA\b|\bBNSS\b|\bBNS\b|Evidence Act|NCRP|\b1930\b|Government of India|"
    r"State Police|Police Station|solemnly|do hereby|certify|certificate",
    re.IGNORECASE,
)


@pytest.fixture(autouse=True)
def _restore_api_globals(monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", api_server._case_state)
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)


@pytest.fixture
def ingested(tmp_path, monkeypatch):
    folder = tmp_path / "evidence"
    folder.mkdir()
    conn = sqlite3.connect(folder / "msgstore.db")
    conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT)")
    conn.execute("INSERT INTO message(text_data) VALUES ('hello')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    api_server._execute_ingestion_pipeline(str(folder), "CASE-RPT", "Report case", "Examiner One", "Agency One")
    return folder


def _html(resp):
    return resp.body.decode("utf-8")


def test_report_is_refused_without_a_case(monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", {**api_server._case_state, "loaded": False})
    with pytest.raises(HTTPException) as e:
        api_server.examination_report_post(ReportParticulars())
    assert e.value.status_code == 412
    with pytest.raises(HTTPException):
        api_server.report_facts("json")


def test_report_states_recorded_facts_and_matches_hashes(ingested):
    html = _html(api_server.examination_report_post(ReportParticulars(case_number="FIR 12/2026")))
    st = api_server._case_state
    assert st["hashes"]["sha256"] in html and st["hashes"]["postIngestionSha256"] in html
    assert "<strong>MATCH</strong>" in html
    assert "FIR 12/2026" in html
    assert "Examiner One" in html and "Agency One" in html     # carried from the ingest request, not invented
    assert "Not recorded" in html                               # device fields the evidence did not contain
    assert "Not provided" in html                               # particulars the examiner did not type


def test_report_contains_no_legal_form_wording(ingested):
    html = _html(api_server.examination_report_post(ReportParticulars()))
    assert not FORBIDDEN.search(html), FORBIDDEN.search(html).group(0)
    csv_text = api_server.report_facts("csv").body.decode("utf-8")
    assert not FORBIDDEN.search(csv_text)


def test_particulars_are_html_escaped(ingested):
    html = _html(api_server.examination_report_post(ReportParticulars(notes="<script>alert(1)</script>")))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_report_does_not_invent_particulars_when_none_were_entered(tmp_path, monkeypatch):
    folder = tmp_path / "ev"
    folder.mkdir()
    conn = sqlite3.connect(folder / "msgstore.db")
    conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, text_data TEXT)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    api_server._execute_ingestion_pipeline(str(folder), "CASE-BLANK", "Blank", "", "")
    facts = json.loads(api_server.report_facts("json").body)
    assert facts["particulars"]["examiner_name"] == examination_report.NOT_PROVIDED
    assert facts["particulars"]["agency"] == examination_report.NOT_PROVIDED


def test_findings_appear_with_note_and_source(ingested):
    api_server.pin_finding(api_server.FindingIn(
        kind="chat", record_id="r-1", title="Message about payment", note="Examiner words",
        source={"file": "msgstore.db", "table": "message", "rowid": 1}))
    html = _html(api_server.examination_report_post(ReportParticulars()))
    assert "Message about payment" in html and "Examiner words" in html and "rowid: 1" in html


def test_audit_records_actions_and_report_lists_them(ingested):
    api_server.pin_finding(api_server.FindingIn(kind="chat", record_id="r-2", title="T"))
    html = _html(api_server.examination_report_post(ReportParticulars()))
    actions = [e["action"] for e in api_server.get_audit_log()["entries"]]
    assert actions[0] == "evidence_ingested"
    assert "finding_pinned" in actions and "report_generated" in actions
    assert "VERIFIED" in html and "report_generated" in html
    # the head hash printed in the report is the head at the time of generation
    assert api_server.get_audit_log()["head_hash"] in html


def test_tampered_audit_file_is_reported_as_failed(ingested):
    import os
    led, _ = api_server._get_audit()
    path = led.path
    lines = open(path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[0])
    rec["payload_json"] = '{"evidence":"other.zip"}'
    lines[0] = json.dumps(rec, sort_keys=True)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    api_server._audit_cache.clear()
    summary = api_server.get_audit_log()
    assert summary["verified"] is False and "failed verification" in summary["error"]
    html = _html(api_server.examination_report_post(ReportParticulars()))
    assert "FAILED" in html and "<strong class=\"ok\">VERIFIED" not in html


def test_limitations_list_failures_warnings_and_integrity_state():
    plog = [
        {"stage": "parse_database", "file": "a.db", "status": "OK", "error": ""},
        {"stage": "parse_database", "file": "b.db", "status": "FAILED", "error": "DatabaseError: file is not a database"},
        {"stage": "ingest_schema", "file": "chats", "status": "WARNING", "error": "Columns with data not stored: x"},
    ]
    lim = examination_report.limitations(plog, {"sha256": "a" * 64, "postIngestionSha256": "b" * 64, "integrityMatch": False})
    text = "\n".join(lim)
    assert "MISMATCH" in text and "b.db" in text and "not a database" in text and "Columns with data not stored" in text
    assert "a.db" not in text
    assert examination_report.integrity_state({})[0] == "NOT RECORDED"


def test_facts_csv_neutralises_formulas_and_quotes_commas():
    facts = {
        "generated": {"utc": "u", "ist": "i"}, "case": {"id": "=HYPERLINK(1)", "name": "a,b"}, "particulars": {},
        "evidence": {}, "device": {}, "environment": {}, "counts": {}, "limitations": [],
        "processing": {"ok": 0, "failed": 0, "warnings": 0, "log": []}, "findings": [], "audit": {"entries": []},
    }
    out = examination_report.render_facts_csv(facts)
    assert "'=HYPERLINK(1)" in out and '"a,b"' in out


def test_facts_json_has_the_same_hashes_as_the_report(ingested):
    facts = json.loads(api_server.report_facts("json").body)
    assert facts["evidence"]["sha256_before"] == api_server._case_state["hashes"]["sha256"]
    assert facts["evidence"]["comparison"] == "MATCH"


def test_no_statutory_form_routes_exist():
    """The tool supplies facts; it exposes no endpoint that generates a legal form."""
    paths = [getattr(r, "path", "") for r in api_server.app.routes]
    banned = re.compile(r"sec63|sec230|ncrp|1930|bnss|bsa|nodal|requisition", re.IGNORECASE)
    assert not [p for p in paths if banned.search(p)], [p for p in paths if banned.search(p)]
    assert "/api/report/examination" in paths and "/api/report/facts" in paths and "/api/report/package" in paths


def test_report_sections_can_be_left_out_but_evidence_limitations_and_audit_cannot(ingested):
    full = _html(api_server.examination_report_post(ReportParticulars()))
    part = _html(api_server.examination_report_post(ReportParticulars(sections=["findings"])))
    none = _html(api_server.examination_report_post(ReportParticulars(sections=[])))
    assert "Case particulars" in full and "Tool and processing environment" in full
    for html in (full, part, none):                                     # always present, whatever was asked for
        assert "Evidence and hashes" in html and "Limitations" in html and "Audit log" in html
    assert "Case particulars" not in part.split("chose not to include")[0] and "Findings pinned" in part
    assert "chose not to include" in part and "Case particulars" in part.split("chose not to include")[1]   # named as left out
    assert "chose not to include" not in full
    nums = re.findall(r"<h2>(\d+)\. ", none)
    assert nums == ["1", "2", "3"]                                      # numbering follows what is shown
    assert not FORBIDDEN.search(none)


def test_unknown_section_names_are_ignored(ingested):
    html = _html(api_server.examination_report_post(ReportParticulars(sections=["not_a_section", "tags"])))
    assert "Records tagged by the examiner" in html and "not_a_section" not in html


# ---------------------------------------------------------------- review step 9
def _two_item_state():
    def item(i, status):
        return {"item_id": i, "label": i, "hashes": {"sha256": "a" * 64, "postIngestionSha256": "a" * 64, "integrityMatch": True},
                "device": {}, "processing_log": [{"stage": "parse_database", "file": f"{i}.db", "status": status, "error": "x"}],
                "corrupt_fields": []}
    return {"case_id": "C", "case_name": "n", "items": [item("EV-001", "OK"), item("EV-002", "FAILED")],
            "processing_log": [{"stage": "parse_database", "file": "EV-001.db", "status": "OK", "error": ""}], "hashes": {}}


def test_multi_device_tally_covers_every_device():
    facts = examination_report.build_facts(_two_item_state(), {}, [], {"entries": [], "verified": True, "head_hash": ""}, {}, {})
    assert facts["processing"]["ok"] == 1 and facts["processing"]["failed"] == 1
    assert {e["evidence_item"] for e in facts["processing"]["log"]} == {"EV-001", "EV-002"}
    html = examination_report.render_report_html(facts)
    assert "EV-002 / parse_database" in html


def test_damaged_case_file_value_is_not_called_not_recorded():
    st = _two_item_state()
    st["items"][0]["corrupt_fields"] = ["hashes"]
    facts = examination_report.build_facts(st, {}, [], {"entries": [], "verified": True, "head_hash": ""}, {}, {})
    assert any("damaged" in x and "hashes" in x for x in facts["limitations"])


def test_facts_csv_carries_findings_and_encrypted_count():
    facts = examination_report.build_facts(_two_item_state(), {}, [{"kind": "chat", "note": "n"}],
                                           {"entries": [], "verified": True, "head_hash": ""}, {}, {})
    text = examination_report.render_facts_csv(facts)
    assert "finding.1" in text and "processing.encrypted_no_key" in text
