"""Examination report and facts annexure.

Both are built only from facts the software recorded for the loaded case, plus particulars the examiner typed.
Nothing here is a legal form: no statute is named, no declaration is made and no institution is assumed. Where a
value was not recorded or not provided the output says so. A lab that needs a statutory certificate copies the
facts from the annexure into its own form and signs it.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict, List, Optional, Tuple

from src.audit.ledger import IST
from datetime import datetime, timezone

NOT_RECORDED = "Not recorded"
NOT_PROVIDED = "Not provided"

PARTICULAR_FIELDS: List[Tuple[str, str]] = [
    ("case_number", "Case / reference number"),
    ("agency", "Agency / laboratory"),
    ("examiner_name", "Examiner"),
    ("designation", "Designation"),
    ("requesting_officer", "Requesting officer"),
    ("notes", "Notes from the examiner"),
]

CATEGORIES: List[Tuple[str, str]] = [
    ("upi_all", "Payments and banking transactions"),
    ("chats_all", "Messages"),
    ("calls_all", "Calls"),
    ("contacts_all", "Contacts"),
]


def now_stamps() -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    return {
        "utc": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "ist": now.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST (+05:30)"),
    }


def integrity_state(hashes: Dict[str, Any]) -> Tuple[str, str]:
    """MATCH, MISMATCH or NOT RECORDED, with the sentence that goes next to it."""
    if not hashes.get("sha256") or not hashes.get("postIngestionSha256"):
        return "NOT RECORDED", "A hash before or after processing is missing, so no comparison was made."
    if hashes.get("integrityMatch"):
        return "MATCH", "SHA-256 and MD5 of the evidence were identical before and after processing."
    return "MISMATCH", "The evidence hash changed during processing. Do not rely on this output until that is explained."


def limitations(processing_log: List[Dict[str, Any]], hashes: Dict[str, Any]) -> List[str]:
    """What the software could not do or did not finish, taken from the processing log."""
    out: List[str] = []
    state, text = integrity_state(hashes)
    if state != "MATCH":
        out.append(f"Integrity comparison: {state}. {text}")
    for e in processing_log or []:
        status = str(e.get("status", "")).upper()
        if status in ("FAILED", "WARNING", "ENCRYPTED_NO_KEY"):
            label = {"FAILED": "Failed", "WARNING": "Warning", "ENCRYPTED_NO_KEY": "Encrypted, no key"}[status]
            out.append(f"{label}: {e.get('stage', '?')} / {e.get('file', '?')}: {e.get('error', '') or 'no detail recorded'}")
    return out


def _item_facts(it: Dict[str, Any]) -> Dict[str, Any]:
    """The evidence and device facts of one evidence item."""
    h = it.get("hashes") or {}
    d = it.get("device") or {}
    state, state_text = integrity_state(h)
    return {
        "item_id": it.get("item_id") or NOT_RECORDED,
        "label": it.get("label") or NOT_RECORDED,
        "evidence": {
            "source_path": it.get("source_path") or NOT_RECORDED,
            "size_bytes": h.get("fileSizeBytes"),
            "sha256_before": h.get("sha256") or NOT_RECORDED,
            "md5_before": h.get("md5") or NOT_RECORDED,
            "sha256_after": h.get("postIngestionSha256") or NOT_RECORDED,
            "md5_after": h.get("postIngestionMd5") or NOT_RECORDED,
            "comparison": state,
            "comparison_text": state_text,
        },
        "device": {
            "model": d.get("model") or NOT_RECORDED,
            "manufacturer": d.get("manufacturer") or NOT_RECORDED,
            "os_version": d.get("androidVersion") or NOT_RECORDED,
            "build": d.get("buildNumber") or NOT_RECORDED,
            "serial": d.get("serialNumber") or NOT_RECORDED,
            "imei": d.get("imei1") or NOT_RECORDED,
            "acquisition_time": d.get("acquisitionTime") or NOT_RECORDED,
        },
    }


def build_facts(
    case_state: Dict[str, Any],
    counts: Dict[str, Any],
    findings: List[Dict[str, Any]],
    audit: Dict[str, Any],
    particulars: Optional[Dict[str, Any]],
    environment: Dict[str, Any],
    tags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """The annexure: every fact the report prints, as plain data."""
    hashes = case_state.get("hashes") or {}
    dev = case_state.get("device_metadata") or {}
    state, state_text = integrity_state(hashes)
    plog = case_state.get("processing_log") or []
    items = case_state.get("items") or []
    if len(items) > 1:
        # Several devices in one case: every statement is made per item, never for "the" evidence.
        ev_items = [_item_facts(it) for it in items]
        lim: List[str] = []
        for it in items:
            lim += [f"[{it.get('item_id')}] {x}" for x in limitations(it.get("processing_log") or [], it.get("hashes") or {})]
    else:
        ev_items = None
        lim = limitations(plog, hashes)
    parts = {k: str((particulars or {}).get(k) or "").strip() for k, _ in PARTICULAR_FIELDS}
    return {
        "generated": now_stamps(),
        "case": {"id": case_state.get("case_id") or NOT_RECORDED, "name": case_state.get("case_name") or NOT_RECORDED},
        "particulars": {k: (v or NOT_PROVIDED) for k, v in parts.items()},
        "evidence_items": ev_items,
        "evidence": None if ev_items else {
            "source_path": case_state.get("evidence_path") or NOT_RECORDED,
            "size_bytes": hashes.get("fileSizeBytes"),
            "sha256_before": hashes.get("sha256") or NOT_RECORDED,
            "md5_before": hashes.get("md5") or NOT_RECORDED,
            "sha256_after": hashes.get("postIngestionSha256") or NOT_RECORDED,
            "md5_after": hashes.get("postIngestionMd5") or NOT_RECORDED,
            "comparison": state,
            "comparison_text": state_text,
        },
        "device": None if ev_items else {
            "model": dev.get("model") or NOT_RECORDED,
            "manufacturer": dev.get("manufacturer") or NOT_RECORDED,
            "os_version": dev.get("androidVersion") or NOT_RECORDED,
            "build": dev.get("buildNumber") or NOT_RECORDED,
            "serial": dev.get("serialNumber") or NOT_RECORDED,
            "imei": dev.get("imei1") or NOT_RECORDED,
            "acquisition_time": dev.get("acquisitionTime") or NOT_RECORDED,
        },
        "environment": environment,
        "counts": {
            key: {
                "label": label,
                "active": (counts.get(key) or {}).get("active", 0),
                "recovered": (counts.get(key) or {}).get("wal_and_carved", 0),
                "total": (counts.get(key) or {}).get("total", 0),
            }
            for key, label in CATEGORIES
        },
        "processing": {
            "ok": sum(1 for e in plog if str(e.get("status", "")).upper() == "OK"),
            "failed": sum(1 for e in plog if str(e.get("status", "")).upper() == "FAILED"),
            "warnings": sum(1 for e in plog if str(e.get("status", "")).upper() == "WARNING"),
            "log": plog,
        },
        "limitations": lim,
        "findings": findings,
        "tags": tags or {"available": False},
        "audit": audit,
    }


# --------------------------------------------------------------------------------------------- HTML
_e = html.escape

_CSS = """
body{font-family:Georgia,'Times New Roman',serif;line-height:1.5;color:#111;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.6rem;margin:.2rem 0}h2{font-size:1.1rem;border-bottom:1px solid #444;margin-top:1.6rem;padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.92rem}th,td{border:1px solid #666;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#eee}.mono{font-family:Consolas,monospace;word-break:break-all}.ok{color:#065f46}.warn{color:#92400e}.bad{color:#991b1b;font-weight:bold}
.sig{margin-top:3rem;display:flex;gap:3rem}.sig div{flex:1;border-top:1px solid #000;padding-top:.3rem}
@media print{body{margin:0}}
"""


def _rows(pairs: List[Tuple[str, str]], mono: bool = False) -> str:
    cls = ' class="mono"' if mono else ""
    return "".join(f"<tr><th style='width:32%'>{_e(k)}</th><td{cls}>{_e(str(v))}</td></tr>" for k, v in pairs)


def _source_text(src: Dict[str, Any]) -> str:
    if not isinstance(src, dict) or not src:
        return NOT_RECORDED
    return "; ".join(f"{k}: {v}" for k, v in sorted(src.items()))


# Sections the examiner may leave out of the report. The evidence and hashes, the limitations and the audit log
# are always included: a report must not be able to hide what was not read or what the examiner did.
OPTIONAL_SECTIONS = {
    "particulars": "Case particulars",
    "device": "Device, as recorded in the evidence",
    "environment": "Tool and processing environment",
    "counts": "Records found",
    "findings": "Findings pinned by the examiner",
    "tags": "Records tagged by the examiner",
}
REQUIRED_SECTIONS = ("evidence", "limitations", "audit")


def render_report_html(f: Dict[str, Any], sections: Optional[List[str]] = None) -> str:
    """``sections`` lists the optional sections to include; None means all of them. Required sections are always there.
    The report names the sections that were left out, so a reader knows they exist."""
    chosen = set(OPTIONAL_SECTIONS) if sections is None else {s for s in sections if s in OPTIONAL_SECTIONS}
    env, au = f["environment"], f["audit"]
    many = f.get("evidence_items")
    units = many if many else [{"item_id": None, "label": None, "evidence": f["evidence"], "device": f["device"]}]

    def _evidence_table(u: Dict[str, Any]) -> str:
        ev = u["evidence"]
        cls = {"MATCH": "ok", "MISMATCH": "bad"}.get(ev["comparison"], "warn")
        size = ev.get("size_bytes")
        size_txt = f"{int(size):,} bytes" if isinstance(size, int) else NOT_RECORDED
        head = f"<h3>{_e(str(u['item_id']))}: {_e(str(u['label']))}</h3>" if many else ""
        return head + f"""<table>{_rows([("Source", ev['source_path']), ("Size", size_txt), ("SHA-256 before processing", ev['sha256_before']), ("MD5 before processing", ev['md5_before']),
 ("SHA-256 after processing", ev['sha256_after']), ("MD5 after processing", ev['md5_after'])], mono=True)}
<tr><th>Comparison</th><td class="{cls}"><strong>{_e(ev['comparison'])}</strong>: {_e(ev['comparison_text'])}</td></tr></table>"""

    def _device_table(u: Dict[str, Any]) -> str:
        dev = u["device"]
        head = f"<h3>{_e(str(u['item_id']))}: {_e(str(u['label']))}</h3>" if many else ""
        return head + f"""<table>{_rows([("Model", dev['model']), ("Manufacturer", dev['manufacturer']), ("OS version", dev['os_version']), ("Build", dev['build']),
 ("Serial number", dev['serial']), ("IMEI", dev['imei']), ("Acquisition time", dev['acquisition_time'])])}</table>"""

    evidence_html = "".join(_evidence_table(u) for u in units)
    device_html = "".join(_device_table(u) for u in units)

    count_rows = "".join(
        f"<tr><td>{_e(c['label'])}</td><td>{c['active']}</td><td>{c['recovered']}</td><td>{c['total']}</td></tr>"
        for c in f["counts"].values()
    )
    lim = f["limitations"]
    lim_html = ("<ul>" + "".join(f"<li>{_e(x)}</li>" for x in lim) + "</ul>") if lim else \
        "<p>The processing log recorded no failures or warnings. This does not mean every file in the evidence was decoded: only files a parser exists for are read.</p>"
    fnd = f["findings"]
    if fnd:
        fnd_html = "<table><tr><th>#</th><th>Item</th><th>Examiner's note</th><th>Where it came from</th></tr>" + "".join(
            f"<tr><td>{i}</td><td>{_e(str(x.get('title','')))}<br><small>{_e(str(x.get('kind','')))} {_e(str(x.get('record_id','')))}</small></td>"
            f"<td>{_e(str(x.get('note','')) or NOT_PROVIDED)}</td><td class='mono'>{_e(_source_text(x.get('source', {})))}</td></tr>"
            for i, x in enumerate(fnd, 1)
        ) + "</table>"
    else:
        fnd_html = "<p>No findings were pinned.</p>"
    tg = f.get("tags") or {}
    if tg.get("available") and (tg.get("detached_total") or any(t["count"] for t in tg["tags"])):
        tag_rows = "".join(f"<tr><td>{_e(t['tag'])}</td><td>{t['count']}</td><td>{t['detached']}</td></tr>" for t in tg["tags"] if t["count"])
        rel = "".join(
            f"<tr><td>{_e(str(r['table']))} #{r['id']}</td><td>{_e(str(r['evidence_item'] or NOT_RECORDED))}</td><td>{_e(str(r['summary'] or ''))}</td>"
            f"<td class='mono'>{_e(str(r['provenance'] or NOT_RECORDED))}</td><td>{_e(str(r['note'] or ''))}</td></tr>" for r in tg["relied_upon"])
        more_rel = tg["relied_upon_total"] - len(tg["relied_upon"])
        tags_html = (
            "<p>Tags are the examiner's decisions; the software applies none by itself.</p>"
            f"<table><tr><th>Tag</th><th>Records</th><th>Not placed on a record</th></tr>{tag_rows}</table>"
            + (f"<h3>Records relied upon</h3><table><tr><th>Record</th><th>Evidence item</th><th>Content when tagged</th><th>Where it came from</th><th>Note</th></tr>{rel}</table>" if rel else "<p>No record is tagged as relied upon.</p>")
            + (f"<p>{more_rel} further relied-upon record(s) are not listed here.</p>" if more_rel > 0 else "")
            + (f"<p>{tg['relied_upon_withheld_privileged']} relied-upon record(s) also carry the privileged tag and are not listed.</p>" if tg["relied_upon_withheld_privileged"] else "")
            + (f"<p>{tg['relied_upon_detached']} relied-upon tag(s) could not be placed on a record after the evidence was processed again and are not listed.</p>" if tg["relied_upon_detached"] else ""))
    else:
        tags_html = "<p>No records were tagged.</p>"
    entries = au.get("entries") or []
    shown = entries[:500]
    audit_rows = "".join(
        f"<tr><td>{x['seq']}</td><td>{_e(x['ts_utc'])}</td><td>{_e(x['actor'])}</td><td>{_e(x['action'])}</td></tr>" for x in shown
    )
    more = f"<p>{len(entries) - len(shown)} further entries are in the audit file.</p>" if len(entries) > len(shown) else ""
    audit_state = "VERIFIED" if au.get("verified") else "FAILED"
    audit_cls = "ok" if au.get("verified") else "bad"
    fail_log = [x for x in f["processing"]["log"] if str(x.get("status", "")).upper() in ("FAILED", "WARNING")]
    log_rows = "".join(
        f"<tr><td>{_e(str(x.get('status')))}</td><td>{_e(str(x.get('stage')))}</td><td class='mono'>{_e(str(x.get('file')))}</td><td>{_e(str(x.get('error') or ''))}</td></tr>"
        for x in fail_log[:200]
    )

    parts: List[Tuple[str, str, str]] = [
        ("particulars", "Case particulars (as entered by the examiner)",
         f"""<table>{_rows([("Case ID (in this tool)", f['case']['id']), ("Case name", f['case']['name'])] + [(label, f['particulars'][k]) for k, label in PARTICULAR_FIELDS])}</table>"""),
        ("evidence", "Evidence and hashes", evidence_html),
        ("device", "Device, as recorded in the evidence", device_html),
        ("environment", "Tool and processing environment", f"<table>{_rows([(k, v) for k, v in env.items()])}</table>"),
        ("counts", "Records found",
         f"<table><tr><th>Category</th><th>Active</th><th>Recovered (WAL / carved)</th><th>Total</th></tr>{count_rows}</table>"),
        ("limitations", "Limitations",
         lim_html + f"""
<p>Processing steps: {f['processing']['ok']} completed, {f['processing']['failed']} failed, {f['processing']['warnings']} warnings.</p>
{('<table><tr><th>Status</th><th>Stage</th><th>File</th><th>Detail</th></tr>' + log_rows + '</table>') if log_rows else ''}"""),
        ("findings", "Findings pinned by the examiner", fnd_html),
        ("tags", "Records tagged by the examiner", tags_html),
        ("audit", "Audit log", f"""<p>Entries: {len(entries)}. Chain check: <strong class="{audit_cls}">{audit_state}</strong>{(' (' + _e(au.get('error','')) + ')') if au.get('error') else ''}.
Head hash at the time of this report: <span class="mono">{_e(str(au.get('head_hash','')))}</span></p>
<table><tr><th>#</th><th>Time (UTC)</th><th>By</th><th>Action</th></tr>{audit_rows}</table>{more}"""),
    ]
    shown_parts = [p for p in parts if p[0] in REQUIRED_SECTIONS or p[0] in chosen]
    left_out = [OPTIONAL_SECTIONS[p[0]] for p in parts if p[0] in OPTIONAL_SECTIONS and p[0] not in chosen]
    body_html = "\n\n".join(f"<h2>{i}. {_e(title)}</h2>{html_}" for i, (_, title, html_) in enumerate(shown_parts, 1))
    if left_out:
        body_html += "\n\n<p><em>Sections the examiner chose not to include in this copy of the report: " + _e("; ".join(left_out)) + ".</em></p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Examination report: {_e(str(f['case']['id']))}</title>
<style>{_CSS}</style></head><body>
<h1>Examination report</h1>
<p>Generated {_e(f['generated']['utc'])} ({_e(f['generated']['ist'])}). This report lists what the software recorded for this case.
It contains no opinion and makes no declaration. Any legal form a court or agency requires is prepared and signed by the examiner.</p>

{body_html}

<div class="sig"><div>Examiner name and signature:</div><div>Date:</div></div>
</body></html>"""


# --------------------------------------------------------------------------------------------- CSV / JSON
def _cell(v: Any) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_facts_csv(f: Dict[str, Any]) -> str:
    """Flat field,value rows for copying into the lab's own form."""
    rows: List[Tuple[str, Any]] = [("generated_utc", f["generated"]["utc"]), ("generated_ist", f["generated"]["ist"])]
    for sect in ("case", "particulars", "evidence", "device", "environment"):
        for k, v in (f.get(sect) or {}).items():
            rows.append((f"{sect}.{k}", v))
    for u in f.get("evidence_items") or []:
        for sect in ("evidence", "device"):
            for k, v in u[sect].items():
                rows.append((f"evidence_items.{u['item_id']}.{sect}.{k}", v))
        rows.append((f"evidence_items.{u['item_id']}.label", u["label"]))
    for k, c in f["counts"].items():
        rows.append((f"counts.{k}", f"active={c['active']} recovered={c['recovered']} total={c['total']}"))
    tg = f.get("tags") or {}
    if tg.get("available"):
        for t in tg["tags"]:
            if t["count"]:
                rows.append((f"tags.{t['tag']}", f"records={t['count']} not_placed={t['detached']}"))
        rows.append(("tags.relied_upon_listed", tg["relied_upon_total"]))
        rows.append(("tags.relied_upon_not_listed_privileged", tg["relied_upon_withheld_privileged"]))
    p = f["processing"]
    rows += [("processing.ok", p["ok"]), ("processing.failed", p["failed"]), ("processing.warnings", p["warnings"])]
    rows += [(f"limitation.{i}", x) for i, x in enumerate(f["limitations"], 1)]
    rows += [("audit.entries", len(f["audit"].get("entries") or [])), ("audit.verified", f["audit"].get("verified")),
             ("audit.head_hash", f["audit"].get("head_hash"))]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["field", "value"])
    for k, v in rows:
        w.writerow([_cell(k), _cell(v)])
    return buf.getvalue()


def render_facts_json(f: Dict[str, Any]) -> str:
    return json.dumps(f, indent=2, sort_keys=True, ensure_ascii=False, default=str)
