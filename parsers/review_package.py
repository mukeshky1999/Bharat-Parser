"""Portable review package: selected files plus a manifest and an offline viewer, for a reviewer who has no workstation.

Rules, in the order they are applied:
1. FAIL CLOSED. Every item needs an explicit disposition. If any item has none, or an unknown one, nothing is
   written. There is no default.
2. Files marked INCLUDE are copied byte for byte. Every other disposition is withheld: no bytes are written, only a
   notice card carrying the name, hashes and the reason.
3. Masking terms (for example a person's name) are removed from names, notes, notice cards and the viewer,
   case-insensitively. File CONTENTS are never altered; an INCLUDE file that mentions a masked term still mentions it.
4. File names inside the package are index-based and sanitised, and every write is checked to stay inside the package.
5. Tags: an INCLUDE file that is named in the provenance of records the examiner tagged privileged, complainant
   or excluded is refused unless the caller acknowledges it, and the flag is written beside the file in the manifest
   and the viewer. The tool does not decide; it makes the examiner look.
6. The manifest records SHA-256/MD5 of each original (including withheld ones), a Merkle root, and the audit-log head
   hash when one is given.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.audit.manifest import HashManifest

INCLUDE = "INCLUDE"
WITHHOLD_SENSITIVE = "WITHHOLD_SENSITIVE"
WITHHOLD_PRIVILEGED = "WITHHOLD_PRIVILEGED"
WITHHOLD_NOT_RELIED_UPON = "WITHHOLD_NOT_RELIED_UPON"
DISPOSITIONS = (INCLUDE, WITHHOLD_SENSITIVE, WITHHOLD_PRIVILEGED, WITHHOLD_NOT_RELIED_UPON)

_REASON = {
    WITHHOLD_SENSITIVE: "Sensitive content: not copied. The original stays with the examiner for supervised inspection.",
    WITHHOLD_PRIVILEGED: "Privileged or protected: not copied.",
    WITHHOLD_NOT_RELIED_UPON: "Not relied upon: not copied.",
}


# The viewer's only script: it reads the marks the reviewer entered and offers them as a file. It makes no network call.
_VIEWER_SCRIPT = """(function(){
var PKG="__PACKAGE_ID__";
function collect(){var out=[];document.querySelectorAll("tr[data-index]").forEach(function(tr){
var label=tr.querySelector("select").value,note=tr.querySelector("input").value;
if(label||note.trim()){out.push({index:tr.getAttribute("data-index"),sha256:tr.getAttribute("data-sha"),label:label,note:note});}});return out;}
window.buildMarks=function(){return JSON.stringify({kind:"reviewer_marks",schema:1,package_id:PKG,reviewer:document.getElementById("rv").value,
reviewer_clock:new Date().toISOString(),marks:collect()},null,2);};
document.getElementById("save").onclick=function(){var b=new Blob([window.buildMarks()],{type:"application/json"});
var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="reviewer_marks.json";document.body.appendChild(a);a.click();a.remove();};
})();"""


class PackageRefused(ValueError):
    """The package was not built; nothing was written."""


@dataclass
class PackageItem:
    source_path: str
    disposition: Optional[str] = None
    note: str = ""
    display_name: str = ""
    tag_flags: Optional[Dict[str, int]] = None   # e.g. {"privileged": 3}: records of this file the examiner tagged


@dataclass
class PackageResult:
    directory: str
    viewer_path: str
    manifest_path: str
    included: int
    withheld: int
    merkle_root: str
    package_id: str = ""                                   # SHA-256 of manifest.json: what the reviewer's marks are bound to
    entries: Optional[List[Dict[str, str]]] = None         # index, name, sha256 of each item


def _safe_component(name: str, index: int) -> str:
    base = os.path.basename(str(name).replace("\\", "/")).strip().strip(".")
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)
    return f"{index:03d}_{base or 'item'}"


def _write_inside(directory: str, filename: str, data: bytes) -> str:
    directory = os.path.abspath(directory)
    dest = os.path.abspath(os.path.join(directory, filename))
    if os.path.dirname(dest) != directory:
        raise PackageRefused(f"Refusing to write outside the package: {filename}")
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest


def build_package(
    case_id: str,
    items: List[PackageItem],
    output_dir: str,
    mask_terms: Optional[List[str]] = None,
    audit_head: str = "",
    acknowledge_tagged: bool = False,
) -> PackageResult:
    if not items:
        raise PackageRefused("No items were selected.")
    terms = [t.strip() for t in (mask_terms or []) if t and t.strip()]
    short = [t for t in terms if len(t) < 3]
    if short:
        raise PackageRefused("A masking term needs at least 3 characters (a shorter one would damage unrelated words): "
                             + ", ".join(repr(t) for t in short))

    # ---- validate everything before writing anything
    missing = [os.path.basename(i.source_path) for i in items if i.disposition is None]
    if missing:
        raise PackageRefused("Every item needs an explicit decision (INCLUDE or a withhold reason). "
                             "No decision for: " + ", ".join(missing))
    unknown = [f"{os.path.basename(i.source_path)}={i.disposition}" for i in items if i.disposition not in DISPOSITIONS]
    if unknown:
        raise PackageRefused("Unknown disposition: " + ", ".join(unknown))
    flagged = [os.path.basename(i.source_path) + " (" + ", ".join(f"{k}: {v}" for k, v in sorted(i.tag_flags.items())) + ")"
               for i in items if i.disposition == INCLUDE and i.tag_flags]
    if flagged and not acknowledge_tagged:
        raise PackageRefused("These files hold records the examiner tagged privileged, complainant or excluded: " + "; ".join(flagged)
                             + ". Withhold them, or build again with the tag warning acknowledged. Nothing was written.")
    unreadable = [os.path.basename(i.source_path) for i in items if not os.path.isfile(i.source_path)]
    if unreadable:
        raise PackageRefused("File not found: " + ", ".join(unreadable))
    final = os.path.abspath(output_dir)
    if os.path.exists(final) and os.listdir(final):
        raise PackageRefused("The package folder already exists and is not empty. Nothing was changed.")
    # Built beside the final folder and moved into place only when complete, so a failure leaves nothing half-made.
    out = final + ".building-" + uuid.uuid4().hex[:8]
    try:
        return _build_into(out, final, case_id, items, terms, audit_head, acknowledge_tagged)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_into(out: str, final: str, case_id: str, items: List[PackageItem], terms: List[str], audit_head: str,
                acknowledge_tagged: bool) -> PackageResult:
    # One pass, longest term first, so "Ramesh Kumar" is not half-replaced by an earlier "Ram"; the marker number is the
    # position of the term in the examiner's list.
    number = {t.lower(): n for n, t in reversed(list(enumerate(terms, 1)))}
    pattern = re.compile("|".join(re.escape(t) for t in sorted(set(terms), key=len, reverse=True)), re.IGNORECASE) if terms else None

    def mask(text: object) -> str:
        t = str(text)
        return pattern.sub(lambda m: f"[REDACTED_{number[m.group(0).lower()]:02d}]", t) if pattern else t

    def esc(text: object) -> str:
        return html.escape(mask(text), quote=True)

    manifest = HashManifest()
    for idx, it in enumerate(items, 1):
        manifest.add_file(f"{idx:03d}", it.source_path)

    os.makedirs(os.path.join(out, "exhibits"), exist_ok=True)
    entries: List[Dict[str, str]] = []
    included = withheld = 0
    for idx, it in enumerate(items, 1):
        mi = manifest.items[f"{idx:03d}"]
        shown = mask(it.display_name or os.path.basename(it.source_path))
        safe = _safe_component(shown, idx)
        entry = {"index": f"{idx:03d}", "name": shown, "disposition": it.disposition, "sha256": mi.sha256,
                 "md5": mi.md5, "size_bytes": str(mi.byte_size), "note": mask(it.note), "file": "",
                 "tagged_records": ", ".join(f"{k}: {v}" for k, v in sorted((it.tag_flags or {}).items()))}
        if it.disposition == INCLUDE:
            dest = os.path.join(out, "exhibits", safe)
            if os.path.dirname(os.path.abspath(dest)) != os.path.join(out, "exhibits"):
                raise PackageRefused(f"Refusing to write outside the package: {safe}")
            shutil.copyfile(it.source_path, dest)
            if _sha256_file(dest) != mi.sha256:
                raise PackageRefused(f"The copy of {os.path.basename(it.source_path)} does not match the file that was hashed "
                                     "(it changed while the package was being built). Nothing was kept.")
            entry["file"] = "exhibits/" + safe
            included += 1
        else:
            stem = os.path.splitext(safe)[0]
            card = (
                "WITHHELD ITEM\n=============\n"
                f"Name: {shown}\nSHA-256 of the original: {mi.sha256}\nMD5 of the original: {mi.md5}\n"
                f"Size: {mi.byte_size} bytes\nDecision: {it.disposition}\nReason: {_REASON[it.disposition]}\n"
                f"Examiner note: {mask(it.note) or 'none'}\n"
            )
            card_name = f"{stem}_WITHHELD.txt"
            _write_inside(os.path.join(out, "exhibits"), card_name, card.encode("utf-8"))
            entry["file"] = "exhibits/" + card_name
            withheld += 1
        entries.append(entry)

    root = manifest.merkle_root()
    meta = {
        "case_id": mask(case_id), "items": entries, "merkle_root": root, "audit_head_hash": audit_head or "Not recorded",
        "tag_warning_acknowledged": bool(acknowledge_tagged and any(i.tag_flags and i.disposition == INCLUDE for i in items)),
        "masking": f"{len(terms)} term(s) masked in names, notes and cards. File contents are not altered.",
    }
    manifest_path = _write_inside(out, "manifest.json", json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))

    package_id = hashlib.sha256(open(manifest_path, "rb").read()).hexdigest()
    rows = "".join(
        f"<tr data-index=\"{e['index']}\" data-sha=\"{e['sha256']}\"><td>{e['index']}</td><td>{esc(e['name'])}</td><td>{esc(e['disposition'])}</td>"
        f"<td><a href=\"{html.escape(e['file'], quote=True)}\">{html.escape(e['file'])}</a></td>"
        f"<td class=\"m\">{e['sha256']}</td><td>{esc(e['note'])}{(' [records tagged: ' + esc(e['tagged_records']) + ']') if e['tagged_records'] else ''}</td>"
        "<td><select aria-label=\"Your mark\"><option value=\"\">no mark</option><option value=\"relevant\">relevant</option>"
        "<option value=\"not_relevant\">not relevant</option><option value=\"needs_clarification\">needs clarification</option></select> "
        "<input type=\"text\" maxlength=\"2000\" aria-label=\"Your note\" placeholder=\"note\"></td></tr>" for e in entries
    )
    script = _VIEWER_SCRIPT.replace("__PACKAGE_ID__", package_id)
    script_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    viewer = (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'\">"
        f"<title>Review package {esc(case_id)}</title><style>body{{font-family:sans-serif;margin:1.5rem}}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #666;padding:.3rem;text-align:left}"
        ".m{font-family:Consolas,monospace;font-size:.8rem;word-break:break-all}</style></head><body>"
        f"<h1>Review package: {esc(case_id)}</h1>"
        f"<p>{included} file(s) included, {withheld} withheld. {html.escape(meta['masking'])}</p>"
        f"<p>Merkle root of the originals: <span class=\"m\">{root}</span><br>"
        f"Audit log head hash: <span class=\"m\">{html.escape(meta['audit_head_hash'])}</span></p>"
        "<p>Reviewer: you can mark each item and save your marks as a small file to send back to the examiner. "
        "Your marks are suggestions; the examiner decides what to do with them. Your name and your computer's clock are recorded as you give them.</p>"
        "<p><label>Your name <input id=\"rv\" type=\"text\" maxlength=\"120\"></label> "
        "<button id=\"save\" type=\"button\">Save my marks</button></p>"
        "<table><tr><th>#</th><th>Name</th><th>Decision</th><th>File</th><th>SHA-256 of original</th><th>Note</th><th>Your mark</th></tr>"
        f"{rows}</table><p class=\"m\">Package id: {package_id}</p><script>{script}</script></body></html>"
    )
    _write_inside(out, "index.html", viewer.encode("utf-8"))
    if os.path.isdir(final):
        os.rmdir(final)                      # it was empty (checked above)
    os.replace(out, final)
    viewer_path = os.path.join(final, "index.html")
    manifest_path = os.path.join(final, "manifest.json")
    return PackageResult(final, viewer_path, manifest_path, included, withheld, root, package_id,
                         [{"index": e["index"], "name": e["name"], "sha256": e["sha256"]} for e in entries])
