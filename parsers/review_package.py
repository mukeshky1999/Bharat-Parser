"""Portable review package: selected files plus a manifest and an offline viewer, for a reviewer who has no workstation.

Rules, in the order they are applied:
1. FAIL CLOSED. Every item needs an explicit disposition. If any item has none, or an unknown one, nothing is
   written. There is no default.
2. Files marked INCLUDE are copied byte for byte. Every other disposition is withheld: no bytes are written, only a
   notice card carrying the name, hashes and the reason.
3. Masking terms (for example a person's name) are removed from names, notes, notice cards and the viewer,
   case-insensitively. File CONTENTS are never altered; an INCLUDE file that mentions a masked term still mentions it.
4. File names inside the package are index-based and sanitised, and every write is checked to stay inside the package.
5. The manifest records SHA-256/MD5 of each original (including withheld ones), a Merkle root, and the audit-log head
   hash when one is given.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
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


class PackageRefused(ValueError):
    """The package was not built; nothing was written."""


@dataclass
class PackageItem:
    source_path: str
    disposition: Optional[str] = None
    note: str = ""
    display_name: str = ""


@dataclass
class PackageResult:
    directory: str
    viewer_path: str
    manifest_path: str
    included: int
    withheld: int
    merkle_root: str


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
) -> PackageResult:
    if not items:
        raise PackageRefused("No items were selected.")
    terms = [t.strip() for t in (mask_terms or []) if t and t.strip()]

    # ---- validate everything before writing anything
    missing = [os.path.basename(i.source_path) for i in items if i.disposition is None]
    if missing:
        raise PackageRefused("Every item needs an explicit decision (INCLUDE or a withhold reason). "
                             "No decision for: " + ", ".join(missing))
    unknown = [f"{os.path.basename(i.source_path)}={i.disposition}" for i in items if i.disposition not in DISPOSITIONS]
    if unknown:
        raise PackageRefused("Unknown disposition: " + ", ".join(unknown))
    unreadable = [os.path.basename(i.source_path) for i in items if not os.path.isfile(i.source_path)]
    if unreadable:
        raise PackageRefused("File not found: " + ", ".join(unreadable))
    out = os.path.abspath(output_dir)
    if os.path.exists(out) and os.listdir(out):
        raise PackageRefused("The package folder already exists and is not empty. Nothing was changed.")

    def mask(text: object) -> str:
        t = str(text)
        for n, term in enumerate(terms, 1):
            t = re.sub(re.escape(term), f"[REDACTED_{n:02d}]", t, flags=re.IGNORECASE)
        return t

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
                 "md5": mi.md5, "size_bytes": str(mi.byte_size), "note": mask(it.note), "file": ""}
        if it.disposition == INCLUDE:
            dest = os.path.join(out, "exhibits", safe)
            if os.path.dirname(os.path.abspath(dest)) != os.path.join(out, "exhibits"):
                raise PackageRefused(f"Refusing to write outside the package: {safe}")
            shutil.copyfile(it.source_path, dest)
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
        "masking": f"{len(terms)} term(s) masked in names, notes and cards. File contents are not altered.",
    }
    manifest_path = _write_inside(out, "manifest.json", json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))

    rows = "".join(
        f"<tr><td>{e['index']}</td><td>{esc(e['name'])}</td><td>{esc(e['disposition'])}</td>"
        f"<td><a href=\"{html.escape(e['file'], quote=True)}\">{html.escape(e['file'])}</a></td>"
        f"<td class=\"m\">{e['sha256']}</td><td>{esc(e['note'])}</td></tr>" for e in entries
    )
    viewer = (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Review package {esc(case_id)}</title><style>body{{font-family:sans-serif;margin:1.5rem}}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #666;padding:.3rem;text-align:left}"
        ".m{font-family:Consolas,monospace;font-size:.8rem;word-break:break-all}</style></head><body>"
        f"<h1>Review package: {esc(case_id)}</h1>"
        f"<p>{included} file(s) included, {withheld} withheld. {html.escape(meta['masking'])}</p>"
        f"<p>Merkle root of the originals: <span class=\"m\">{root}</span><br>"
        f"Audit log head hash: <span class=\"m\">{html.escape(meta['audit_head_hash'])}</span></p>"
        "<table><tr><th>#</th><th>Name</th><th>Decision</th><th>File</th><th>SHA-256 of original</th><th>Note</th></tr>"
        f"{rows}</table></body></html>"
    )
    viewer_path = _write_inside(out, "index.html", viewer.encode("utf-8"))
    return PackageResult(out, viewer_path, manifest_path, included, withheld, root)
