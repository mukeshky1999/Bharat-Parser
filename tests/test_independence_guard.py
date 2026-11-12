"""Independence guard: product code must not cite another vendor's product as its design target.

Reading another tool's container formats (.ufdr, .xry, .ofb) is interoperability and is allowed; the
container type names and extension lists stay. What must not appear is wording that says our schema,
layout or behaviour is modelled on, or equal to, a named product.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = ["parsers", "src", "tools", "electron", "ui/renderer", "ui/shared"]
SUFFIXES = {".py", ".ts", ".tsx", ".cjs", ".css"}
BANNED = re.compile(
    r"Physical Analyzer|Cellebrite PA|Cellebrite[- ]Reader|Oxygen Forensic Detective|Magnet AXIOM|"
    r"Chainalysis|TRM Labs|\bPA[ _]schema|PA_CATEGORIZED|PAField|PATable|PAWorkbench|parity engine",
    re.IGNORECASE,
)


def test_no_vendor_design_target_wording():
    hits = []
    for d in SCAN_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.suffix not in SUFFIXES or "node_modules" in p.parts or "__pycache__" in p.parts:
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if BANNED.search(line):
                    hits.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not hits, "vendor product cited as a design target:\n" + "\n".join(hits)
