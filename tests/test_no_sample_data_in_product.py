"""The shipped product carries no sample data: fixtures live under test_evidence/ and tests/, and are not packaged."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRODUCT_DIRS = ["parsers", "src", os.path.join("ui", "renderer"), "electron"]
# values that only ever came from the sample-data generators
FIXTURE_LITERALS = re.compile(r"Vikram Boss|Rajesh Verma|mule_account\d|TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf|FIR/CYB/2026|Cyber Crime PS")
ALLOWED = {os.path.join("parsers", "validation.py")}          # builds its own known-answer inputs on purpose


def _files():
    for d in PRODUCT_DIRS:
        for base, _, names in os.walk(os.path.join(ROOT, d)):
            if "__pycache__" in base:
                continue
            for n in names:
                if n.endswith((".py", ".ts", ".tsx", ".cjs", ".json")):
                    yield os.path.join(base, n)


def test_product_code_has_no_fixture_values():
    hits = []
    for p in _files():
        rel = os.path.relpath(p, ROOT)
        if rel in ALLOWED:
            continue
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                if FIXTURE_LITERALS.search(line):
                    hits.append(f"{rel}:{i}")
    assert not hits, hits


def test_packaging_does_not_ship_fixtures():
    for cfg in ("electron-builder.yml", "bharat_backend.spec"):
        text = open(os.path.join(ROOT, cfg), encoding="utf-8").read()
        for bad in ("test_evidence", "tests/", "scripts/", "scratch"):
            assert bad not in text, f"{cfg} mentions {bad}"


def test_no_mock_data_generator_in_scripts():
    assert not os.path.exists(os.path.join(ROOT, "scripts", "create_mock_db.py"))
