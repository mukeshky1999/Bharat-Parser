"""Runs one parser tree over a folder of databases and writes a JSON summary of what each file yields.
Run it once per tree (for example an older snapshot and the current one) over the same evidence, then diff the two JSON files.
usage: python tools/compare_parser_trees.py <parser_root> <evidence_root> <out.json>"""
usage: python run_parsers.py <parser_root> <evidence_root> <out.json>"""
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")
root, evidence, out = sys.argv[1], sys.argv[2], sys.argv[3]
os.chdir(root)
sys.path.insert(0, root)
from parsers.heuristic_engine import parse_database_artifacts  # noqa: E402

res = {}
for d, _, files in os.walk(evidence):
    for f in sorted(files):
        if f.endswith(("-wal", "-shm", "-journal")) or not (f.endswith((".db", ".sqlite", ".sqlite3")) or "." not in f):
            continue
        p = os.path.join(d, f)
        label = os.path.relpath(d, evidence).replace("\\", "/")
        try:
            arts = parse_database_artifacts(p, "android", label)
        except Exception as exc:
            res[os.path.relpath(p, evidence)] = {"ERROR": f"{type(exc).__name__}: {exc}"}
            continue
        entry = {}
        for k, df in arts.items():
            if df is None or not hasattr(df, "shape") or df.shape[0] == 0:
                continue
            cols = [c for c in ("Transaction_ID", "Amount", "Counterparty", "Status", "Type", "Message_Body", "Direction", "Display_Name", "Identifier") if c in df.columns]
            rows = sorted(json.dumps([None if (v != v) else str(v) for v in r], ensure_ascii=False) for r in df[cols].itertuples(index=False, name=None))
            entry[k] = {"count": int(df.shape[0]), "cols": cols, "rows": rows}
        res[os.path.relpath(p, evidence)] = entry
json.dump(res, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print("files:", len(res))
