"""Compares two JSON files written by compare_parser_trees.py and lists, per file and category, the rows only one tree produced.
usage: python tools/diff_parser_runs.py <old.json> <new.json>"""
import json
import sys

old, new = json.load(open(sys.argv[1], encoding="utf-8")), json.load(open(sys.argv[2], encoding="utf-8"))
differences = 0
for f in sorted(set(old) | set(new)):
    a, b = old.get(f, {}), new.get(f, {})
    if "ERROR" in a or "ERROR" in b:
        print(f, "error in one run:", a.get("ERROR"), "|", b.get("ERROR"))
        differences += 1
        continue
    for k in sorted(set(a) | set(b)):
        ra, rb = a.get(k, {}).get("rows", []), b.get(k, {}).get("rows", [])
        if ra == rb:
            continue
        differences += 1
        print(f"{f} [{k}]: first={len(ra)} rows, second={len(rb)} rows")
        for r in [x for x in ra if x not in rb][:10]:
            print("   only in first :", r[:200])
        for r in [x for x in rb if x not in ra][:10]:
            print("   only in second:", r[:200])
print("no differences" if not differences else f"{differences} difference(s)")
