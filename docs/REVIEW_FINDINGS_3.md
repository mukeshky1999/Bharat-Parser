# Review Findings 3: the code written in Phases 5A to 5C

Review date: 2026-11-12. Scope: the parts that had no independent review: the case file, search, tags, timeline, media,
saved filters, review package and marks, examination report, bank alerts, encrypted-database ingest, row locator,
validation record, `src/audit`, the routes added to `parsers/api_server.py`, the Electron shell after the X-09 work,
the React views added in 5C, and packaging. Three reviewers read the code (backend modules, API server with Electron
and packaging, React renderer); the serious items below were checked against the code again by the author before
being fixed. Reading was done on the working tree at `cd4973a`; nothing was run against a real device extraction.

"CONFIRMED" means the code path proves it or it was reproduced by a test that failed on the old code.
"SUSPECTED" means the code allows it and it was not reproduced.

Baseline before any change: `pytest tests --ignore=tests/e2e` 636 passed; `tsc --noEmit` clean.

## 1. What was clean

No SQL injection (every table or column name comes from an allow-list or `sqlite_master`); no path traversal in
`safe_case_dir_name`, the package file writer or the thumbnail path check; the Merkle tree carries an odd node up
instead of duplicating it; the token middleware covered every `/api/*` route; `RowLocator` WAL offsets are right;
no key is stored or logged in the renderer; the report preview iframe is sandboxed.

## 2. Findings and what was done

IDs: N-xx backend, server and shell; U-xx renderer. Fix commits are `Review step n` in `git log`.

### High

| ID | Where | Defect | Status |
|---|---|---|---|
| N-01 | `MuleLinkGraphTab.tsx` | Graph HTML (loaded verbatim from a case file) ran in a frame with `allow-scripts allow-same-origin`: it could read the API token and call the IPC bridge | FIXED step 1 (`allow-scripts` only; a test fails if `allow-same-origin` appears anywhere in the renderer). Graph HTML is still stored in the case file; with the opaque origin it can no longer reach the app |
| N-02 | `api_server.py` workspace root | Cases lived in the code folder: unwritable under Program Files, deleted on exit for the portable build | FIXED step 2 (`BHARAT_WORKSPACE_ROOT`, else `%LOCALAPPDATA%\BharatAnalyzer\cases` when frozen) |
| N-03 | `validation.py` | The validation record swapped the open case, store and workspace with nothing keeping other requests out | FIXED step 4 (every other request is answered 409 while it runs; refused while an ingest runs) |
| N-04 | replace-mode ingest | Old working folders were deleted before the container check and hashing | FIXED step 3 (set aside, deleted only after success, restored on failure) |
| N-05 | replace-mode ingest | The case store was deleted, taking tags, reviewer marks, hash lists, saved filters | FIXED step 3 (only evidence records are replaced; tags are set aside and put back by provenance, and only when the new ingest is the same source) |
| N-06 | `case_tag_report.py` | Privileged / complainant / excluded checks ignored tags set aside by a re-process (fail-open) | FIXED step 6 (matched by the provenance the tag kept; untraceable ones are reported) |
| N-07 | `case_search.py` | A regex such as `((a+))+$` or `(a?){25}a{25}c` froze the whole backend | FIXED step 8 (`regex` package with a one-second limit per match; the search stops and says why) |
| N-08 | `src/audit/ledger.py` | The hash did not cover the printed times; `verify()` checked memory, not the file; fields were joined with `\|` | FIXED step 5 (hash v2 over one JSON list; `verify()` and every append read the file; truncation or edits are refused; old logs still verify) |
| N-09 | `safe_case_dir_name` | "FIR 12/2026" and "FIR_12_2026" shared a folder and an audit file | FIXED step 2 (folder name carries a hash of the exact id; old folders are used only if they record that id) |
| N-10 | `/api/case/open` | Any folder holding a `*.db` could be opened as a case; the store constructor changes the file | FIXED step 2 (only folders inside the cases folder, only `bharat_case_store.db`) |
| N-11 | fusion endpoints | `statement_path` / `cdr_path` read any file; a UNC path can leak the user's NTLM hash | FIXED step 7 (confined to the case; UNC refused everywhere) |
| N-12 | `electron/main.cjs` | No spawn error handler; backend orphaned when Electron crashed; no prompt when closing during an ingest | FIXED step 1 (error dialog, parent-process watchdog in the backend, confirmation while an ingest runs) |
| U-20 | `workbenchStore.ts` | Lists were replaced only when the new case had rows: case B showed case A's calls | FIXED step 10 |
| U-21 | `workbenchStore.ts` | The open record and bytes were not closed on a case change; Pin wrote the old record into the new case | FIXED step 10 |
| U-22 | `forensicClient.ts` | A failed read was returned as an empty list and read as "nothing found" | FIXED step 10 (`error` on the response, a banner naming what could not be read, the views throw) |
| U-23 | `RecordDetail` / `TagControls` | A late reply showed record A's fields under record B | FIXED step 10 |
| U-24 | `TimelineView.tsx` | IST-only events read "time not recorded"; UTC printed twice | FIXED step 10 |
| U-25 | `workbenchStore.ts` | Call parties were read from columns that do not exist: every call showed the other party as caller and "To: not recorded" | FIXED step 10 (parties follow the direction; unknown direction names neither; "Other party" column) |
| U-26 | `workbenchStore.ts` | A missing amount became 0; an unknown direction made payer and payee the same | FIXED step 10 |
| U-27 | several views | Overlapping requests: an older reply could overwrite a newer one (timeline, tags, search, media look-alikes, link graph, saved filters) | FIXED step 10 (`useLatestRequest`) |
| U-28 | `CommandPalette` / `SearchView` | "Search records for…" filled the box and ran nothing | FIXED step 10 |
| U-29 | three views | Static claims: "SHA-256 match validated", "Corroboration Engine Verified", "High-Value Target Indicator"; device-trace view had no data source | FIXED step 10 (the view now reads the case) |

### Medium

Fixed in steps 3 to 9: audit failures no longer pass silently (actions are refused while the log fails verification,
`tags_reattached` is written after the switch, one ledger per file); the case state and store switch together; the
ingest lock is held by the worker; package masking is one pass, longest term first, terms under three characters are
refused, copies are re-hashed, the package is built aside; the multi-device report tallies every device; bank alerts
(spoof indicator only for received messages, unplaceable times stay empty, raw value as read); SQLite URIs built with
`as_uri()` in about sixty places (a file named `notes#1.db` opened a different file); examiner keys are never cut by the
candidate cap; EXIF capture clock no longer falls back to the file's modification time; saved filters refuse NaN;
refusals are no longer turned into `success: false` or 500; an unreadable store is an error, not "no transactions";
analysis failures reach the processing log; dev server: docs off by default, root needs the token, origin `null`
allowed only with a token; CSP for the packaged window; frame navigation limited.

### Low

Fixed: hex view no longer re-parses the offset from a rebuilt string; links and junctions in evidence folders are not
followed; `shell:showItemInFolder` refuses `//host/share`; timeline bounds compared in one form; search says which
tables it could not search and bounds the offset; facts CSV matches the JSON; media re-analysis keeps ids and removes
thumbnails with their item; reviewer marks identified by content, duplicates refused; review package copies verified;
case listing is read-only and names an unreadable case; damaged case-file values are called damaged; validation
corpus errors are results; Tk dialogs run on one dedicated thread; the accounts query is chunked; the grid scrolls the
selected row clear of its header, shows focus, and counts its header row; CSV exports start with a byte-order mark and
keep plain negative numbers as numbers; crypto amounts are shown exactly as stored; `npm run test:python` uses the venv
and skips the e2e runner; the second client test file is run.

## 3. Not done, and why

- **Port 0 handshake and token off the command line** (Electron): the free port is still chosen by the shell and passed
  to the backend, and the token is still a renderer launch argument. A process running as the same user can read it.
  Moving both needs the backend to report its port on stdout and the token to travel by IPC; it was left because it is
  a change to how the two halves start, and the per-launch token, Host check and origin check already refuse a web page.
- **Dev mode without a token**: `npm run backend` still runs without a token when none is set (the plain-browser
  development flow has no way to receive one). The `null` origin and the docs routes are closed in that mode.
- **Graph HTML from a case file is still stored and served.** It can no longer reach the app (N-01), but it can still
  draw anything in its own frame. Regenerating it from the store on open would remove that.
- **Timeline "fixed" group** rests on the `Timestamp_IST` column being filled only by sources that fixed the instant
  (SUSPECTED defect upstream if a converter fills it from a zone-less string). Not changed.
- **Packaging**: found by building it. The frozen backend did not start at all, before and after this review's changes:
  Python 3.15 ships `python3t.dll` in `abi3t-compat/`, cryptography's `_rust.pyd` imports it, and PyInstaller does not
  bundle it ("DLL load failed while importing _rust"). The spec now bundles it, collects `src.*` and `parsers.*`, and turns
  UPX off. A backend built from the new spec (outside the repository) starts, answers `/api/health` with the token and
  401 without it, and creates its cases folder under `%LOCALAPPDATA%\BharatAnalyzer`. The installer itself (NSIS) and a
  per-machine install were not built or tried.
- **Electron was not driven by hand** for the new behaviours (close prompt, orphan watchdog, CSP). They are covered by
  source checks and by the watchdog unit test only.
- Each new test was written against the described failure; the stash-and-rerun check (that it fails on the old code)
  was not repeated for every one of them.
