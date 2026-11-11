# Bharat Forensic Suite

Post-extraction mobile forensic analysis (Android / iOS) for Indian investigative workflows:
UPI and banking apps, NPCI artefacts, DLT SMS, messengers, crypto wallets, telemetry,
geolocation, and Section 63 BSA reporting.

This repository is the **single source of truth**. It was formed by merging two earlier
projects, *Bharart Analyzer* and *bharat-pa-forensics*. Both originals, with their full git
history, are archived read-only at `E:\v8\_archive\combined_originals_2026-11-11\`.
Nothing in this repository loads code from the archive.

## Layout

| Path | What it is |
|---|---|
| `src/` | Python forensic engines (VFS, SQLite/WAL recovery, UPI, banking, messengers, crypto, legal/BSA, …). Originated in Bharart Analyzer. |
| `parsers/` | Python REST backend for the desktop UI (`parsers/api_server.py`, FastAPI), plugin registry, heuristic engine, carvers. Originated in bharat-pa-forensics. Imports from `src/`. |
| `tools/` | Benchmark recorder. |
| `electron/` | Electron shell (`main.cjs`, `preload.cjs`). Spawns `python -m parsers.api_server`. |
| `ui/renderer/` | React 19 + TypeScript desktop UI (built by Vite into `dist/`). |
| `ui/main/`, `ui/shared/` | TypeScript engines. Partly used by the UI (`case_manager/case_db`, `reporting/sec63_bsa_generator`); the rest is only exercised by `ui/tests/`. |
| `main.py` | Second, separate launcher: the Bharart Analyzer web dashboard (`src/workstation_app`) and `--self-test`. |
| `tests/` | Python tests (pytest) plus `tests/e2e/runner.py` and `tests/test_forensic_client.ts`. |
| `ui/tests/` | TypeScript tests (run with `jiti`). |
| `test_evidence/` | Test fixtures (synthetic extraction ZIP, WhatsApp DB with WAL, Paisa DB, 50 MB disk image). |
| `scripts/` | `start_all.py`, `build_desktop_exe.ps1`, OCR model setup, fixture generators. |
| `docs/` | Architecture/abilities/command docs, original specs (`docs/specs/`), merge history. |

## Setup

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
npm install
```

## Run

```powershell
npm run desktop:dev        # Electron desktop app (spawns the Python backend)
npm run dev                # Vite UI dev server only (port 3000)
npm run backend            # FastAPI backend only
.venv\Scripts\python main.py --self-test   # legacy dashboard diagnostics
```

## Test

```powershell
.venv\Scripts\python -m pytest tests --ignore=tests/e2e
.venv\Scripts\python tests\e2e\runner.py --tier all
npx tsc --noEmit
npm run test:ts
```

### Verified status (2026-11-11, from this root only)

| Check | Result |
|---|---|
| `pytest tests` | **364 passed, 3 failed** (see `docs/REVIEW_BRIEF.md` §2) |
| `tests/e2e/runner.py --tier all` | 65 / 65 passed |
| `npx tsc --noEmit` | 0 errors |
| `npm run test:ts` | 92 passed, 0 failed |
| `npx vite build` | builds (one chunk > 500 kB warning) |
| `main.py --self-test` | 7 / 7 passed |
| Electron desktop launch | not re-verified after the merge cleanup |

Passing tests are not, on their own, evidence of forensic correctness or court admissibility.
Earlier documents in `docs/merge-history/` make stronger claims than were verified. Treat them
as history, not status.
