# Bharat Forensic Suite

Post-extraction mobile forensic analysis (Android / iOS) for Indian investigative workflows:
UPI and banking apps, NPCI artefacts, DLT SMS, messengers, crypto wallets, telemetry,
geolocation, and examination reporting (facts, not legal forms).


## Layout

| Path | What it is |
|---|---|
| `src/` | Python forensic engines (VFS, SQLite/WAL recovery, UPI, banking, messengers, crypto, legal/BSA, …). Originated in Bharart Analyzer. |
| `parsers/` | Python REST backend for the desktop UI (`parsers/api_server.py`, FastAPI), plugin registry, heuristic engine, carvers. Imports from `src/`. |
| `tools/` | Benchmark recorder. |
| `electron/` | Electron shell (`main.cjs`, `preload.cjs`). Spawns `python -m parsers.api_server`. |
| `ui/renderer/` | React 19 + TypeScript desktop UI (built by Vite into `dist/`). |
| `ui/shared/` | Shared TypeScript types used by the renderer. (The duplicate TypeScript parsers/carvers/VFS/report generators that used to live in `ui/main/` were deleted: the Python backend is the only engine.) |
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

Optional disk-image support (EWF/E01 via `libewf-python`, Sleuth Kit via `pytsk3`) is in `requirements-optional.txt`:
`python -m pip install -r requirements-optional.txt`. The app runs without these packages.

## Quick start (Windows)

Run these in the project folder, then the desktop app opens with the full UI:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
npm install
npm run build
npm run desktop:dev
```

## Run

```powershell
npm run desktop:dev        # Electron desktop app (spawns the Python backend)
npm run dev                # Vite UI dev server only (port 3000)
npm run backend            # FastAPI backend only
```

The desktop window needs the UI: either run `npm run build` once (creates `dist/`) or keep
`npm run dev` running in another terminal before `npm run desktop:dev`. The backend is started with
the interpreter in `.venv` (or the active virtualenv / conda env); set `BHARAT_PYTHON` to point at a
different `python.exe` that has the requirements installed. If `electron` reports a missing binary,
run `node node_modules/electron/install.js`.

## Test

```powershell
.venv\Scripts\python -m pytest tests --ignore=tests/e2e
.venv\Scripts\python tests\e2e\runner.py --tier all
npx tsc --noEmit
npm run test:ts
```
