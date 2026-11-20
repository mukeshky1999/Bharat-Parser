# Bharat Forensic Suite

Windows desktop application for post-extraction forensic analysis of Android and iOS data in Indian investigations. It parses UPI and banking apps, NPCI artefacts, DLT SMS, messengers, crypto wallets, telemetry and geolocation, and produces examination reports. The backend is a Python FastAPI service (`parsers/`, `src/`); the UI is Electron with React.

## Requirements

- Windows 10 or 11
- Python 3.11 to 3.13 (3.12 recommended; 3.14 and later are not yet supported)
- Node.js 22 LTS
- Git

Visual Studio and C++ build tools are not needed for the standard install.

## Install and run

```powershell
git clone https://github.com/mukeshky1999/Bharat-Parser.git
cd Bharat-Parser
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
npm ci
npm run build
npm run desktop:dev
```

## Optional: E01 and Sleuth Kit disk images

    .venv\Scripts\python -m pip install -r requirements-optional.txt

pytsk3 may have no prebuilt wheel for your Python version. If so, the install needs Microsoft C++ Build Tools. The app works without these packages.

## Development

    .venv\Scripts\python -m pip install -r requirements-dev.txt

Run modes:

- `npm run dev`: Vite UI dev server on port 3000
- `npm run backend`: API server only
- `npm run desktop:dev`: Electron app, which starts the backend

Tests:

    .venv\Scripts\python -m pytest tests --ignore=tests/e2e
    npx tsc --noEmit
    npm run test:ts

Some tests need fixtures in `test_evidence/`. Generate them with `python scripts/generate_forensic_test_data.py`. Tests that need them are skipped if the folder is absent.

Build the Windows executable: `npm run desktop:build`.

## Project layout

| Path | Contents |
|---|---|
| `src/` | Python forensic engines |
| `parsers/` | FastAPI backend, plugin registry, heuristic engine, carvers |
| `electron/` | Electron shell; starts the Python backend |
| `ui/renderer/` | React and TypeScript UI, built by Vite into `dist/` |
| `ui/shared/` | TypeScript types shared by the UI |
| `ui/tests/` | TypeScript tests |
| `tests/` | Python tests |
| `scripts/` | Build, setup and fixture-generation scripts |
| `tools/` | Benchmark recorder |

## Troubleshooting

- "Microsoft Visual C++ 14.0 is required": you are on an unsupported Python version, or you installed `requirements-optional.txt`. Use Python 3.12.
- "Python backend exited": install the requirements into `.venv`, or set `BHARAT_PYTHON` to a `python.exe` that has them.
- Electron binary missing: run `node node_modules/electron/install.js`.
- Blank window: run `npm run build` first.

## License

See LICENSE.
