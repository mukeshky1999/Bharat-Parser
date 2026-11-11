# BHARATANALYZER — COMMAND & OPERATIONS MANUAL
### Sovereign Digital Forensics & Financial Intelligence Suite
> **Version:** 2.0.0 | **Architecture:** Electron + React 19 + Python FastAPI | **Target OS:** Windows 10 / 11 (x64)  
> **Supported Containers:** Cellebrite (`.ufdr`, `.ufd`), MSAB XRY (`.xry`), Oxygen (`.ofb`), Android Tar (`.tar`, `.tar.gz`), Backups (`.zip`, `.ab`), SQLite (`.db`, `.sqlite`), and Extracted Physical/Logical Folders.

---

## 🚀 1. RUNNING IN DEVELOPMENT MODE

### A. Run Full-Stack (Browser Mode — Recommended for Web Dev)
Launches both the **Python Forensic API Backend** (Port 8000) and the **React / Vite Forensic Workbench UI** (Port 3000) concurrently:
```powershell
npm start
# or
python scripts/start_all.py
```
- **Backend API:** `http://127.0.0.1:8000` (Interactive OpenAPI Swagger Docs: `http://127.0.0.1:8000/docs`)
- **Frontend UI:** `http://localhost:3000`

### B. Run Native Electron Desktop Shell (Desktop Dev)
Launches the native Electron desktop application window with automatic child process lifecycle management:
```powershell
npm run desktop:dev
```
- Automatically starts `.venv\Scripts\python.exe` running FastAPI if port 8000 is not already up.
- Connects to native Windows OS file and folder picker dialogs.
- Cleanly terminates the backend process tree when the window is closed.

---

## 📦 2. INITIAL ENVIRONMENT SETUP

### Step A: Setup Python Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install all forensic backend dependencies
pip install -r requirements.txt
```

### Step B: Install Node.js Frontend Dependencies
```powershell
npm install
```

---

## 🛠️ 3. INDEPENDENT COMPONENT COMMANDS

| Component | Command | Details |
| :--- | :--- | :--- |
| **Backend REST Server** | `npm run backend`<br>*or* `python -m parsers.api_server` | Runs FastAPI on `http://127.0.0.1:8000`. |
| **Vite Frontend Dev** | `npm run dev` | Runs Vite HMR server on `http://localhost:3000`. |
| **Compile Frontend** | `npm run build` | Compiles TypeScript and builds production assets into `dist/`. |
| **Preview Built UI** | `npm run preview` | Runs local server serving the `dist/` production bundle. |
| **Electron Shell** | `npm run desktop:dev`<br>*or* `electron .` | Runs Electron desktop wrapper. |

---

## 🔨 4. STANDALONE WINDOWS `.EXE` INSTALLER BUILDER

### One-Click Automated Build (Recommended)
Builds the complete air-gapped Windows desktop installer and portable `.exe`:
```powershell
npm run desktop:build
# or directly via PowerShell:
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1
```

### Advanced Build Flags:
```powershell
# Skip React compilation (reuse existing dist/):
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipFrontend

# Skip PyInstaller compilation (reuse existing dist_backend/):
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipBackend

# Compile without packaging installer:
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipInstaller
```

### Manual Packaging Steps:

#### Step 1: Compile React Frontend
```powershell
npm run build
```

#### Step 2: Compile Python FastAPI with PyInstaller
```powershell
.\.venv\Scripts\pyinstaller.exe --noconfirm --onedir --name bharat_backend `
  --add-data "parsers;parsers" `
  --hidden-import "uvicorn" `
  --hidden-import "uvicorn.logging" `
  --hidden-import "uvicorn.loops" `
  --hidden-import "uvicorn.loops.auto" `
  --hidden-import "uvicorn.protocols" `
  --hidden-import "uvicorn.protocols.http" `
  --hidden-import "uvicorn.protocols.http.auto" `
  --hidden-import "uvicorn.protocols.websockets" `
  --hidden-import "uvicorn.protocols.websockets.auto" `
  --hidden-import "uvicorn.lifespan" `
  --hidden-import "uvicorn.lifespan.on" `
  --hidden-import "fastapi" `
  --hidden-import "starlette" `
  --hidden-import "pydantic" `
  --hidden-import "sqlite3" `
  --hidden-import "pandas" `
  --hidden-import "numpy" `
  --hidden-import "pyvis" `
  --hidden-import "networkx" `
  --hidden-import "parsers" `
  --hidden-import "parsers.api_server" `
  --hidden-import "parsers.social_interaction_comms_parsers" `
  --hidden-import "parsers.chat_social_privacy_parsers" `
  --hidden-import "parsers.heuristic_engine" `
  --hidden-import "parsers.plugin_loader" `
  --hidden-import "parsers.deep_sqlite" `
  --hidden-import "parsers.fiat_crypto_bridge" `
  --hidden-import "parsers.crypto_address_validator" `
  --hidden-import "parsers.crypto_p2p_parser" `
  --hidden-import "parsers.graph_intelligence" `
  --distpath "dist_backend" `
  --workpath "build_backend" `
  parsers/api_server.py
```

#### Step 3: Bundle Electron Windows Installer & Portable Package
```powershell
npx electron-builder --win --x64
```

---

## 📁 5. GENERATED DISTRIBUTION ARTIFACTS (`release/`)

After packaging, all deployable deliverables are created in `release/`:

| Output File | Format | Description |
| :--- | :--- | :--- |
| `release/BharatAnalyzer-Setup-2.0.0.exe` | **NSIS Installer** | Standard Windows installer with desktop and Start Menu shortcuts. |
| `release/win-unpacked/BharatAnalyzer.exe` | **Portable Folder** | Standalone air-gapped folder for running directly from external hard drives or USB media. |
| `release/BharatAnalyzer-Portable-2.0.0.exe` | **Single-file Portable** | Standalone single-executable for rapid on-scene triage. |

### Packaged Directory Architecture:
```text
release/win-unpacked/
├── BharatAnalyzer.exe                <- Native Electron Desktop Shell Launcher
├── resources/
│   ├── app.asar                      <- Encrypted React UI & Preload scripts
│   └── backend/                      <- Bundled Standalone Python Forensic Backend
│       ├── bharat_backend.exe        <- Compiled FastAPI Forensic Server
│       ├── parsers/                  <- 42+ UPI & Social Communication Parsers
│       ├── python310.dll / vcruntime <- Bundled C-Runtime dependencies
│       └── ...
└── ...
```

---

## 🧪 6. TEST SUITE & VERIFICATION COMMANDS

### Run All Unit & Integration Tests
```powershell
# 1. Run All Python Forensic Unit Tests (65 tests):
npm run test:python
# or
python -m unittest discover tests

# 2. Run Social & Extended Comms Parsers Tests (12 tests):
python -m unittest tests/test_social_interaction_comms_parsers.py

# 3. Run TypeScript & 28-Column Categorized UI Workbench Tests (79 tests):
npm run test:ts

# 4. Verify TypeScript Compiler (0 Errors):
npx tsc --noEmit
```

---

## 🔬 7. FORENSIC BENCHMARK & VENDOR DIFFERENTIAL HARNESS

To benchmark parsers against commercial dumps (**Cellebrite Physical Analyzer `.ufdr`**, **MSAB XRY `.xry`**, **Oxygen `.ofb`**, or raw `.tar`/`.zip` dumps up to 1.5 TB) with strict **PII redaction** (`[Aadhaar Redacted]`):

```powershell
python -m tools.forensic_benchmark_recorder --input "path/to/evidence_dump.ufdr" --output-dir "reports/case_benchmark" --verbose
```

### Output Artifacts Generated:
1. `reports/case_benchmark/PARITY_GAP_REPORT.md` (Court-grade differential report with head-to-head comparison table and unparsed schema blueprints)
2. `reports/case_benchmark/benchmark_telemetry_ledger.json` (Sanitized machine-readable diagnostic ledger)

---

## 🔒 8. AIR-GAPPED DEPLOYMENT FOR LAW ENFORCEMENT

1. **Zero Cloud Connectivity:** BharatAnalyzer operates in 100% offline air-gapped mode. It never performs outbound internet calls.
2. **Double-Click Execution:** Examiners can run `BharatAnalyzer.exe` on clean analysis workstations without installing Python, Node.js, Git, or compilers.
3. **Automatic Process Management:** Launching `BharatAnalyzer.exe` automatically starts the local backend service on `127.0.0.1:8000`. Closing the window immediately terminates the entire child process tree cleanly using Windows `taskkill`, preventing locked ports.
4. **Read-Only SQLite (`?mode=ro`):** All evidence containers, `.db`, `.sqlite`, `.ufdr`, and `.tar` archives are opened in strict read-only mode to preserve forensic hash integrity under Section 63 BSA (2023).

---

## ❓ 9. TROUBLESHOOTING & FAQ

### Q: Port 8000 is already in use
If another process is using port 8000, find and terminate it:
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
```

### Q: Native Windows File Explorer dialog doesn't appear
BharatAnalyzer uses dual fallbacks:
1. Electron IPC (`dialog.showOpenDialog`) when running as a desktop app.
2. Tkinter thread-safe file dialog (`/api/system/pick-evidence-file`) when running in browser mode.
Ensure your window has focus.

### Q: Windows Defender SmartScreen warning on setup `.exe`
Because the generated executable is locally built and self-signed, click **More info** -> **Run anyway**. For enterprise law enforcement deployments, sign the executable using your agency's Microsoft Authenticode code-signing certificate:
```powershell
signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a "release/BharatAnalyzer-Setup-2.0.0.exe"
```
