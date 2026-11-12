# BharatAnalyzer Sovereign Forensics Suite — Unified Command & Operations Manual (`command.md`)

> **Version:** 2.0.0 (Unified Post-Merger Build) | **OS Target:** Windows 10/11 (x64) | **Air-Gapped Offline Mode**

---

## 1. IMPORTANT DIRECTORY TOPOLOGY BEFORE RUNNING COMMANDS

After merging `Bharart Analyzer` and `bharat-pa-forensics` into `E:\v8\combined\`, commands operate cleanly across two working directories:
1. **Unified Project Root (`E:\v8\combined\`):**
   - Houses the consolidated `src/` (**40 packages**), `parsers/` (**32 modules**), `electron/`, `tools/`, `test_evidence/`, and unified `tests/` (**68 pytest & 4-tier E2E suites**).
   - Python interpreter with all dependencies pre-installed lives at:
     `E:\v8\combined\bharat-pa-forensics\.venv\Scripts\python.exe` (Python `3.15.2`, `pytest 9.2.0`).
2. **Frontend, Desktop & Build Workspace (`E:\v8\combined\bharat-pa-forensics\`):**
   - Houses `package.json`, React 19 / Vite 8 / Tailwind v4 UI, TypeScript carver/engine (`src/main/`, `src/tests/`), PyInstaller `bharat_backend.spec`, `electron-builder.yml`, `scripts/start_all.py`, and `scripts/build_desktop_exe.ps1`.
   - All `npm ...` and desktop packaging commands run inside `E:\v8\combined\bharat-pa-forensics\`.

---

## 2. INITIAL ENVIRONMENT SETUP

### 2.1 Activate Existing Python Virtual Environment (Recommended)
From `E:\v8\combined\`:
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\Activate.ps1
python --version
```

*(If provisioning a fresh machine or creating a dedicated root `.venv` inside `E:\v8\combined\`):*
```powershell
cd "E:\v8\combined"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r bharat-pa-forensics\requirements.txt
# Optional testing & extended image/compression utilities (pytest, pytest-cov, brotli, pillow):
pip install pytest>=7.4.0 pytest-cov>=4.1.0 brotli>=1.0.9 pillow>=10.0.0
```

### 2.2 Install Node.js & Electron Dependencies
From `E:\v8\combined\bharat-pa-forensics\`:
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
npm install
```

### 2.3 (Optional, Requires Temporary Internet Before Air-Gap) Bilingual OCR Trained Models
Downloads official Tesseract `hin.traineddata` and `eng.traineddata` into `./.workspace_tmp/tessdata/` (when offline, pure-Python stream fallback remains active automatically):
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe "Bharart Analyzer\scripts\setup_ocr_models.py"
```

---

## 3. RUNNING THE MERGED APPLICATION (ALL MODES)

### 3.1 Full-Stack Web Workbench Mode (FastAPI `:8000` + React Vite `:3000`)
Starts both the Python REST API backend (`http://127.0.0.1:8000`, Swagger UI at `/docs`) and the React 19 workbench (`http://localhost:3000`):
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
.\.venv\Scripts\Activate.ps1
npm start
# Or directly:
# python scripts/start_all.py
```

### 3.2 Native Electron 45 Desktop App Mode (Development)
Opens the 1600x960 native Electron desktop shell with Windows native Open/Save dialogs and automatic child-process management (`taskkill` clean teardown):
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
.\.venv\Scripts\Activate.ps1
npm run desktop:dev
# Or:
# npx electron .
```
- Note: To run Electron against the **unified root** `E:\v8\combined\electron\main.cjs` instead, run from root once backend/frontend are built:
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\node_modules\.bin\electron.cmd .
```

### 3.3 Independent Component Launchers
Run **Unified Root Backend REST API** on default `127.0.0.1:8000`:
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -m parsers.api_server
```
With custom host/port:
```powershell
$env:HOST = "127.0.0.1"
$env:PORT = "8000"
.\bharat-pa-forensics\.venv\Scripts\python.exe -m parsers.api_server
```
Or from `bharat-pa-forensics\`:
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
npm run backend        # Starts FastAPI on http://127.0.0.1:8000
npm run dev            # Starts Vite React HMR server on http://localhost:3000
npm run build          # Runs TypeScript check (tsc) + builds Vite static UI into dist/
npm run preview        # Serves compiled dist/ UI locally
```

### 3.4 Standalone Python Diagnostic Workstation (`src/workstation_app` / Port 8765)
Launches the lightweight standalone workstation server (`src/workstation_app/dashboard_server.py`) with integrated 7-engine self-test diagnostics:
```powershell
cd "E:\v8\combined"
# Execute 7 core sub-engine self-tests and exit:
.\bharat-pa-forensics\.venv\Scripts\python.exe "Bharart Analyzer\main.py" --self-test

# Launch dedicated Chromium/pywebview desktop window on Port 8765:
.\bharat-pa-forensics\.venv\Scripts\python.exe "Bharart Analyzer\main.py" --desktop

# Launch browser dashboard or headless server:
.\bharat-pa-forensics\.venv\Scripts\python.exe "Bharart Analyzer\main.py"
.\bharat-pa-forensics\.venv\Scripts\python.exe "Bharart Analyzer\main.py" --no-browser --port 8765
```

---

## 4. BUILDING STANDALONE WINDOWS `.EXE` INSTALLER & PORTABLE SUITE

All packaging runs inside `E:\v8\combined\bharat-pa-forensics\`:

### 4.1 One-Click Automated 3-Stage Build (Vite -> PyInstaller -> Electron-Builder)
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
.\.venv\Scripts\Activate.ps1
npm run desktop:build
# Equivalent direct PowerShell invocation:
# powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1
```

### 4.2 Partial / Skip-Stage Build Flags
```powershell
# Skip React build (reuse dist/):
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipFrontend

# Skip PyInstaller backend compile (reuse dist_backend/):
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipBackend

# Compile dist/ and dist_backend/ without running electron-builder:
powershell -ExecutionPolicy Bypass -File scripts/build_desktop_exe.ps1 -SkipInstaller
```

### 4.3 Manual Step-by-Step Build
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
npm run build
.\.venv\Scripts\pyinstaller.exe --noconfirm bharat_backend.spec --distpath dist_backend --workpath build_backend
$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
npx electron-builder --win --x64
```

### 4.4 Running the Packaged Air-Gapped Artifacts (`release/`)
```powershell
# Portable folder executable (runs from USB / air-gapped forensic station):
.\release\win-unpacked\BharatAnalyzer.exe

# Or install system-wide / run single-file portable:
# .\release\BharatAnalyzer-Setup-2.0.0.exe
# .\release\BharatAnalyzer-Portable-2.0.0.exe
```

---

## 5. TEST SUITES, COMPILER CHECKS & STATIC VERIFICATION

### 5.1 Unified 4-Tier End-to-End Test Runner (`tests/e2e/runner.py`)
From `E:\v8\combined\`:
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe tests\e2e\runner.py --tier all --verbose

# Or run an individual E2E tier:
.\bharat-pa-forensics\.venv\Scripts\python.exe tests\e2e\runner.py --tier 1 --verbose  # Core ingestion, SQLite, UPI, Banking, Truecaller, Chats, Crypto, UI, Reports
.\bharat-pa-forensics\.venv\Scripts\python.exe tests\e2e\runner.py --tier 2 --verbose  # Boundary & corner cases
.\bharat-pa-forensics\.venv\Scripts\python.exe tests\e2e\runner.py --tier 3 --verbose  # Cross-feature correlations
.\bharat-pa-forensics\.venv\Scripts\python.exe tests\e2e\runner.py --tier 4 --verbose  # Real-world end-to-end flows
```

### 5.2 Complete Pytest Regression Suite (Phases 1–11, API, Adversarial M2–M5)
From `E:\v8\combined\` (isolates scratch journals strictly inside `./.workspace_tmp/pytest`):
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/ --basetemp=./.workspace_tmp/pytest -W error::cryptography.utils.CryptographyDeprecationWarning -v
```
Targeted phase & stress invocations:
```powershell
# Phase-by-phase suites:
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase1*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase2*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase3*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase4*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase5*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase6*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase7*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase8*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase9*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase10*.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_phase11*.py --basetemp=./.workspace_tmp/pytest -v

# UI API server & Challenger/Adversarial verification suites:
.\bharat-pa-forensics\.venv\Scripts\python.exe -m pytest tests/test_ui_api_server.py tests/test_challenger_verification.py tests/test_adversarial_m4_challenge.py tests/test_m4_adversarial_stress.py tests/test_m5_challenger_adversarial.py --basetemp=./.workspace_tmp/pytest -v
.\bharat-pa-forensics\.venv\Scripts\python.exe tests/adversarial_m2_stress.py
.\bharat-pa-forensics\.venv\Scripts\python.exe tests/adversarial_m3_stress.py
```

### 5.3 Hardened API, FTS5, Parity & TypeScript Engine Tests (`bharat-pa-forensics/`)
From `E:\v8\combined\bharat-pa-forensics\`:
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
.\.venv\Scripts\Activate.ps1

# 1. All Python unittest suites inside bharat-pa-forensics/tests/:
npm run test:python
# Or directly:
python -m unittest discover tests -v

# Individual high-value suites:
python -m unittest tests/test_hardened_api_server.py -v
python -m unittest tests/test_ui_fts5_paginator.py -v
python -m unittest tests/test_generic_table_engine.py -v
python -m unittest tests/test_enterprise_1tb_engine.py -v
python -m unittest tests/test_hardened_freelist_wal_carver.py -v
python -m unittest tests/test_social_interaction_comms_parsers.py -v
python -m unittest tests/test_e01_adapter.py -v
python -m unittest tests/test_forensic_benchmark_recorder.py -v
python -m unittest tests/test_phase6_7.py -v

# 2. TypeScript Workbench & Native Parser Tests (jiti):
npm run test:ts
# Plus Phase 1-5 TS unit suites:
npx jiti src/tests/phase1_test.ts
npx jiti src/tests/phase2_test.ts
npx jiti src/tests/phase3_test.ts
npx jiti src/tests/phase4_test.ts
npx jiti src/tests/phase5_test.ts
npx jiti src/tests/forensic_engine_test.ts

# 3. Strict TypeScript Type Check (0 errors required):
npx tsc --noEmit
```

### 5.4 Python Syntax & Bytecode Verification across Unified Root
From `E:\v8\combined\`:
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -c "
import pathlib, py_compile, sys
errors = []
for folder in ['src', 'parsers', 'tools']:
    for p in pathlib.Path(folder).rglob('*.py'):
        try:
            py_compile.compile(str(p), doraise=True)
        except Exception as e:
            errors.append((str(p), str(e)))
print(f'Checked {folder} files; errors: {len(errors)}')
for f, e in errors:
    print(f, e)
sys.exit(1 if errors else 0)
"
```

---

## 6. FORENSIC BENCHMARKING & DIRECT ENGINE CLI UTILITIES

### 6.1 Vendor Parity Differential Benchmarker (`tools/forensic_benchmark_recorder.py`)
Compares extraction coverage against `.ufdr`/`.xry`/`.ofb`/`.tar`/`.zip` dumps up to 1.5 TB with strict PII redaction (`[Aadhaar Redacted]`, `[PAN Redacted]`):
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -m tools.forensic_benchmark_recorder `
  --input "path\to\evidence_dump.ufdr" `
  --output-dir ".\.workspace_tmp\case_benchmark" `
  --verbose
```
Generates `COVERAGE_COMPARISON_REPORT.md` and `benchmark_telemetry_ledger.json`.

### 6.2 Container VFS Indexing, Querying & Dual SHA-256 Product A Hashing
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -c "
import pathlib, tempfile
from src.provenance.hasher import ProductAHasher
from src.vfs.indexer import VFSIndexer
from src.vfs.reader import VFSReader

container_path = r'test_evidence\android_logical_extraction.zip'
res = ProductAHasher().hash_file(container_path, compute_md5=True)
print('Container SHA-256 (Product A):', res.sha256)
print('Container MD5 (Product A):', res.md5)

with tempfile.TemporaryDirectory() as tmpdir:
    catalog_db = pathlib.Path(tmpdir) / 'vfs_index.sqlite'
    count = VFSIndexer(catalog_db).index_archive(container_path, container_id=1)
    entries = VFSReader(catalog_db).vfs_query_paths('%')
    print('Indexed entries:', count, '| Query sample:', entries[:2] if entries else [])
"
```

### 6.3 4 KB Sliding-Window Block Entropy Skyline & Chi-Square Profiler
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -c "
from src.unk_triage.entropy_profiler import SlidingWindowEntropyProfiler

profiler = SlidingWindowEntropyProfiler(block_size_bytes=4096)
with open(r'test_evidence\msgstore.db', 'rb') as f:
    raw = f.read()

skyline = profiler.compute_block_entropy_skyline(raw)
chi2 = profiler.compute_256bin_chi_squared(raw)
print(f'Blocks: {skyline.block_count} | Chi-Square: {chi2.chi_squared_statistic} (ciphertext_uniform={chi2.is_likely_uniform_ciphertext})')
for idx, (h, comp) in enumerate(zip(skyline.block_entropies[:10], skyline.block_compositions[:10])):
    print(f'Block {idx:04d}: H={h:.4f} | ASCII={comp.printable_ascii_pct}% | Zero={comp.null_zero_pct}% | HighBit={comp.high_bit_structured_pct}%')
"
```

### 6.4 Zero-Code UNK Introspection & Table Promotion to Case Ledger
```powershell
cd "E:\v8\combined"
.\bharat-pa-forensics\.venv\Scripts\python.exe -c "
import pathlib, sqlite3, tempfile
from src.zero_omission_and_fts5.fallback_introspector import UniversalFallbackIntrospector
from src.unk_triage.schema_mapper import ZeroCodeSchemaMapper
from src.unk_triage.models import SemanticColumnRole

# Copy fixture to isolated temp dir to avoid mutating or locking source evidence
with tempfile.TemporaryDirectory() as tmpdir:
    tmp_db = pathlib.Path(tmpdir) / 'paisa_copy.db'
    tmp_db.write_bytes(pathlib.Path(r'test_evidence\paisa.db').read_bytes())
    findings = UniversalFallbackIntrospector().introspect_sqlite_file(
        vfs_file_id=1,
        file_path=str(tmp_db),
        owning_package='com.google.android.apps.nbu.paisa.user',
    )
    print('Auto-swept UNK findings:', len(findings))

    ledger_db = pathlib.Path(tmpdir) / 'triage_ledger.sqlite'
    mapper = ZeroCodeSchemaMapper()
    mapper.initialize_triage_db(str(ledger_db))
    promoted = mapper.promote_table_to_case(
        db_path=str(ledger_db),
        vfs_file_id=1,
        table_name='transactions',
        column_roles={'ts_ms': SemanticColumnRole.TIMESTAMP_EPOCH_MS, 'amount': SemanticColumnRole.FINANCIAL_OR_CRYPTO_AMOUNT},
        raw_rows=[{'ts_ms': 1700000000000, 'amount': 5000}],
        examiner_name='Inspector Sharma',
    )
    print('Promoted mapping UID:', promoted.mapping_uid, '| Rows:', promoted.promoted_rows_count)
"
```

### 6.5 Reports from the command line (backend running on port 8000)
```powershell
# After POST /api/case/ingest has loaded a case:
curl.exe -s -X POST http://127.0.0.1:8000/api/report/examination -H "Content-Type: application/json" -d "{\"case_number\":\"REF-1\"}" -o examination_report.html
curl.exe -s "http://127.0.0.1:8000/api/report/facts?format=csv" -o case_facts.csv
curl.exe -s http://127.0.0.1:8000/api/audit
```
When the desktop app is used, the backend requires the per-launch token header `X-Bharat-Token`; run the backend yourself without `BHARAT_API_TOKEN` for these examples.

## 7. TROUBLESHOOTING & MAINTENANCE

### 7.1 Port 8000 or Port 3000 Already in Use
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue).OwningProcess -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue).OwningProcess -ErrorAction SilentlyContinue | Stop-Process -Force
```

### 7.2 Sync Check Between Unified Root `parsers/` and `bharat-pa-forensics/parsers/`
Before removing mirrored folders or building `.exe` installers, compare root vs `bharat-pa-forensics/` copies:
```powershell
cd "E:\v8\combined\bharat-pa-forensics"
powershell -ExecutionPolicy Bypass -File scripts\diff_duplicate_folders.ps1
```

### 7.3 Air-Gap & Code Cleanliness Check
```powershell
cd "E:\v8\combined"
Select-String -Path "src\**\*.py","parsers\*.py" -Pattern "\b(TODO|FIXME|NotImplemented)\b"
```
