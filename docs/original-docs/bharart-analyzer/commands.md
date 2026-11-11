# BHARAT ANALYZER — COMMAND EXECUTION MANUAL (`commands.md`)

This guide provides the authoritative operational commands to set up, test, audit, and execute the **Bharat Analyzer** forensic engine.

---

## 1. ENVIRONMENT SETUP & PREREQUISITES

Bharat Analyzer is an air-gapped, post-acquisition forensic engine operating under strict USB workspace isolation.

### 1.1 Python Virtual Environment

#### Windows (PowerShell):
```powershell
# Navigate to the project root on the USB workspace
cd "E:\v8\Bharart Analyzer"

# Create a local virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

#### Windows (Command Prompt `cmd.exe`):
```cmd
cd /d "E:\v8\Bharart Analyzer"
python -m venv .venv
.\.venv\Scripts\activate.bat
```

#### Linux / macOS:
```bash
cd /media/forensics/bharat_analyzer
python3 -m venv .venv
source .venv/bin/activate
```

### 1.2 Install Dependencies
Install the verified dependencies from `requirements.txt`:
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. TEST SUITE EXECUTION & VERIFICATION

All tests must run against realistic binary fixtures with temp journals and outputs routed strictly to `./.workspace_tmp/`.

### 2.1 Complete Global Regression Suite (All 233 Tests, Zero Warnings)
Run the full 11-phase forensic test suite with strict deprecation warning escalation:
```powershell
python -m pytest tests/ --basetemp=./.workspace_tmp/pytest -W error::cryptography.utils.CryptographyDeprecationWarning -v
```

### 2.2 Phase-by-Phase Test Execution

#### Phase 1: Ingestion, Normalization & 5D Evidentiary Integrity
```powershell
python -m pytest tests/test_phase1*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 2: Universal Storage, Decryption & Residual Recovery
```powershell
python -m pytest tests/test_phase2*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 3: Indian UPI, FinTech & Domestic Banking Intelligence
```powershell
python -m pytest tests/test_phase3*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 4: Cryptocurrency, Web3 & Exchange Forensics
```powershell
python -m pytest tests/test_phase4*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 5: Deep Messaging Engine (Mainstream & High-OpSec)
```powershell
python -m pytest tests/test_phase5*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 6: OS Telemetry, Geolocation & Anti-Forensics
```powershell
python -m pytest tests/test_phase6*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 7: Media, C2PA Provenance & Offline OCR
```powershell
python -m pytest tests/test_phase7*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 8: Commercial Workbench, Link Analysis & BSA Sec 63 Reports
```powershell
python -m pytest tests/test_phase8*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 9: Advanced Examiner Workstation & Triage Studio
```powershell
python -m pytest tests/test_phase9*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 10: Remediation, Bilingual OCR, Hybrid Geocoder & main.py Launcher
```powershell
python -m pytest tests/test_phase10*.py --basetemp=./.workspace_tmp/pytest -v
```

#### Phase 11: Real Evidence Ingestion, Dynamic Workstation UI, Hex Inspector & Native Desktop App
```powershell
python -m pytest tests/test_phase11*.py --basetemp=./.workspace_tmp/pytest -v
```

### 2.3 Code Coverage Verification
Generate comprehensive branch and line coverage reports:
```powershell
python -m pytest tests/ --cov=src --cov-report=term-missing --cov-report=html:./.workspace_tmp/cov_html --basetemp=./.workspace_tmp/pytest
```

---

## 3. CORE FORENSIC ENGINE CLI INVOCATIONS

### 3.0 Unified Workstation Single-Command Launcher (`main.py`)
Launch the complete interactive workstation in a **dedicated native desktop application window** (Chromium / Edge app mode or native webview):
```powershell
python main.py --desktop
```
Launch the interactive web workstation UI in the default browser:
```powershell
python main.py
```
Run comprehensive automated diagnostic checks across all core forensic subsystems:
```powershell
python main.py --self-test
```
Run workstation server headless on a custom port without launching any UI window:
```powershell
python main.py --no-browser --port 8765
```
Setup / download official Hindi & English Tesseract models for offline OCR:
```powershell
python scripts/setup_ocr_models.py
```

### 3.1 VFS Ingestion & Evidence Container Fingerprinting
Ingest physical images (`.bin`, `.e01`, `.ufdr`, `.tar`, `.zip`, GrayKey, iOS backup):
```powershell
python -c "
from src.vfs.reader import VFSReader
from src.provenance.hasher import ProvenanceHasher

# Inspect evidence container with zero full-disk unpacking
reader = VFSReader('evidence_image.tar')
hasher = ProvenanceHasher()
meta = hasher.compute_container_sha256('evidence_image.tar')
print(f'Container SHA-256 (Product A): {meta.sha256}')
"
```

### 3.2 4 KB Sliding-Window Block Entropy Skyline Profiling
Analyze unallocated blocks or unknown payloads for encryption vs. compression vs. plaintext:
```powershell
python -c "
from src.unk_triage_and_bsa_studio.entropy_profiler import SlidingWindowEntropyProfiler

profiler = SlidingWindowEntropyProfiler(block_size_bytes=4096)
with open('unknown_payload.bin', 'rb') as f:
    raw_bytes = f.read()

res = profiler.profile_blocks(raw_bytes)
for b in res.blocks:
    print(f'Block {b.block_index:04d} [Offset {b.offset_start}..{b.offset_end}]: H={b.entropy_bits_per_byte:.2f} ({b.classification})')
"
```

### 3.3 Zero-Code SQLite Schema Promotion
Promote custom/unsupported SQLite tables into the Unified Super-Timeline and Entity Graph:
```powershell
python -c "
from src.unk_triage_and_bsa_studio.schema_mapper import ZeroCodeSchemaMapper
from src.unk_triage_and_bsa_studio.models import SemanticColumnRole

mapper = ZeroCodeSchemaMapper()
# Introspect table schema
cols = mapper.introspect_table_columns('app_db.sqlite', 'secret_ledger')
print('Discovered columns:', cols)

# Map and promote into Super-Timeline
promoted = mapper.promote_table_to_timeline(
    db_path='app_db.sqlite',
    table_name='secret_ledger',
    role_mapping={
        'tx_time': SemanticColumnRole.TIMESTAMP_EPOCH,
        'sender': SemanticColumnRole.ACTOR_SOURCE_IDENTIFIER,
        'receiver': SemanticColumnRole.ACTOR_TARGET_IDENTIFIER,
        'memo': SemanticColumnRole.MESSAGE_OR_EVENT_BODY_TEXT,
        'val': SemanticColumnRole.FINANCIAL_OR_CRYPTO_AMOUNT
    }
)
print(f'Promoted {len(promoted)} rows into Unified Super-Timeline.')
"
```

### 3.4 Golden-Hour 1930 NCRP Bank Lien Export
Generate bank freeze requisition CSVs with automatic Complainant/Victim safeguard lock:
```powershell
python -c "
from src.unk_triage_and_bsa_studio.freeze_deconfliction import NodalFreezeDeconflictionCenter

center = NodalFreezeDeconflictionCenter()
csv_text = center.export_1930_ncrp_csv(
    case_fir_number='FIR-2026-CYBER-884',
    complainant_account='SBIN0001234:9876543210',
    selected_targets=['HDFC0005678:1122334455', 'ICIC0009012:9988776655'],
    disputed_amount=250000.0,
    evidence_utr='612345678901'
)
with open('./.workspace_tmp/1930_ncrp_freeze.csv', 'w', encoding='utf-8') as f:
    f.write(csv_text)
print('1930 NCRP Freeze CSV generated at ./.workspace_tmp/1930_ncrp_freeze.csv')
"
```

### 3.5 Section 63(4)(c) BSA 2023 & Section 230 BNSS Dual Courtroom Report
Validate the 6-point pre-flight gate and generate side-by-side Master Court vs. Defense Disclosure copies:
```powershell
python -c "
from src.unk_triage_and_bsa_studio.bsa_report_studio import BsaReportStudioEngine

engine = BsaReportStudioEngine()
dossier = engine.generate_dual_preview(
    deponent_name='Inspector Rajesh Kumar, Cyber Crime Police Station',
    deponent_designation='Deputy Superintendent of Police, Technical Intelligence',
    court_name='Special Court for Cyber Crimes, Bengaluru',
    fir_number='CR-104/2026',
    pre_sha256='a' * 64,
    post_sha256='a' * 64,
    merkle_root='b' * 64,
    statutory_caption_mode='BSA_2023',
    exhibit_records=[
        {'id': 'EX-01', 'title': 'WhatsApp Chat Export', 'sha256_prod_a': '1' * 64, 'sha256_prod_b': '2' * 64},
        {'id': 'EX-02', 'title': 'PhonePe UTR Ledger', 'sha256_prod_a': '3' * 64, 'sha256_prod_b': '4' * 64}
    ]
)
print('Master Court Preview lines:', len(dossier.master_court_preview_html.splitlines()))
print('Section 230 BNSS Defense Preview lines:', len(dossier.sec230_bnss_defense_preview_html.splitlines()))
print('Pre-flight Compliance Status:', dossier.preflight_status.is_valid)
"
```

---

## 4. AIR-GAPPED OFFENSIVE AUDIT & CONSTITUTION CHECKS

To guarantee zero reward-hacking and zero placeholder code across the entire production codebase:

### 4.1 Banned Keyword Verification (Must return 0 matches)
```powershell
Select-String -Path "src\**\*.py" -Pattern "\b(TODO|FIXME|pass|NotImplemented|placeholder)\b"
```

### 4.2 Strict USB Workspace Isolation Check
Verify no files were created outside the USB project root:
```powershell
# Verify that all pytest/runtime artifacts reside strictly within ./.workspace_tmp/
Get-ChildItem -Path ".\.workspace_tmp" -Recurse
```

### 4.3 Git Integrity Check
Verify that `tests/` has not been altered:
```powershell
git diff tests/
```
*(Must output zero diff lines, proving tests are sacred and strictly read-only).*
