# Original User Request

## Initial Request — 2026-11-08T18:18:29Z

Merge the best working backend parsers and frontend UI from `Bharart Analyzer` and `bharat-pa-forensics` into a single, fully functional, production-ready Android & iOS Post-Extraction Forensic Suite tailored for the Indian ecosystem (UPI, Indian banking, Truecaller, regional chat apps, Indian e-commerce/shopping, crypto, and core SQLite/WAL/freelist/LevelDB/Plist extraction) with competitor capabilities.

Working directory: E:\v8\combined
Integrity mode: development

## Requirements

### R1. Repository Audit and State Tracking
Audit source files across `Bharart Analyzer` and `bharat-pa-forensics`, ignoring environments and generated directories (`.venv`, `venv`, `node_modules`, `.git`, `__pycache__`, `dist`, `build`). Create and maintain `E:\v8\combined\MERGE_STATE.md` recording audited file paths, superior logic choices, and a checklist of completed versus pending modules, selecting the cleanest folder or workspace root as the primary target.

### R2. Core Forensic Ingestion Engine
Merge and verify all archive and extraction handlers (UFED, tar, zip, ADB backup, iOS backup), SQLite with WAL/journal recovery, Plist and LevelDB readers, and SHA-256 forensic hashing.

### R3. Indian Ecosystem App Parsers
Merge all parser plugins (UPI & Banking, Truecaller, regional chat apps, shopping, crypto, call logs/SMS/contacts) ensuring zero parser logic from either codebase is lost, standardizing outputs into a unified schema.

### R4. API Bridge and Forensic UI
Connect the unified backend cleanly to the UI (Dashboard, Case Manager, Category Tree, Timeline/Link Analysis, Hex/SQLite Viewer, Indian Artifact Inspector, and Court-Admissible Report Generator) using an original investigative workflow.

### R5. Complete Implementation and Incremental Verification
Every merged or created source file must contain 100% complete logic with zero shortcuts, truncation, placeholder comments (`// ... rest of code`, `# existing code here`), `pass`, `TODO`, or mock stub functions. Execute atomically (1 to 2 files per step) and run terminal checks (`python -m py_compile` for Python, build/import checks for UI) immediately after editing each file.

## Verification Resources
Existing test suites and sample extraction dumps in `Bharart Analyzer` and `bharat-pa-forensics`, supplemented by synthetic test fixtures and databases generated as needed.

## Acceptance Criteria

### Audit and State Management
- [ ] `E:\v8\combined\MERGE_STATE.md` exists and contains the complete file-by-file merge checklist, audit comparison of `Bharart Analyzer` vs `bharat-pa-forensics`, and tracking of completed vs pending modules.
- [ ] No files within `.venv`, `venv`, `node_modules`, `.git`, `__pycache__`, `dist`, or `build` are tracked or modified as source files.

### Ingestion Engine and Parsers
- [ ] Ingestion engine successfully processes UFED, tar, zip, ADB backup, iOS backup, SQLite + WAL/journal, and Plist/LevelDB formats with SHA-256 hashing.
- [ ] All parser plugins from both codebases (UPI, Indian banking, Truecaller, regional chat apps, shopping, crypto, call logs, SMS, contacts) produce standardized structured records without loss of parser capabilities from either codebase.

### Completeness and System Integrity
- [ ] Zero source files contain truncation markers (`// ... rest of code`, `# existing code here`), TODO comments substituting for implementation, or mock stub functions.
- [ ] All modified Python files pass `python -m py_compile` without compilation errors.
- [ ] UI files pass build or import syntax validation without unresolved imports or broken references.
- [ ] Unified application boots end-to-end with backend services and UI accessible and functional.


## Follow-up — 2026-11-10T17:06:16Z

continue

Resume from Milestone 3 gate verification -> Milestone 4 (API Bridge and Forensic UI) -> Milestone 5 (E2E Testing & End-to-End Boot Verification).
