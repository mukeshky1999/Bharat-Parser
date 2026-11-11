"""
Bharat Forensic Suite — E2E Test Environment Setup and Path Discovery
Configures sys.path to support both root-merged layout and source workspaces.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Clean out any stale or inaccessible search paths (e.g. OneDrive AcquireX)
sys.path = [p for p in sys.path if "AcquireX" not in p and "acquirex" not in p]

# Establish authoritative root
ROOT_DIR = Path(__file__).resolve().parent.parent.parent

# Register candidate module search directories in priority order:
# 1. Project Root (unified target)
# 2. bharat-pa-forensics (parsers, tools, FTS5 case store)
# 3. Bharart Analyzer (src.* deep forensic modules)
search_candidates = [
    str(ROOT_DIR),
    str(ROOT_DIR / "bharat-pa-forensics"),
    str(ROOT_DIR / "Bharart Analyzer"),
]

for candidate in reversed(search_candidates):
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

# Ensure ROOT_DIR (unified target) is strictly at sys.path[0] ahead of all fallbacks
if str(ROOT_DIR) in sys.path:
    sys.path.remove(str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR))

# Bridge package search paths (__path__) so that unmigrated future-milestone submodules
# (e.g. src.upi, parsers.api_server) remain discoverable from legacy workspaces
# while prioritizing ROOT_DIR unified implementations at __path__[0].
try:
    import src
    bharat_src = str(ROOT_DIR / "Bharart Analyzer" / "src")
    if os.path.exists(bharat_src) and bharat_src not in src.__path__:
        src.__path__.append(bharat_src)
except Exception:
    pass

try:
    import parsers
    forensics_parsers = str(ROOT_DIR / "bharat-pa-forensics" / "parsers")
    if os.path.exists(forensics_parsers) and forensics_parsers not in parsers.__path__:
        parsers.__path__.append(forensics_parsers)
except Exception:
    pass

TEST_EVIDENCE_DIR = ROOT_DIR / "test_evidence"
if not TEST_EVIDENCE_DIR.exists():
    fallback_evidence = ROOT_DIR / "bharat-pa-forensics" / "test_evidence"
    if fallback_evidence.exists():
        TEST_EVIDENCE_DIR = fallback_evidence


def create_isolated_sandbox(prefix: str = "forensic_e2e_") -> Path:
    """Creates an isolated temporary scratch directory for opaque-box test executions."""
    tmp_base = ROOT_DIR / ".workspace_tmp" / "e2e_scratch"
    tmp_base.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=str(tmp_base)))
    return temp_dir


def cleanup_isolated_sandbox(sandbox_path: Path | str) -> None:
    """Cleans up the isolated scratch directory."""
    try:
        shutil.rmtree(str(sandbox_path), ignore_errors=True)
    except Exception:
        pass
