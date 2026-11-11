"""
Bharat Forensic Suite — E2E Test Environment Setup and Path Discovery
Puts the unified project root on sys.path. All code is resolved from the root only.
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

# The unified root is the only source of truth for src.*, parsers.* and tools.*
if str(ROOT_DIR) in sys.path:
    sys.path.remove(str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR))

TEST_EVIDENCE_DIR = ROOT_DIR / "test_evidence"


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
