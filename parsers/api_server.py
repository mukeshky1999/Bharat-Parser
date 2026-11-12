"""
Bharat-PA Forensics — High-Performance Local REST API Server
Bridges Python 1 TB+ FTS5 Paginated Case Store, Native Windows File/Folder Pickers,
Streaming Forensic Ingestion Pipeline, Graph Intelligence, and the examination report and review package
to the React / Electron Frontend Workbench.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import html
import html as html_lib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
import pandas as pd
import uvicorn

from parsers.account_profiler import (
    build_unified_owner_dossier,
    extract_account_profile,
)
from parsers.corroboration_engine import (
    harvest_corroboration_signals,
    heal_counterparties_across_apps,
    reconcile_and_enrich_artifacts,
)
from parsers.crypto_p2p_parser import parse_crypto_p2p_artifacts
from parsers.enterprise_1tb_chat_and_container_engine import (
    TerabyteForensicContainerEngine,
    UnsupportedContainer,
    should_materialize_artifact,
)
from parsers.fiat_crypto_bridge import (
    align_bank_to_custodial_onramp,
    align_fiat_to_crypto,
)
from parsers.graph_intelligence import (
    build_transaction_graph,
    classify_syndicate_roles,
    detect_mule_behavior,
    generate_pyvis_network_html,
)
from parsers.heuristic_engine import (
    compose_tx_provenance,
    extract_profile_from_sqlite,
    parse_database_artifacts,
)
from parsers.multi_source_fusion import (
    correlate_cdr_with_transactions,
    parse_bank_statement,
    parse_cdr_record,
    reconcile_bank_statement_with_device,
)
from parsers.plugin_loader import PluginRegistry
from parsers import examination_report, review_package
from parsers import encrypted_db
from parsers.keychain_decryptor import extract_app_keys_and_decrypt
from parsers.case_file import CaseFile, FILE_NAME as CASE_FILE_NAME, list_cases, safe_case_dir_name
from src.audit.ledger import AuditLedger, AuditTamperError
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from tools.forensic_benchmark_recorder import ForensicBenchmarkRecorder
from src.chat_reconstructor_and_redline.myers_redline_engine import MyersRedlineEngine
from src.chat_reconstructor_and_redline.models import DiffTokenType
from src.financial_graph_and_storyboard.sankey_canvas import SankeyCanvasRenderer, SankeyLaunderingCanvas, render_layout_svg
from src.financial_graph_and_storyboard.models import SankeyNode, SankeyFlowRibbon, SankeyStageColumn
from src.geospatial_media_and_tamper.bilingual_ocr_engine import BilingualOcrEngine

# ------------------------------------------------------------------------------
# App Initialization & State
# ------------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    print("[*] Bharat-PA Forensics API initializing...")
    yield
    # Shutdown sequence
    print("[*] Bharat-PA Forensics API shutting down. Draining thread pools and checkpointing databases...")
    _thread_pool.shutdown(wait=True)
    if _active_store is not None:
        try:
            conn = _active_store._get_connection()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
            print("[*] SQLite WAL checkpointed and closed successfully.")
        except Exception as e:
            print(f"[!] Warning: Failed to checkpoint WAL on shutdown: {e}")


app = FastAPI(
    title="Bharat-PA Forensics REST Engine",
    description="High-performance backend API for Indian UPI, Chat Forensics, 1 TB+ Case Store, and examination reporting",
    version="1.0.0",
    lifespan=lifespan,
)

# Per-launch API token. The Electron shell generates a random token, gives it to this process in
# BHARAT_API_TOKEN and to the renderer through the preload; every /api/ request must carry it in
# X-Bharat-Token. Without the variable (tests, plain `python -m parsers.api_server` in development)
# the check is skipped. Registered before CORS so that a 401 still carries CORS headers.
@app.middleware("http")
async def _require_api_token(request, call_next):
    expected = os.environ.get("BHARAT_API_TOKEN", "")
    if expected and request.method != "OPTIONS" and request.url.path.startswith("/api/"):
        supplied = request.headers.get("x-bharat-token", "")
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API token."})
    return await call_next(request)


# The API only serves the local desktop shell. Restrict origins (a web page the examiner happens
# to have open must not be able to read workstation files) and reject foreign Host headers
# (DNS rebinding). "null" is the origin of file:// pages loaded by Electron.
_ALLOWED_ORIGINS = [
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:4173", "http://127.0.0.1:4173",
    "null",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)

DEFAULT_WORKSPACE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "scratch", "active_case")
)
os.makedirs(DEFAULT_WORKSPACE_ROOT, exist_ok=True)

# Active Case Store instance
_active_store: CaseUIPaginatorStore = CaseUIPaginatorStore(
    case_workspace=DEFAULT_WORKSPACE_ROOT,
    db_name="bharat_case_store.db"
)

# Active Plugin Registry instance
_plugin_registry: PluginRegistry = PluginRegistry()

# Active Ingested Case State
_case_state: Dict[str, Any] = {
    "loaded": False,
    "case_id": None,
    "case_name": None,
    "evidence_path": None,
    "extractions": [],
    "counts": {},
    "owner_dossier": None,
    "hashes": {},
    "mule_alerts": [],
    "syndicate_roles": [],
    "device_metadata": None,
    "pyvis_html": "",
    "charge_sheet_chain": {},
}

_thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
_ingest_lock = asyncio.Lock()
_benchmark_lock = asyncio.Lock()

TOOL_VERSION = "2.0.0"
_audit_cache: Dict[str, AuditLedger] = {}
_log = __import__("logging").getLogger("bharat.api")


def _get_audit():
    """The audit ledger of the loaded case, or (None, reason). The file sits beside the case database."""
    cid = str(_case_state.get("case_id") or "").strip()
    if not cid:
        return None, "No case is loaded."
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", cid)[:80]
    path = os.path.join(os.path.dirname(os.path.abspath(_active_store.db_path)), f"audit_{safe}.jsonl")
    led = _audit_cache.get(path)
    if led is None:
        try:
            led = AuditLedger(cid, path)
        except AuditTamperError as exc:
            return None, f"Audit log failed verification: {exc}"
        _audit_cache[path] = led
    return led, ""


def _audit_event(action: str, payload: Optional[Dict[str, Any]] = None) -> None:
    led, err = _get_audit()
    if led is None:
        _log.error("audit event %s not recorded: %s", action, err)
        return
    actor = str(_case_state.get("examiner_name") or "").strip() or "examiner (name not entered)"
    led.append(actor, action, payload or {})


def _tool_environment() -> Dict[str, Any]:
    import platform
    commit = os.environ.get("BHARAT_BUILD_COMMIT", "")
    if not commit:
        try:
            import subprocess
            commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=3,
                                    cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip()
        except Exception:
            commit = ""
    return {
        "Tool": "BharatAnalyzer",
        "Tool version": TOOL_VERSION,
        "Build commit": commit or examination_report.NOT_RECORDED,
        "Python": platform.python_version(),
        "Operating system": f"{platform.system()} {platform.release()}",
    }


def _audit_summary() -> Dict[str, Any]:
    led, err = _get_audit()
    if led is None:
        return {"entries": [], "verified": False, "error": err, "head_hash": ""}
    res = led.verify()
    return {
        "entries": [{"seq": e.seq, "ts_utc": e.ts_utc, "ts_ist": e.ts_ist, "actor": e.actor, "action": e.action,
                     "payload": json.loads(e.payload_json), "hash": e.hash} for e in led.entries],
        "verified": res.ok, "error": res.error, "head_hash": res.head_hash,
    }



# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------

class CaseOpenRequest(BaseModel):
    workspace_dir: str
    db_name: Optional[str] = "bharat_case_store.db"


class IngestCaseRequest(BaseModel):
    evidence_path: str
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    examiner_name: Optional[str] = ""   # supplied by the examiner; never a placeholder name
    agency_name: Optional[str] = ""
    # "replace" (default) starts the case again from this evidence. "add" puts another device into the
    # existing case; the same source added again replaces only that item.
    mode: Optional[str] = "replace"
    label: Optional[str] = ""           # the examiner's name for this device, e.g. "Suspect's phone"
    # Keys the examiner holds for encrypted databases: name -> hex, base64 or passphrase. Used only to open files in
    # this ingest; never stored in the case file or the logs (the audit log keeps the name and a short fingerprint).
    keys: Optional[Dict[str, str]] = None


class BenchmarkRequest(BaseModel):
    dump_path: str
    output_dir: Optional[str] = None
    verbose: Optional[bool] = False


class FusionBankRequest(BaseModel):
    statement_path: Optional[str] = None
    csv_content: Optional[str] = None
    filename: Optional[str] = "bank_statement.csv"


class FusionCdrRequest(BaseModel):
    cdr_path: Optional[str] = None
    csv_content: Optional[str] = None
    filename: Optional[str] = "cdr_record.csv"


class SqliteInspectRequest(BaseModel):
    db_path: Optional[str] = None
    table_name: Optional[str] = None
    limit: int = 100


class ChatRedlineRequest(BaseModel):
    original_text: str
    edited_text: str


class ChatRedlineResponse(BaseModel):
    success: bool
    original_text: str
    edited_text: str
    rendered_markup: str
    tokens: List[Dict[str, Any]]
    has_financial_or_crypto_token: bool


class OcrAnalyzeRequest(BaseModel):
    image_path: str


# ------------------------------------------------------------------------------
# Ingestion progress (5B.3): what the pipeline is really doing, readable while it runs
# ------------------------------------------------------------------------------

class IngestProgress:
    """Progress of the ingest that is running (or ran last). Every value comes from the pipeline:

    - ``stage`` / ``stage_index`` / ``stage_count``: the step the pipeline is in, out of the fixed list below.
    - ``units_done`` / ``units_total`` / ``unit``: work counted inside that step (bytes hashed, files read, tables
      written). ``fraction`` is set only when the total is known; otherwise it is None, never a made-up percentage.
    - ``stage_eta_s`` is a straight-line estimate for the current step alone, given once 5 percent is done.
    There is deliberately no overall percentage: the steps differ in cost and the pipeline cannot know by how much.
    """

    STAGES = [
        ("hash_evidence", "Hashing the evidence"),
        ("extract", "Reading the container"),
        ("keys", "Looking for keys"),
        ("parse", "Reading databases"),
        ("reconcile", "Reconciling across apps"),
        ("owner", "Building the owner profile"),
        ("align", "Aligning fiat and crypto records"),
        ("link", "Link analysis"),
        ("store", "Writing the case store"),
        ("verify", "Re-hashing the evidence"),
        ("save", "Saving the case"),
    ]
    MAX_EVENTS = 500

    def __init__(self, case_id: str = "", evidence_item: str = "", evidence: str = "", mode: str = "") -> None:
        self._lock = threading.Lock()
        self.job_id = uuid.uuid4().hex[:12]
        self.case_id, self.evidence_item, self.evidence, self.mode = case_id, evidence_item, evidence, mode
        self.state = "running"
        self.current_stage = ""
        self.units_done = 0
        self.units_total: Optional[int] = None
        self.unit = ""
        self.detail = ""
        self.message = ""
        self._seq = 0
        self._events: List[Dict[str, Any]] = []
        self._log: Optional[List[Dict[str, Any]]] = None
        self._t0 = time.monotonic()
        self._stage_t0 = self._t0
        self.started_utc = datetime.now(timezone.utc).isoformat()
        self.updated_utc = self.started_utc

    # -- writers (called by the pipeline) -----------------------------------------------------------
    def _event(self, kind: str, **kw: Any) -> None:
        self._seq += 1
        self._events.append({"seq": self._seq, "t": datetime.now(timezone.utc).isoformat(), "kind": kind, **kw})
        if len(self._events) > self.MAX_EVENTS:
            del self._events[: len(self._events) - self.MAX_EVENTS]
        self.updated_utc = self._events[-1]["t"]

    def attach_log(self, processing_log: List[Dict[str, Any]]) -> None:
        self._log = processing_log

    def stage(self, key: str, total: Optional[int] = None, unit: str = "") -> None:
        with self._lock:
            self.current_stage, self.units_done, self.units_total, self.unit, self.detail = key, 0, total, unit, ""
            self._stage_t0 = time.monotonic()
            self._event("stage", stage=key, label=dict(self.STAGES).get(key, key), units_total=total, unit=unit)

    def progress(self, done: int, total: Optional[int] = None, detail: str = "") -> None:
        with self._lock:
            self.units_done = int(done)
            if total is not None:
                self.units_total = int(total)
            if detail:
                self.detail = detail
            self.updated_utc = datetime.now(timezone.utc).isoformat()

    def add(self, n: int) -> None:
        with self._lock:
            self.units_done += int(n)

    def note(self, detail: str) -> None:
        with self._lock:
            self.detail = detail
            self.updated_utc = datetime.now(timezone.utc).isoformat()

    def succeed(self, message: str = "") -> None:
        with self._lock:
            self.state, self.message = "succeeded", message
            self._event("done", message=message)

    def fail(self, message: str) -> None:
        with self._lock:
            if self.state != "running":
                return
            self.state, self.message = "failed", message
            self._event("failed", stage=self.current_stage, message=message)

    # -- reader (the endpoint) ------------------------------------------------------------------------
    def snapshot(self, since: int = 0) -> Dict[str, Any]:
        with self._lock:
            keys = [k for k, _ in self.STAGES]
            idx = keys.index(self.current_stage) + 1 if self.current_stage in keys else 0
            fraction = None
            eta = None
            if self.units_total:
                fraction = max(0.0, min(1.0, self.units_done / self.units_total))
                if fraction >= 0.05 and self.state == "running":
                    eta = round((time.monotonic() - self._stage_t0) * (1 - fraction) / fraction, 1)
            log = list(self._log) if self._log is not None else []
            return {
                "job_id": self.job_id, "state": self.state, "case_id": self.case_id,
                "evidence_item": self.evidence_item, "evidence": os.path.basename(self.evidence), "mode": self.mode,
                "stage": self.current_stage, "stage_label": dict(self.STAGES).get(self.current_stage, ""),
                "stage_index": idx, "stage_count": len(self.STAGES),
                "units_done": self.units_done, "units_total": self.units_total, "unit": self.unit,
                "fraction": fraction, "stage_eta_s": eta, "detail": self.detail, "message": self.message,
                "started_utc": self.started_utc, "updated_utc": self.updated_utc,
                "elapsed_s": round(time.monotonic() - self._t0, 1),
                "seq": self._seq,
                "events": [e for e in self._events if e["seq"] > since],
                "processing_log_count": len(log), "processing_log_tail": log[-20:],
            }


_ingest_progress: IngestProgress = IngestProgress()
_ingest_progress.state = "idle"


def _evidence_size(path: str) -> int:
    """Bytes the hashing step will read: the file, or every file under a folder."""
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


# ------------------------------------------------------------------------------
# Hashing & File Utilities
# ------------------------------------------------------------------------------

def _hash_stream(path: str, md5_h, sha_h, on_bytes=None) -> int:
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            md5_h.update(chunk)
            sha_h.update(chunk)
            if on_bytes:
                on_bytes(len(chunk))
    return total


def compute_hashes_streaming(file_path: str, on_bytes=None) -> Dict[str, Any]:
    """
    Computes SHA-256 and MD5 in read-only 8 MB streaming chunks.

    Files hash their bytes. Directories hash a manifest of sorted, relative
    ``path\0sha256\0size`` lines, so renaming/adding/removing a file changes the digest.
    Unreadable files raise (the hash would otherwise silently describe less than the evidence).
    A missing path raises FileNotFoundError; an empty input is reported, never "verified".
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Cannot hash missing path: {file_path}")

    md5_hasher = hashlib.md5()
    sha256_hasher = hashlib.sha256()
    total_bytes = 0
    file_count = 1

    if os.path.isfile(file_path):
        total_bytes = _hash_stream(file_path, md5_hasher, sha256_hasher, on_bytes)
    else:
        entries: List[Tuple[str, str, int]] = []
        for root, dirs, files in os.walk(file_path):
            dirs.sort()
            for name in sorted(files):
                full_p = os.path.join(root, name)
                rel = os.path.relpath(full_p, file_path).replace("\\", "/")
                f_sha = hashlib.sha256()
                f_md5 = hashlib.md5()
                size = _hash_stream(full_p, f_md5, f_sha, on_bytes)
                total_bytes += size
                entries.append((rel, f_sha.hexdigest(), size))
        entries.sort()
        file_count = len(entries)
        for rel, digest, size in entries:
            line = f"{rel}\0{digest}\0{size}\n".encode("utf-8")
            md5_hasher.update(line)
            sha256_hasher.update(line)

    return {
        "md5": md5_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
        "fileSizeBytes": total_bytes,
        "fileCount": file_count,
        "method": "file-bytes" if os.path.isfile(file_path) else "sorted-path-sha256-manifest",
        "verified": file_count > 0 and total_bytes > 0,
        "calculatedAt": datetime.now(timezone.utc).isoformat(),
    }


def _run_native_file_dialog() -> str:
    """Invokes native Windows File Explorer dialog using Tkinter on dedicated thread."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.focus_force()
        filetypes = [
            (
                "Forensic Containers & Databases",
                "*.ufdr;*.ufd;*.tar;*.tar.gz;*.tgz;*.zip;*.xry;*.ofb;*.ab;*.db;*.sqlite;*.sqlite3",
            ),
            ("UFDR Archives (*.ufdr;*.ufd)", "*.ufdr;*.ufd"),
            ("Physical/Logical TAR Images (*.tar;*.tar.gz)", "*.tar;*.tar.gz"),
            ("ZIP Archives (*.zip)", "*.zip"),
            ("SQLite Databases (*.db;*.sqlite;*.sqlite3)", "*.db;*.sqlite;*.sqlite3"),
            ("All Files (*.*)", "*.*"),
        ]
        selected = filedialog.askopenfilename(
            title="Select Forensic Evidence Container / Database",
            filetypes=filetypes,
        )
        root.destroy()
        return selected or ""
    except Exception as e:
        print(f"[!] Tkinter file dialog error: {e}", file=sys.stderr)
        return ""


def _run_native_folder_dialog() -> str:
    """Invokes native Windows Folder Explorer dialog using Tkinter on dedicated thread."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.focus_force()
        selected = filedialog.askdirectory(
            title="Select Extracted Evidence Directory / Physical Dump Folder",
            mustexist=True,
        )
        root.destroy()
        return selected or ""
    except Exception as e:
        print(f"[!] Tkinter folder dialog error: {e}", file=sys.stderr)
        return ""


# ------------------------------------------------------------------------------
# File access sandbox
# ------------------------------------------------------------------------------

def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:  # different drives
        return False


def _case_roots() -> List[Tuple[Optional[str], Optional[str], str]]:
    """(evidence item id, evidence source path, working copy folder) for every item of the loaded case."""
    ws = os.path.abspath(_active_store.case_workspace)
    if not _case_state.get("loaded"):
        return [(None, None, os.path.join(ws, "working_copy"))]
    items = _case_state.get("items")
    if items:
        return [
            (it["item_id"], it.get("source_path"),
             os.path.join(ws, "items", safe_case_dir_name(it["item_id"]), "working_copy"))
            for it in items
        ]
    return [(None, _case_state.get("evidence_path"), os.path.join(ws, "working_copy"))]


def _resolve_case_file(requested: str, *, for_sqlite: bool = False, evidence_item: Optional[str] = None) -> str:
    """
    Resolves a client-supplied path to a file the active case may read.

    Only the case workspace and the evidence sources are allowed. When SQLite is going to open the
    file, a path inside an original evidence folder is redirected to the identical file in that item's
    working copy, so the original is never touched.

    A case can hold several devices, and two phones have the same relative paths. A relative path that
    exists in more than one evidence item is refused (409) unless the caller names the item.
    """
    if not requested or not isinstance(requested, str):
        raise HTTPException(status_code=400, detail="A file path is required.")
    ws = os.path.abspath(_active_store.case_workspace)
    roots = _case_roots()
    if evidence_item:
        roots = [r for r in roots if r[0] == evidence_item]
        if not roots:
            raise HTTPException(status_code=404, detail=f"No evidence item {evidence_item} in this case.")
    ev_paths = [r[1] for r in roots if r[1]]

    def in_ev(p: str) -> bool:
        return any(_is_within(p, e) for e in ev_paths)

    direct = [os.path.abspath(requested), os.path.abspath(os.path.join(ws, requested))]
    relative_ok = ".." not in re.split(r"[\\/]+", requested) and not os.path.isabs(requested)

    # (item id, evidence source, working copy, candidate); the item id is None for a direct path
    cands: List[Tuple[Optional[str], Optional[str], Optional[str], str]] = [(None, None, None, c) for c in direct]
    if relative_ok:
        for item_id, ev, wc in roots:
            cands.append((item_id, ev, wc, os.path.abspath(os.path.join(wc, requested))))
            if ev and os.path.isdir(ev):
                cands.append((item_id, ev, wc, os.path.abspath(os.path.join(ev, requested))))

    allowed_missing = False
    found: List[Tuple[Optional[str], Optional[str], Optional[str], str]] = []
    for item_id, ev, wc, cand in cands:
        if not (_is_within(cand, ws) or in_ev(cand)):
            continue
        if not os.path.isfile(cand):
            allowed_missing = True
            continue
        found.append((item_id, ev, wc, cand))

    if found:
        direct_hit = [f for f in found if f[0] is None]
        chosen_group = direct_hit or found
        items_hit = {f[0] for f in chosen_group if f[0] is not None}
        if len(items_hit) > 1:
            raise HTTPException(
                status_code=409,
                detail=f"This path exists in more than one evidence item ({', '.join(sorted(items_hit))}). "
                       "Say which item it belongs to.",
            )
        item_id, ev, wc, cand = chosen_group[0]
        if for_sqlite and in_ev(cand) and not _is_within(cand, ws):
            owner = next((r for r in roots if r[1] and _is_within(cand, r[1])), None)
            if owner is None:
                raise HTTPException(status_code=404, detail="No working copy exists for this evidence file.")
            o_ev, o_wc = owner[1], owner[2]
            rel = os.path.relpath(cand, o_ev if os.path.isdir(o_ev) else os.path.dirname(o_ev))
            mapped = os.path.join(o_wc, rel)
            if not os.path.isfile(mapped):
                raise HTTPException(status_code=404, detail="No working copy exists for this evidence file.")
            return mapped
        return cand
    if allowed_missing:
        raise HTTPException(status_code=404, detail=f"File not found: {requested}")
    raise HTTPException(
        status_code=403,
        detail="Access Denied: Requested file path is outside the active case workspace and evidence container.",
    )


def _case_state_from_file(ws: str, cf: CaseFile, active_item_id: Optional[str] = None) -> Dict[str, Any]:
    """The in-memory case state, rebuilt from the case file. The same code runs after an ingest and after a reopen."""
    info = cf.info()
    items = cf.items()
    active = next((i for i in items if i["item_id"] == active_item_id), None) or (items[-1] if items else None)
    analysis = (active or {}).get("analysis") or {}
    return {
        "loaded": True,
        "case_id": info.get("case_id") or os.path.basename(ws),
        "case_name": info.get("case_name") or "",
        "evidence_path": (active or {}).get("source_path") or ws,
        "examiner_name": info.get("examiner_name", ""),
        "agency_name": info.get("agency_name", ""),
        "items": [
            {k: it.get(k) for k in ("item_id", "label", "source_path", "kind", "added_utc", "integrity_match",
                                    "hashes", "device", "processing_log", "record_counts")}
            for it in items
        ],
        "active_item": (active or {}).get("item_id"),
        "extractions": [
            {"evidenceId": it["item_id"], "label": it.get("label") or "", "sourcePath": it.get("source_path"),
             "type": "PHYSICAL_OR_LOGICAL", "hashes": it.get("hashes") or {}, "deviceMetadata": it.get("device") or {}}
            for it in items
        ],
        "owner_dossier": (active or {}).get("dossier"),
        "hashes": (active or {}).get("hashes") or {},
        "device_metadata": (active or {}).get("device"),
        "processing_log": (active or {}).get("processing_log") or [],
        "mule_alerts": analysis.get("mule_alerts", []),
        "syndicate_roles": analysis.get("syndicate_roles", []),
        "charge_sheet_chain": analysis.get("charge_sheet_chain", {}),
        "pyvis_html": analysis.get("pyvis_html", ""),
        "workspace_dir": ws,
    }


def _item_summaries(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for it in state.get("items") or []:
        h = it.get("hashes") or {}
        d = it.get("device") or {}
        out.append({
            "item_id": it["item_id"], "label": it.get("label") or "", "source_path": it.get("source_path") or "",
            "kind": it.get("kind") or "", "added_utc": it.get("added_utc") or "",
            "integrity_match": it.get("integrity_match"),
            "sha256": h.get("sha256") or "", "model": d.get("model") or "", "manufacturer": d.get("manufacturer") or "",
            "records": it.get("record_counts") or {},
            "failed_steps": sum(1 for e in (it.get("processing_log") or []) if str(e.get("status", "")).upper() == "FAILED"),
        })
    return out


# ------------------------------------------------------------------------------
# Core Ingestion Pipeline Implementation
# ------------------------------------------------------------------------------

_STORED_FRAMES = ("chats", "transactions", "contacts", "calls", "locations", "os_spillover", "p2p_orders")


def decoder_name(function: str, app_profile: str = "") -> str:
    """Parser and version, as written into Decoded_By on every record it produces."""
    return f"parsers.heuristic_engine.{function} {TOOL_VERSION}; app profile: {app_profile or 'none (generic)'}"


def db_coverage(counts: Dict[str, int], error: str = "") -> Tuple[str, str, Dict[str, int]]:
    """What became of a SQLite file: (outcome, reason, records kept per table)."""
    if error:
        return "FAILED", error, {}
    kept = {k: v for k, v in counts.items() if k in _STORED_FRAMES and v}
    dropped = {k: v for k, v in counts.items() if k not in _STORED_FRAMES and v}
    if kept and not dropped:
        return "DECODED", "", kept
    if dropped:
        why = "Decoded but not written to the case: " + ", ".join(f"{k} ({v})" for k, v in sorted(dropped.items()))
        return "PARTIAL", why, kept
    return "NOT_DECODED", "Opened as a SQLite database, but no table in it matched a decoder, so no records were produced.", {}


def non_database_coverage(path: str, f_low: str) -> Tuple[str, str, str]:
    """What became of a file that is not opened as a database: (outcome, reason, kind)."""
    if f_low.endswith(("-wal", "-shm", "-journal")):
        return "COMPANION", "Side file of a database; its content is read together with that database.", "SQLite side file"
    if f_low.endswith("build.prop"):
        return "METADATA_ONLY", "Read for device details only (model, manufacturer, Android version, build).", "Device properties"
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError as exc:
        return "FAILED", f"Could not be read: {exc}", "File"
    if head.startswith(b"SQLite format 3\x00"):
        return ("NOT_DECODED", "A SQLite database whose name does not end in .db, .sqlite or .sqlite3. The tool chooses "
                "databases by file extension, so it was not opened.", "SQLite database (not opened)")
    return "NOT_DECODED", "Not opened: the tool has no decoder for this file type.", "File"


def _execute_ingestion_pipeline(
    evidence_path: str,
    case_id: str,
    case_name: str,
    examiner_name: str,
    agency_name: str,
    mode: str = "replace",
    label: str = "",
    keys: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    global _active_store, _case_state

    abs_evidence = os.path.abspath(evidence_path)
    if not os.path.exists(abs_evidence):
        raise HTTPException(status_code=404, detail=f"Evidence path not found: {abs_evidence}")

    mode = "add" if mode == "add" else "replace"
    workspace_dir = os.path.abspath(os.path.join(DEFAULT_WORKSPACE_ROOT, safe_case_dir_name(case_id)))
    os.makedirs(workspace_dir, exist_ok=True)
    cfile = CaseFile(workspace_dir)
    if mode == "replace":
        # The case starts again from this one item. Folders of earlier items (and the pre-5B.2 layout) go.
        item_id, reprocess = "EV-001", False
        for stale_dir in ("items", "working_copy", "extracted_dbs"):
            shutil.rmtree(os.path.join(workspace_dir, stale_dir), ignore_errors=True)
    else:
        # Another device for the same case. The same source again replaces only that item.
        existing = cfile.item_for_source(abs_evidence)
        item_id, reprocess = (existing["item_id"], True) if existing else (cfile.next_item_id(), False)
        shutil.rmtree(os.path.join(workspace_dir, "items", item_id), ignore_errors=True)
    item_dir = os.path.join(workspace_dir, "items", item_id)
    extracted_dbs_dir = os.path.join(item_dir, "extracted_dbs")
    os.makedirs(extracted_dbs_dir, exist_ok=True)

    # 1. Compute Pre-Ingestion SHA-256 and MD5
    global _ingest_progress
    prog = _ingest_progress = IngestProgress(case_id, item_id, abs_evidence, mode)
    prog.stage("hash_evidence", total=_evidence_size(abs_evidence), unit="bytes")
    hashes = compute_hashes_streaming(abs_evidence, on_bytes=prog.add)

    # 2. Extract or Index Forensic DBs
    p_low = abs_evidence.lower()
    is_archive = p_low.endswith((".ufdr", ".ufd", ".tar", ".tar.gz", ".tgz", ".zip", ".xry", ".ofb", ".e01", ".ex01", ".l01"))
    # An Android backup or an iOS backup folder is read through src/vfs (it was copied as a single file or as
    # hash-named files before, and nothing in it was parsed).
    if TerabyteForensicContainerEngine.is_vfs_container(abs_evidence):
        is_archive = True

    catalog_entries: List[Dict[str, Any]] = []
    working_copy_dir: Optional[str] = None
    processing_log: List[Dict[str, str]] = []
    prog.attach_log(processing_log)

    def _log_failure(stage: str, path: str, exc: BaseException) -> None:
        processing_log.append({
            "stage": stage,
            "file": os.path.basename(path),
            "status": "FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        })

    # Phase 5B.4: one row for every file the tool looked at, saying what became of it.
    coverage: List[Dict[str, Any]] = []

    def _cov(name: str, outcome: str, reason: str = "", kind: str = "", decoded_by: str = "",
             records: Optional[Dict[str, int]] = None, path: str = "") -> None:
        try:
            size = os.path.getsize(path) if path else None
        except OSError:
            size = None
        coverage.append({"file": name, "size_bytes": size, "kind": kind, "outcome": outcome, "reason": reason,
                         "decoded_by": decoded_by or None, "records": records or {}})

    if p_low.endswith((".ufd", ".xry", ".ofb")) and not zipfile.is_zipfile(abs_evidence):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported container: {os.path.basename(abs_evidence)} is not a ZIP-based "
                   "extraction. Nothing was ingested.",
        )

    prog.stage("extract", unit="entries")
    if is_archive:
        container_engine = TerabyteForensicContainerEngine(abs_evidence, item_dir)
        try:
            container_engine.index_and_materialize_targets(
                progress_cb=lambda done, total, path: prog.progress(done, total or None, os.path.basename(str(path))))
        except UnsupportedContainer as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        for vpath in container_engine.rejected_entries:
            processing_log.append({"stage": "extract", "file": os.path.basename(vpath), "status": "WARNING",
                                   "error": f"Not extracted: the path {vpath!r} would leave the extraction folder"})
            _cov(vpath, "NOT_EXTRACTED", "The path would leave the extraction folder, so the entry was not extracted.")
        for vpath, why in container_engine.read_errors:
            processing_log.append({"stage": "extract", "file": os.path.basename(vpath), "status": "FAILED", "error": why})
            _cov(vpath, "NOT_EXTRACTED", why)
        # Collect materialized DBs
        discovered_files: List[str] = []
        for root, _, files in os.walk(extracted_dbs_dir):
            for f in files:
                discovered_files.append(os.path.join(root, f))
    elif os.path.isdir(abs_evidence):
        # Evidence is never opened in place: SQLite creates -shm/-wal side files and may
        # checkpoint. Parse a byte-identical working copy instead.
        working_copy_dir = os.path.join(item_dir, "working_copy")
        if os.path.isdir(working_copy_dir):
            shutil.rmtree(working_copy_dir)
        shutil.copytree(abs_evidence, working_copy_dir)
        discovered_files = []
        for root, _, files in os.walk(working_copy_dir):
            for f in files:
                f_path = os.path.join(root, f)
                discovered_files.append(f_path)
                catalog_entries.append({
                    "vfs_path": os.path.relpath(f_path, working_copy_dir).replace("\\", "/"),
                    "container_format": "RAW_FOLDER",
                    "file_name": f,
                    "file_size": os.path.getsize(f_path),
                    "archive_offset": 0,
                    "is_materialized": 1,
                    "local_disk_path": f_path,
                })
    else:
        working_copy_dir = os.path.join(item_dir, "working_copy")
        if os.path.isdir(working_copy_dir):
            shutil.rmtree(working_copy_dir)
        os.makedirs(working_copy_dir)
        # Bring sibling -wal/-shm/-journal along so WAL content is parsed from the copy.
        src_dir, src_name = os.path.split(abs_evidence)
        for sibling in os.listdir(src_dir):
            if sibling == src_name or (
                sibling.startswith(src_name)
                and sibling[len(src_name):] in ("-wal", "-shm", "-journal")
            ):
                shutil.copy2(os.path.join(src_dir, sibling), os.path.join(working_copy_dir, sibling))
        copied = os.path.join(working_copy_dir, src_name)
        discovered_files = [copied]
        catalog_entries.append({
            "vfs_path": src_name,
            "container_format": "FILE",
            "file_name": src_name,
            "file_size": os.path.getsize(copied),
            "archive_offset": 0,
            "is_materialized": 1,
            "local_disk_path": copied,
        })

    # 3. Discovery & Parsing Pipeline
    app_artifacts: Dict[str, Dict[str, Any]] = {}
    profiles: Dict[str, Any] = {}
    corroboration_signals: List[Dict[str, Any]] = []
    account_hints: List[Dict[str, str]] = []
    crypto_p2p_records: List[pd.DataFrame] = []

    all_chats_list: List[pd.DataFrame] = []
    all_txs_list: List[pd.DataFrame] = []
    all_contacts_list: List[pd.DataFrame] = []
    all_calls_list: List[pd.DataFrame] = []
    all_locations_list: List[pd.DataFrame] = []
    all_spillover_list: List[pd.DataFrame] = []

    device_meta = {
        "model": "Not recorded",
        "manufacturer": "Not recorded",
        "androidVersion": "Not recorded",
        "buildNumber": "Not recorded",
        "imei1": "Not recorded",
        "imei2": "Not recorded",
        "serialNumber": "Not recorded",
        "timezone": "Not recorded",
        "extractionType": "Not recorded",
        "evidenceSourcePath": abs_evidence,
        "hashes": hashes,
        # M-06: when the phone was acquired is not known from the files alone. It is not the time this
        # tool processed them, so it stays unrecorded; processing time is reported separately.
        "acquisitionTimestamp": {
            "rawValue": 0,
            "sourceFormat": "UNIX_MS",
            "utcIso": "Not recorded",
            "istFormatted": "Not recorded",
            "epochMs": 0,
        },
        "processedAtUtc": datetime.now(timezone.utc).isoformat(),
        "osType": _detect_os_type(discovered_files),
    }

    prog.stage("keys")
    # Keys for encrypted databases: what the examiner supplied plus what the evidence itself holds (key stores and
    # preference files). Nothing is generated or guessed.
    carved_keys: Dict[str, Any] = {}
    key_scan_root = working_copy_dir or extracted_dbs_dir
    if key_scan_root and os.path.isdir(key_scan_root):
        try:
            carved_keys = extract_app_keys_and_decrypt(key_scan_root, "")
        except Exception as exc:
            _log_failure("key_search", key_scan_root, exc)
    key_candidates = encrypted_db.build_candidates(keys, carved_keys)
    # The audit ledger belongs to a loaded case, which does not exist yet. These are written after the ingest event.
    key_events: List[Tuple[str, Dict[str, Any]]] = []
    if key_candidates:
        key_events.append(("keys_available", {
            "evidence_item": item_id,
            "keys": [{"label": lab, "fingerprint": encrypted_db.key_fingerprint(mat)} for lab, mat in key_candidates],
        }))

    # Iterate over discovered files
    prog.stage("parse", total=len(discovered_files), unit="files")
    for _file_no, file_path in enumerate(discovered_files):
        prog.progress(_file_no, len(discovered_files), os.path.basename(file_path))
        f_low = file_path.lower()
        original_file_path = file_path  # the path in the evidence; a decrypted copy lives elsewhere
        # Determine relative / virtual file system path for accurate plugin matching
        if is_archive and original_file_path.startswith(extracted_dbs_dir):
            vfs_path = os.path.relpath(original_file_path, extracted_dbs_dir).replace("\\", "/")
        elif working_copy_dir and original_file_path.startswith(working_copy_dir):
            vfs_path = os.path.relpath(original_file_path, working_copy_dir).replace("\\", "/")
        else:
            vfs_path = original_file_path.replace("\\", "/")

        decrypted_note = ""
        file_counts: Dict[str, int] = {}
        file_error = ""

        # An encrypted database is opened only with a key that was supplied or found in the evidence.
        enc_reason = encrypted_db.encrypted_database_reason(file_path)
        if enc_reason:
            rel = os.path.basename(file_path)
            out_dir = os.path.join(item_dir, "decrypted", hashlib.sha1(file_path.encode("utf-8", "replace")).hexdigest()[:8])
            outcome = encrypted_db.try_decrypt(file_path, out_dir, key_candidates)
            if outcome["status"] == "DECRYPTED":
                note = f"decrypted with {outcome['key_label']} (key {outcome['key_fingerprint']}), profile {outcome['profile']}"
                caveats = "; ".join(outcome.get("notes") or [])
                processing_log.append({
                    "stage": "decrypt_database", "file": rel,
                    "status": "WARNING" if caveats else "OK",
                    "error": (note + ("; " + caveats if caveats else "")),
                })
                key_events.append(("key_used", {"evidence_item": item_id, "file": rel, "key": outcome["key_label"],
                                                "fingerprint": outcome["key_fingerprint"], "profile": outcome["profile"],
                                                "caveats": outcome.get("notes") or []}))
                file_path = outcome["out_path"]
                decrypted_note = f"; opened after decryption with key {outcome['key_fingerprint']} (src.crypto.sqlcipher)"
                f_low = file_path.lower()
            elif outcome["status"] == "KEY_FOUND_OUTPUT_UNREADABLE":
                processing_log.append({"stage": "decrypt_database", "file": rel, "status": "FAILED",
                                       "error": "; ".join(outcome.get("notes") or [])})
                _cov(vfs_path, "FAILED", "; ".join(outcome.get("notes") or []),
                     kind="SQLite database (encrypted)", path=original_file_path)
                continue
            else:
                processing_log.append({
                    "stage": "decrypt_database", "file": rel, "status": "ENCRYPTED_NO_KEY",
                    "error": f"{enc_reason}. " + "; ".join(outcome.get("notes") or []) + ". Its content was not read.",
                })
                _cov(vfs_path, "ENCRYPTED_NO_KEY", f"{enc_reason}. Its content was not read.",
                     kind="SQLite database (encrypted)", path=original_file_path)
                continue

        # Check for build.prop / device info
        if f_low.endswith("build.prop"):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as bf:
                    for line in bf:
                        if line.startswith("ro.product.model="):
                            device_meta["model"] = line.split("=", 1)[1].strip()
                        elif line.startswith("ro.product.manufacturer="):
                            device_meta["manufacturer"] = line.split("=", 1)[1].strip()
                        elif line.startswith("ro.build.version.release="):
                            device_meta["androidVersion"] = f"Android {line.split('=', 1)[1].strip()}"
                        elif line.startswith("ro.build.display.id="):
                            device_meta["buildNumber"] = line.split("=", 1)[1].strip()
            except Exception:
                pass

        # Plugin match
        matched_plugin = _plugin_registry.match_path(clean_path=vfs_path)
        if not matched_plugin and vfs_path != file_path:
            matched_plugin = _plugin_registry.match_path(clean_path=file_path)
        app_label = matched_plugin.app_name if matched_plugin else os.path.basename(file_path)

        # Profile extraction
        try:
            prof1 = extract_account_profile(file_path)
            if prof1:
                profiles[f"{app_label}_{os.path.basename(file_path)}"] = prof1
        except Exception as exc:
            _log_failure("account_profile", file_path, exc)

        if f_low.endswith((".db", ".sqlite", ".sqlite3")):
            try:
                prof2 = extract_profile_from_sqlite(file_path)
                if prof2:
                    profiles[f"{app_label}_sqlite_{os.path.basename(file_path)}"] = prof2
            except Exception as exc:
                _log_failure("sqlite_profile", file_path, exc)

            # Corroboration signals
            try:
                sigs, hints = harvest_corroboration_signals(file_path)
                if sigs:
                    corroboration_signals.extend(sigs)
                if hints:
                    account_hints.extend(hints)
            except Exception as exc:
                _log_failure("corroboration_signals", file_path, exc)

            # Heuristic database parsing
            try:
                arts = parse_database_artifacts(file_path, os_type=device_meta["osType"], app_label=app_label)
                decoder = decoder_name("parse_database_artifacts", matched_plugin.app_name if matched_plugin else "") + decrypted_note
                if arts:
                    for _name, _fr in arts.items():
                        if isinstance(_fr, pd.DataFrame) and not _fr.empty:
                            _fr["Decoded_By"] = decoder
                            file_counts[_name] = len(_fr)
                    # H-08: stamp every record with its application and source file at parse time.
                    for frame_name in ("chats", "transactions", "contacts", "calls", "locations"):
                        fr = arts.get(frame_name)
                        if fr is None or fr.empty:
                            continue
                        if frame_name != "chats":
                            if "Application" not in fr.columns:
                                fr["Application"] = app_label
                            else:
                                fr["Application"] = fr["Application"].where(
                                    fr["Application"].astype(str).str.strip().ne("") & fr["Application"].notna(),
                                    app_label,
                                )
                            if "Source_File" not in fr.columns:
                                fr["Source_File"] = vfs_path
                            else:
                                fr["Source_File"] = fr["Source_File"].where(
                                    fr["Source_File"].astype(str).str.strip().ne("") & fr["Source_File"].notna(),
                                    vfs_path,
                                )
                            if frame_name == "transactions":
                                _stamp_transaction_evidence(fr, vfs_path)
                    key = app_label
                    n = 2
                    while key in app_artifacts:
                        key = f"{app_label}#{n}"
                        n += 1
                    app_artifacts[key] = arts
                    if "chats" in arts and not arts["chats"].empty:
                        all_chats_list.append(arts["chats"])
                    if "transactions" in arts and not arts["transactions"].empty:
                        all_txs_list.append(arts["transactions"])
                    if "contacts" in arts and not arts["contacts"].empty:
                        all_contacts_list.append(arts["contacts"])
                    if "calls" in arts and not arts["calls"].empty:
                        all_calls_list.append(arts["calls"])
                    if "locations" in arts and not arts["locations"].empty:
                        all_locations_list.append(arts["locations"])
                    if "os_spillover" in arts and not arts["os_spillover"].empty:
                        all_spillover_list.append(arts["os_spillover"])
                processing_log.append({"stage": "parse_database", "file": os.path.basename(file_path), "status": "OK", "error": ""})
            except Exception as exc:
                _log_failure("parse_database", file_path, exc)
                file_error = f"{type(exc).__name__}: {exc}"

            # Crypto P2P parsing
            try:
                crypto_df = parse_crypto_p2p_artifacts(file_path, app_name=app_label)
                if crypto_df is not None and not crypto_df.empty:
                    crypto_df["Decoded_By"] = decoder_name("parse_crypto_p2p_artifacts", app_label) + decrypted_note
                    file_counts["p2p_orders"] = len(crypto_df)
                    crypto_p2p_records.append(crypto_df)
            except Exception as exc:
                _log_failure("crypto_p2p", file_path, exc)

            _outcome, _reason, _stored = db_coverage(file_counts, file_error)
            _cov(vfs_path, _outcome, _reason, kind="SQLite database", path=original_file_path,
                 decoded_by=(decoder_name("parse_database_artifacts", matched_plugin.app_name if matched_plugin else "") + decrypted_note) if _stored else "",
                 records=_stored)
        else:
            _outcome, _reason, _kind = non_database_coverage(file_path, f_low)
            _cov(vfs_path, _outcome, _reason, kind=_kind, path=file_path,
                 decoded_by=("device property reader (parsers.api_server)" if _outcome == "METADATA_ONLY" else ""))

    prog.progress(len(discovered_files), len(discovered_files))
    # 4. Reconciliation and Cross-App Enrichment
    prog.stage("reconcile")
    try:
        app_artifacts, reconciled_profiles = reconcile_and_enrich_artifacts(
            app_artifacts=app_artifacts,
            profiles=profiles,
            corroboration_signals=corroboration_signals,
            account_hints=account_hints,
        )
    except Exception as e:
        print(f"[!] Warning during artifact reconciliation: {e}", file=sys.stderr)

    try:
        app_artifacts = heal_counterparties_across_apps(app_artifacts)
    except Exception as e:
        print(f"[!] Warning during counterparty healing: {e}", file=sys.stderr)

    # 5. Master Owner Dossier
    prog.stage("owner")
    try:
        master_owner_dossier = build_unified_owner_dossier(
            profiles=profiles,
            app_artifacts=app_artifacts,
            vpa_df=pd.DataFrame(),
            ifsc_df=pd.DataFrame(),
            account_hints=account_hints,
        )
    except Exception as e:
        print(f"[!] Warning building master owner dossier: {e}", file=sys.stderr)
        master_owner_dossier = {
            "Primary_Mobile": "N/A",
            "Secondary_Mobiles": [],
            "All_Mobiles_List": [],
            "Account_Holder_Names": [],
            "Owner_Emails": [],
            "Owner_VPAs_Raw": [],
            "Owner_VPAs_Detailed": [],
            "Linked_Bank_Accounts": [],
            "Active_Financial_Apps": [],
            "Security_Key_Handles": [],
            "UPI_Circle_Delegations": [],
            "Per_App_Breakdown_DF": pd.DataFrame(),
        }

    # 6. Fiat-to-Crypto & Bank-to-Custodial Alignment
    prog.stage("align")
    combined_txs_df = pd.concat(all_txs_list, ignore_index=True) if all_txs_list else pd.DataFrame()
    combined_crypto_df = pd.concat(crypto_p2p_records, ignore_index=True) if crypto_p2p_records else pd.DataFrame()

    aligned_fiat_crypto_df = pd.DataFrame()
    aligned_bank_custodial_df = pd.DataFrame()

    if not combined_txs_df.empty and not combined_crypto_df.empty:
        try:
            aligned_fiat_crypto_df = align_fiat_to_crypto(
                upi_timeline=combined_txs_df,
                p2p_orders=combined_crypto_df,
                window_minutes=45,
                amount_tolerance_pct=8.0,
            )
        except Exception:
            pass

        try:
            aligned_bank_custodial_df = align_bank_to_custodial_onramp(
                bank_or_upi_df=combined_txs_df,
                custodial_wallet_records=combined_crypto_df,
                window_minutes=60,
                amount_tolerance_pct=8.0,
            )
        except Exception:
            pass

    # 7. Graph Intelligence: Syndicate Roles & Mule Behavior
    prog.stage("link")
    g = build_transaction_graph(combined_txs_df)
    roles_df = classify_syndicate_roles(g, combined_txs_df)
    mule_alerts = detect_mule_behavior(g, combined_txs_df)
    pyvis_html = generate_pyvis_network_html(g, mule_alerts, roles_df)

    # 8. Commit All Data to SQLite+FTS5 Case Store
    prog.stage("store", unit="tables")
    # Opening the same case id again must not add the records a second time: start from an empty store.
    # (The findings file is separate and is kept.)
    if mode == "replace":
        for suffix in ("", "-wal", "-shm"):
            stale = os.path.join(workspace_dir, "bharat_case_store.db" + suffix)
            if os.path.isfile(stale):
                os.remove(stale)
        cfile.remove_all_items()
    store = CaseUIPaginatorStore(workspace_dir, db_name="bharat_case_store.db")
    if mode == "add" and reprocess:
        store.delete_evidence_item(item_id)       # the examiner's tags on this item are set aside, not deleted
    ingested: Dict[str, int] = {}

    if all_chats_list:
        combined_chats = pd.concat(all_chats_list, ignore_index=True)
        prog.note("writing chats")
        ingested["chats"] = store.ingest_dataframe_chunked("chats", combined_chats, evidence_item=item_id)

    if not combined_txs_df.empty:
        prog.note("writing transactions")
        ingested["transactions"] = store.ingest_dataframe_chunked("transactions", combined_txs_df, evidence_item=item_id)

    if all_contacts_list:
        combined_contacts = pd.concat(all_contacts_list, ignore_index=True)
        prog.note("writing contacts")
        ingested["contacts"] = store.ingest_dataframe_chunked("contacts", combined_contacts, evidence_item=item_id)

    if all_calls_list:
        combined_calls = pd.concat(all_calls_list, ignore_index=True)
        prog.note("writing calls")
        ingested["calls"] = store.ingest_dataframe_chunked("calls", combined_calls, evidence_item=item_id)

    if all_locations_list:
        combined_locations = pd.concat(all_locations_list, ignore_index=True)
        prog.note("writing locations")
        ingested["locations"] = store.ingest_dataframe_chunked("locations", combined_locations, evidence_item=item_id)

    if all_spillover_list:
        combined_spillover = pd.concat(all_spillover_list, ignore_index=True)
        prog.note("writing os_spillover")
        ingested["os_spillover"] = store.ingest_dataframe_chunked("os_spillover", combined_spillover, evidence_item=item_id)

    if not combined_crypto_df.empty:
        prog.note("writing p2p_orders")
        ingested["p2p_orders"] = store.ingest_dataframe_chunked("p2p_orders", combined_crypto_df, evidence_item=item_id)

    if not aligned_fiat_crypto_df.empty:
        aligned_fiat_crypto_df = aligned_fiat_crypto_df.assign(
            Decoded_By="derived by the tool from the p2p and transaction records (not read from a file)")
        prog.note("writing fiat_crypto_bridge")
        ingested["fiat_crypto_bridge"] = store.ingest_dataframe_chunked("fiat_crypto_bridge", aligned_fiat_crypto_df, evidence_item=item_id)

    if catalog_entries:
        catalog_df = pd.DataFrame(catalog_entries)
        prog.note("writing vfs_files")
        ingested["vfs_files"] = store.ingest_dataframe_chunked("vfs_files", catalog_df, evidence_item=item_id)

    for tbl, cols in store.last_dropped_columns.items():
        if cols:
            processing_log.append({
                "stage": "ingest_schema", "file": tbl, "status": "WARNING",
                "error": f"Columns with data not stored: {', '.join(cols)}",
            })

    # 5B.4: files seen but not (fully) decoded are limitations; the full list is the coverage report.
    for c in coverage:
        if c["outcome"] == "PARTIAL" or (c["outcome"] == "NOT_DECODED" and c["kind"].startswith("SQLite")):
            processing_log.append({"stage": "coverage", "file": os.path.basename(c["file"]), "status": "WARNING", "error": c["reason"]})
    n_other = sum(1 for c in coverage if c["outcome"] == "NOT_DECODED" and not c["kind"].startswith("SQLite"))
    if n_other:
        processing_log.append({"stage": "coverage", "file": f"{n_other} file(s)", "status": "WARNING",
                               "error": "Seen, but the tool has no decoder for them; they are listed in the coverage report"})
    store.add_coverage(item_id, coverage)
    retag = store.reattach_tags(item_id)
    if retag["reattached"] or retag["detached"]:
        _audit_event("tags_reattached", {"evidence_item": item_id, **retag})
    if retag["detached"]:
        processing_log.append({"stage": "tags", "file": item_id, "status": "WARNING",
                               "error": f"{retag['detached']} tag(s) could not be placed on a record after processing again "
                                        f"(no single record with the same source location). They are kept, marked detached."})

    # Post-ingestion integrity check: re-hash the original evidence and compare.
    prog.stage("verify", total=_evidence_size(abs_evidence), unit="bytes")
    post_hashes = compute_hashes_streaming(abs_evidence, on_bytes=prog.add)
    hashes["postIngestionSha256"] = post_hashes["sha256"]
    hashes["postIngestionMd5"] = post_hashes["md5"]
    hashes["integrityMatch"] = (
        post_hashes["sha256"] == hashes["sha256"] and post_hashes["md5"] == hashes["md5"]
    )
    if not hashes["integrityMatch"]:
        processing_log.append({
            "stage": "integrity", "file": os.path.basename(abs_evidence), "status": "FAILED",
            "error": "Evidence hash changed during ingestion",
        })

    # Update active store and state
    prog.stage("save")
    _active_store = store
    counts = _active_store.get_project_tree_counts()

    # Clean serializable dossier
    serializable_dossier = {
        "Primary_Mobile": master_owner_dossier.get("Primary_Mobile", "N/A"),
        "Secondary_Mobiles": master_owner_dossier.get("Secondary_Mobiles", []),
        "All_Mobiles_List": master_owner_dossier.get("All_Mobiles_List", []),
        "Account_Holder_Names": master_owner_dossier.get("Account_Holder_Names", []),
        "Owner_Emails": master_owner_dossier.get("Owner_Emails", []),
        "Owner_VPAs_Raw": master_owner_dossier.get("Owner_VPAs_Raw", []),
        "Owner_VPAs_Detailed": master_owner_dossier.get("Owner_VPAs_Detailed", []),
        "Linked_Bank_Accounts": master_owner_dossier.get("Linked_Bank_Accounts", []),
        "Active_Financial_Apps": master_owner_dossier.get("Active_Financial_Apps", []),
        "Security_Key_Handles": master_owner_dossier.get("Security_Key_Handles", []),
        "UPI_Circle_Delegations": master_owner_dossier.get("UPI_Circle_Delegations", []),
    }

    roles_list = roles_df.to_dict("records") if not roles_df.empty else []
    kind = "archive" if is_archive else ("folder" if os.path.isdir(abs_evidence) else "file")
    info_now = cfile.info()
    cfile.set_info(
        case_id=case_id,
        case_name=case_name,
        examiner_name=examiner_name,
        agency_name=agency_name,
        created_utc=info_now.get("created_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        last_opened_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f"),
    )
    model_txt = str(device_meta.get("model") or "")
    item_label = (label or "").strip() or (model_txt if model_txt and model_txt != "Not recorded" else os.path.basename(abs_evidence))
    cfile.upsert_item(
        item_id,
        label=item_label,
        source_path=abs_evidence,
        kind=kind,
        integrity_match=hashes.get("integrityMatch"),
        status="ingested",
        hashes=hashes,
        device=device_meta,
        processing_log=processing_log,
        dossier=serializable_dossier,
        record_counts=ingested,
        analysis={
            "mule_alerts": mule_alerts,
            "syndicate_roles": roles_list,
            "charge_sheet_chain": {
                "case_id": case_id,
                "evidence_hash_sha256": hashes.get("sha256"),
                "mule_alerts_count": len(mule_alerts),
                "syndicate_entities_count": len(roles_df) if not roles_df.empty else 0,
                "roles": roles_list,
                "alerts": mule_alerts,
            },
            "pyvis_html": pyvis_html,
        },
    )
    _case_state = _case_state_from_file(workspace_dir, cfile, item_id)
    _case_state["counts"] = counts

    _audit_event("evidence_ingested", {
        "evidence_item": item_id, "mode": mode,
        "evidence": os.path.basename(abs_evidence),
        "sha256_before": hashes.get("sha256"), "sha256_after": hashes.get("postIngestionSha256"),
        "integrity_match": hashes.get("integrityMatch"),
        "steps_failed": sum(1 for x in processing_log if x.get("status") == "FAILED"),
    })
    for action, payload in key_events:
        _audit_event(action, payload)
    prog.succeed(f"{item_id} ingested")
    return {
        "success": True,
        "case_id": case_id,
        "case_name": case_name,
        "workspace_dir": workspace_dir,
        "db_path": _active_store.db_path,
        "evidence_item": item_id,
        "evidence_items": _item_summaries(_case_state),
        "hashes": hashes,
        "integrity_match": hashes["integrityMatch"],
        "processing_log": processing_log,
        "failed_files": [e for e in processing_log if e["status"] == "FAILED"],
        "counts": counts,
        "owner_dossier": serializable_dossier,
        "device_metadata": device_meta,
    }


# ------------------------------------------------------------------------------
# REST API Endpoints
# ------------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "service": "Bharat-PA Forensics REST Engine",
        "status": "ONLINE",
        "documentation": "/docs",
        "case_loaded": _case_state["loaded"],
        "active_workspace": _active_store.case_workspace,
        "db_path": _active_store.db_path,
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "case_loaded": _case_state["loaded"],
        "database_exists": os.path.exists(_active_store.db_path),
        "database_size_bytes": os.path.getsize(_active_store.db_path) if os.path.exists(_active_store.db_path) else 0,
    }


@app.get("/api/case/state")
def get_case_state():
    """Returns current active case state. When no dump is loaded, returns loaded: false."""
    if not _case_state["loaded"]:
        return {
            "loaded": False,
            "case_name": None,
            "extractions": [],
            "counts": {},
            "owner_dossier": None,
        }
    return {
        "loaded": True,
        "case_id": _case_state["case_id"],
        "case_name": _case_state["case_name"],
        "evidence_path": _case_state["evidence_path"],
        "extractions": _case_state["extractions"],
        "counts": _active_store.get_project_tree_counts(),
        "owner_dossier": _case_state["owner_dossier"],
        "hashes": _case_state["hashes"],
        "evidence_items": _item_summaries(_case_state),
        "active_item": _case_state.get("active_item"),
    }


@app.get("/api/cases/recent")
def recent_cases():
    """Cases found in the cases folder, most recently opened first. Opening one needs no new processing."""
    return {"cases": list_cases(DEFAULT_WORKSPACE_ROOT)}


@app.get("/api/case/evidence-items")
def evidence_items():
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    return {"case_id": _case_state["case_id"], "active_item": _case_state.get("active_item"),
            "items": _item_summaries(_case_state)}


class ActiveItemRequest(BaseModel):
    item_id: str


@app.post("/api/case/active-item")
def select_active_item(req: ActiveItemRequest):
    """Which device the owner profile, link graph and alerts describe. Records of all devices stay in the case."""
    global _case_state
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    ws = _case_state.get("workspace_dir") or _active_store.case_workspace
    if not os.path.isfile(os.path.join(ws, CASE_FILE_NAME)):
        raise HTTPException(status_code=404, detail="This case has no case file.")
    cf = CaseFile(ws)
    if cf.get_item(req.item_id) is None:
        raise HTTPException(status_code=404, detail=f"No evidence item {req.item_id} in this case.")
    _case_state = _case_state_from_file(ws, cf, req.item_id)
    _audit_event("active_item_selected", {"evidence_item": req.item_id})
    return {"success": True, "active_item": req.item_id}


# ---------------------------------------------------------------------------
# Findings: records the examiner pinned, each with their own note. Stored beside the case database in a
# separate file so that re-ingesting the evidence does not erase them. A finding stores a pointer to the
# record (its source file, table, row, offset) and the examiner's words; the record itself stays in the case.
# ---------------------------------------------------------------------------
class FindingIn(BaseModel):
    kind: str
    record_id: str
    title: str
    note: str = ""
    source: Dict[str, Any] = {}


def _findings_db() -> sqlite3.Connection:
    path = os.path.join(os.path.dirname(os.path.abspath(_active_store.db_path)), "findings.sqlite")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, kind TEXT NOT NULL, record_id TEXT NOT NULL,"
        "title TEXT NOT NULL, note TEXT NOT NULL, source_json TEXT NOT NULL, pinned_at_utc TEXT NOT NULL,"
        "UNIQUE(case_id, kind, record_id))"
    )
    return conn


@app.get("/api/case/findings")
def list_findings():
    if not _case_state["loaded"]:
        return {"findings": []}
    conn = _findings_db()
    try:
        rows = conn.execute(
            "SELECT id, kind, record_id, title, note, source_json, pinned_at_utc FROM findings WHERE case_id=? ORDER BY id",
            (str(_case_state["case_id"]),),
        ).fetchall()
    finally:
        conn.close()
    return {"findings": [
        {"id": r[0], "kind": r[1], "record_id": r[2], "title": r[3], "note": r[4],
         "source": json.loads(r[5]), "pinned_at_utc": r[6]} for r in rows
    ]}


@app.post("/api/case/findings")
def pin_finding(body: FindingIn):
    if not _case_state["loaded"]:
        raise HTTPException(status_code=409, detail="No case is loaded.")
    if not body.record_id.strip() or not body.title.strip():
        raise HTTPException(status_code=422, detail="record_id and title are required.")
    conn = _findings_db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO findings(case_id, kind, record_id, title, note, source_json, pinned_at_utc) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(case_id, kind, record_id) DO UPDATE SET title=excluded.title, note=excluded.note, source_json=excluded.source_json",
                (str(_case_state["case_id"]), body.kind[:40], body.record_id[:200], body.title[:300], body.note[:4000],
                 json.dumps(body.source, sort_keys=True)[:20000], datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            )
    finally:
        conn.close()
    _audit_event("finding_pinned", {"kind": body.kind[:40], "record_id": body.record_id[:200]})
    return list_findings()


@app.delete("/api/case/findings/{finding_id}")
def unpin_finding(finding_id: int):
    if not _case_state["loaded"]:
        raise HTTPException(status_code=409, detail="No case is loaded.")
    conn = _findings_db()
    try:
        with conn:
            conn.execute("DELETE FROM findings WHERE id=? AND case_id=?", (finding_id, str(_case_state["case_id"])))
    finally:
        conn.close()
    _audit_event("finding_removed", {"finding_id": finding_id})
    return list_findings()


@app.get("/api/case/summary")
def get_case_summary():
    """Returns active case metadata, pre/post verification hashes, owner dossier, mule alerts, and category counts."""
    if not _case_state["loaded"]:
        return {
            "loaded": False,
            "case_name": None,
            "extractions": [],
            "counts": {},
            "owner_dossier": None,
            "device_metadata": None,
            "hashes": {},
            "mule_alerts": [],
            "syndicate_roles": [],
        }

    return {
        "loaded": True,
        "case_id": _case_state["case_id"],
        "case_name": _case_state["case_name"],
        "evidence_path": _case_state["evidence_path"],
        "examiner_name": _case_state.get("examiner_name", ""),
        "agency_name": _case_state.get("agency_name", ""),
        "hashes": _case_state["hashes"],
        "owner_dossier": _case_state["owner_dossier"],
        "device_metadata": _case_state["device_metadata"],
        "mule_alerts": _case_state["mule_alerts"],
        "syndicate_roles": _case_state["syndicate_roles"],
        "counts": _active_store.get_project_tree_counts(),
        "extractions": _case_state["extractions"],
        "evidence_items": _item_summaries(_case_state),
        "active_item": _case_state.get("active_item"),
    }


@app.post("/api/system/pick-evidence-file")
async def pick_evidence_file():
    """Opens native Windows File Explorer dialog using Tkinter on a worker thread."""
    loop = asyncio.get_running_loop()
    selected_path = await loop.run_in_executor(_thread_pool, _run_native_file_dialog)
    return {"selected_path": selected_path}


@app.post("/api/system/pick-evidence-folder")
async def pick_evidence_folder():
    """Opens native Windows Directory Explorer dialog using Tkinter on a worker thread."""
    loop = asyncio.get_running_loop()
    selected_path = await loop.run_in_executor(_thread_pool, _run_native_folder_dialog)
    return {"selected_path": selected_path}


@app.post("/api/case/ingest")
async def ingest_evidence_case(req: IngestCaseRequest):
    """
    Ingests forensic evidence container / folder:
    - Calculates pre-ingestion SHA-256 and MD5 in 8 MB chunks
    - Selectively unpacks target forensic DBs
    - Runs complete account profiling, corroboration, heuristic parsing, crypto bridging, and graph intelligence
    - Populates SQLite+FTS5 bharat_case_store.db
    """
    if _ingest_lock.locked():
        raise HTTPException(
            status_code=409,
            detail="Conflict: An ingestion pipeline is already actively executing. Concurrent ingestion is prohibited.",
        )

    if not req.evidence_path or not req.evidence_path.strip():
        raise HTTPException(status_code=400, detail="Evidence path is required")

    mode = "add" if (req.mode or "replace") == "add" else "replace"
    existing_info: Dict[str, str] = {}
    if mode == "add":
        if not req.case_id:
            raise HTTPException(status_code=400, detail="case_id is required to add evidence to an existing case.")
        ws_existing = os.path.join(DEFAULT_WORKSPACE_ROOT, safe_case_dir_name(req.case_id))
        if not os.path.isfile(os.path.join(ws_existing, CASE_FILE_NAME)):
            raise HTTPException(status_code=404, detail=f"No case {req.case_id} to add evidence to.")
        existing_info = CaseFile(ws_existing).info()
    case_id = req.case_id or f"CASE_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    case_name = req.case_name or existing_info.get("case_name") or os.path.splitext(os.path.basename(req.evidence_path))[0]
    examiner = req.examiner_name or existing_info.get("examiner_name") or ""
    agency = req.agency_name or existing_info.get("agency_name") or ""

    loop = asyncio.get_running_loop()
    try:
        async with _ingest_lock:
            result = await loop.run_in_executor(
                _thread_pool,
                _execute_ingestion_pipeline,
                req.evidence_path,
                case_id,
                case_name,
                examiner,
                agency,
                mode,
                req.label or "",
                req.keys or None,
            )
            return result
    except HTTPException as exc:
        _ingest_progress.fail(str(exc.detail))
        raise
    except Exception as e:
        _ingest_progress.fail(f"{type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@app.get("/api/case/ingest/progress")
def get_ingest_progress(since: int = Query(0, ge=0, description="Only events with a higher sequence number")):
    """What the ingest is doing now (or did last): the step, the work counted inside it, the events so far and the tail
    of the processing log. Poll this while ``POST /api/case/ingest`` is running."""
    return _ingest_progress.snapshot(since)


COVERAGE_SCOPE = (
    "Every file the tool opened for examination. For a folder or a single file that is every file. For a container "
    "(archive, backup, image) it is the entries the tool chose to extract (databases, key stores, device property files), "
    "plus any entry it failed to extract; other entries of the container are not listed."
)


@app.get("/api/case/coverage")
def case_coverage(evidence_item: Optional[str] = Query(None, description="Limit to one evidence item (device)")):
    """Parser transparency: which decoder produced the records, and which files were seen but not decoded, with the reason."""
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    rows = _active_store.get_coverage(evidence_item)
    by_outcome: Dict[str, int] = {}
    for r in rows:
        by_outcome[r["Outcome"]] = by_outcome.get(r["Outcome"], 0) + 1
    files = [{
        "evidence_item": r["Evidence_Item"], "file": r["File"], "size_bytes": r["Size_Bytes"], "kind": r["Kind"],
        "outcome": r["Outcome"], "reason": r["Reason"] or None, "decoded_by": r["Decoded_By"], "records": r["Records"],
    } for r in rows]
    return {
        "evidence_item": evidence_item,
        "scope": COVERAGE_SCOPE,
        "summary": {"files": len(rows), "by_outcome": by_outcome},
        "decoders": _active_store.decoder_summary(evidence_item),
        "files": files,
    }


@app.get("/api/case/search")
def case_search(
    q: str = Query(..., description="Search text"),
    mode: str = Query("keyword", description="keyword, phrase, contains (Unicode and Indic digits folded) or regex"),
    tables: Optional[str] = Query(None, description="Comma separated table names; default all"),
    evidence_item: Optional[str] = Query(None),
    application: Optional[str] = Query(None),
    tag: Optional[str] = Query(None, description="Only records carrying this tag"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Search all tables of the open case. Each hit names its table and id; fetch the whole record with /api/case/record."""
    from parsers.case_search import SearchError
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        return _active_store.search(
            q, mode=mode, tables=[t for t in (tables or "").split(",") if t.strip()] or None,
            evidence_item=evidence_item, application=application, tag=tag, limit=limit, offset=offset)
    except SearchError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/case/timeline")
def case_timeline(
    group: str = Query("fixed", description="fixed (placed by a recorded instant), clock_only (zone not recorded) or no_time"),
    tables: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None, alias="from", description="IST, 2026-02-01 or 2026-02-01 09:30:00"),
    to: Optional[str] = Query(None),
    evidence_item: Optional[str] = Query(None),
    application: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    bucket: Optional[str] = Query(None, description="day or hour: also return counts per bucket"),
    descending: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """One timeline over messages, payments, calls, locations, device traces, notifications and P2P orders."""
    from parsers.case_timeline import TimelineError
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        return _active_store.timeline(
            tables=[t for t in (tables or "").split(",") if t.strip()] or None, group=group, frm=date_from, to=to,
            evidence_item=evidence_item, application=application, tag=tag, bucket=bucket,
            limit=limit, offset=offset, descending=descending)
    except TimelineError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Tags (5B.6): the examiner's decisions about records, kept in the case file.
# ---------------------------------------------------------------------------
class TagRecordRef(BaseModel):
    table: str
    id: int


class TagRequest(BaseModel):
    tag: str
    records: List[TagRecordRef]
    note: str = ""


@app.get("/api/case/tags")
def case_tags_list(evidence_item: Optional[str] = Query(None)):
    """Every tag with how many records carry it (the built-in ones are always listed, even at 0)."""
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    return _active_store.list_tags(evidence_item)


@app.post("/api/case/tags")
def case_tags_apply(body: TagRequest):
    from parsers.case_tags import TagError
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        res = _active_store.tag_records(body.tag, [(r.table, r.id) for r in body.records], body.note)
    except TagError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if res["applied"]:
        _audit_event("records_tagged", {"tag": res["tag"], "count": res["applied"],
                                        "tables": sorted({r.table.lower() for r in body.records})})
    return res


@app.post("/api/case/tags/remove")
def case_tags_remove(body: TagRequest):
    from parsers.case_tags import TagError
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        res = _active_store.untag_records(body.tag, [(r.table, r.id) for r in body.records])
    except TagError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if res["removed"]:
        _audit_event("records_untagged", {"tag": res["tag"], "count": res["removed"]})
    return res


@app.get("/api/case/tags/records")
def case_tags_records(tag: str = Query(...), tables: Optional[str] = Query(None), evidence_item: Optional[str] = Query(None),
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    """The records carrying a tag, with the snapshot kept when they were tagged. Detached ones are flagged."""
    from parsers.case_tags import TagError
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        return _active_store.tagged_records(tag, tables=[t for t in (tables or "").split(",") if t.strip()] or None,
                                            evidence_item=evidence_item, limit=limit, offset=offset)
    except TagError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/case/record")
def case_record(table: str = Query(...), id: int = Query(..., ge=1)):
    """One record exactly as stored; values that were not recorded are null."""
    if not _case_state["loaded"]:
        raise HTTPException(status_code=412, detail="No case is loaded.")
    try:
        rec = _active_store.get_record(table, id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if rec is None:
        raise HTTPException(status_code=404, detail=f"No record {id} in {table}.")
    return {"table": table, "id": id, "record": rec}


@app.get("/api/case/tree-counts")
def get_tree_counts():
    """Returns live (Active / WAL+Carved) badge counts for the evidence tree."""
    if not _case_state["loaded"]:
        return {"success": True, "counts": {}}
    try:
        counts = _active_store.get_project_tree_counts()
        return {"success": True, "counts": counts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/artifacts/query")
def query_artifacts(
    category: str = Query(..., description="Artifact category: upi_transactions, chats, contacts, calls, locations, os_spillover, notifications, custodial_wallets, p2p_orders, fiat_crypto_bridge, crypto_addresses, vfs_files"),
    app_filter: Optional[str] = Query(None, description="App filter e.g. PhonePe, WhatsApp"),
    recovery_filter: Optional[str] = Query(None, description="Filter: ALL, ACTIVE, WAL, CARVED, SPILLOVER"),
    ephemeral_filter: Optional[str] = Query(None, description="Filter: VIEW_ONCE, DISAPPEARING, REVOKED, ATTACHMENTS"),
    search_query: Optional[str] = Query(None, description="Search term"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_col: Optional[str] = Query("id"),
    sort_asc: bool = Query(False),
    evidence_item: Optional[str] = Query(None),
):
    """Sub-10ms paginated query from SQLite+FTS5 case store."""
    category_map = {
        "upi_transactions": "transactions",
        "transactions": "transactions",
        "chats": "chats",
        "contacts": "contacts",
        "calls": "calls",
        "locations": "locations",
        "os_spillover": "os_spillover",
        "notifications": "notifications",
        "custodial_wallets": "custodial_wallets",
        "p2p_orders": "p2p_orders",
        "fiat_crypto_bridge": "fiat_crypto_bridge",
        "crypto_addresses": "crypto_addresses",
        "vfs_files": "vfs_files",
    }
    table_name = category_map.get(category.lower().strip(), category.lower().strip())

    # Sanitize Query parameters when invoked directly in tests
    clean_search = search_query if isinstance(search_query, str) else ""
    clean_sort_col = sort_col if isinstance(sort_col, str) else "id"
    clean_sort_asc = sort_asc if isinstance(sort_asc, bool) else False
    clean_limit = limit if isinstance(limit, int) else 100
    clean_offset = offset if isinstance(offset, int) else 0

    filters: Dict[str, Any] = {}
    if isinstance(app_filter, str) and app_filter != "ALL":
        filters["app_filter"] = app_filter
    if isinstance(recovery_filter, str) and recovery_filter != "ALL":
        filters["recovery_filter"] = recovery_filter
    if isinstance(ephemeral_filter, str) and ephemeral_filter != "ALL":
        filters["ephemeral_filter"] = ephemeral_filter
    if isinstance(evidence_item, str) and evidence_item:
        filters["evidence_item"] = evidence_item

    try:
        page_df, total = _active_store.get_paginated_rows(
            table_name=table_name,
            filters=filters,
            search_query=clean_search,
            sort_col=clean_sort_col,
            sort_asc=clean_sort_asc,
            limit=clean_limit,
            offset=clean_offset,
        )

        rows = page_df.to_dict("records") if not page_df.empty else []

        # Discover available apps for filtering
        apps_available: List[str] = []
        try:
            conn = _active_store._get_connection()
            cur = conn.cursor()
            cur.execute(f"PRAGMA table_info({table_name})")
            cols = [r["name"] for r in cur.fetchall()]
            if "Application" in cols:
                cur.execute(f"SELECT DISTINCT Application FROM {table_name} WHERE Application IS NOT NULL AND Application != ''")
                apps_available = [r["Application"] for r in cur.fetchall()]
            conn.close()
        except Exception:
            pass

        return {
            "success": True,
            "category": category,
            "table_name": table_name,
            "rows": rows,
            "total": total,
            "limit": clean_limit,
            "offset": clean_offset,
            "apps_available": apps_available,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/chats/thread")
def get_chat_thread_singular(
    app: Optional[str] = Query(None, description="App filter e.g. WhatsApp, Telegram"),
    thread_id: Optional[str] = Query(None, description="Specific thread ID for fetching message history"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Singular route alias for fetching conversation thread history."""
    return get_chat_threads(app=app, thread_id=thread_id, limit=limit, offset=offset)


@app.post("/api/chat-redline", response_model=ChatRedlineResponse)
def compute_chat_redline(req: ChatRedlineRequest):
    """
    Computes Myers Shortest-Edit-Script diff between original and edited/revoked messages.
    Returns visual HTML markup with <del> and <ins>, token classification, and financial token detection.
    """
    engine = MyersRedlineEngine()
    diff_result = engine.compute_redline(original_text=req.original_text, edited_text=req.edited_text)

    html_parts = []
    tokens_list = []
    for token in diff_result.tokens:
        tok_type_str = token.token_type.value if hasattr(token.token_type, "value") else str(token.token_type)
        tokens_list.append({"token_type": tok_type_str, "text": token.text})
        escaped = html.escape(token.text)
        if tok_type_str == "DELETE":
            if token.text.isspace():
                html_parts.append(escaped)
            else:
                html_parts.append(f"<del>{escaped}</del>")
        elif tok_type_str == "INSERT":
            if token.text.isspace():
                html_parts.append(escaped)
            else:
                html_parts.append(f"<ins>{escaped}</ins>")
        else:
            html_parts.append(escaped)

    rendered_html = "".join(html_parts)

    return ChatRedlineResponse(
        success=True,
        original_text=req.original_text,
        edited_text=req.edited_text,
        rendered_markup=rendered_html,
        tokens=tokens_list,
        has_financial_or_crypto_token=diff_result.has_financial_or_crypto_token,
    )


@app.post("/api/ocr/analyze")
def analyze_image_ocr(req: OcrAnalyzeRequest):
    """
    Performs bilingual Hindi + English OCR and extracts financial entities (VPA, UTR, PAN, IFSC, INR Amount).
    """
    abs_path = _resolve_case_file(req.image_path)

    with open(abs_path, "rb") as f:
        file_bytes = f.read()

    engine = BilingualOcrEngine()
    ocr_result = engine.extract_from_bytes(file_bytes)

    combined_text = f"{ocr_result.raw_bilingual_text} {ocr_result.normalized_ascii_text}"
    vpa_matches = re.findall(r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}", combined_text)
    unique_vpas = sorted(list(set(vpa_matches)))

    return {
        "success": True,
        "image_path": abs_path,
        "engine_used": ocr_result.engine_used,
        # False when Tesseract is not installed: the fallback only reads text embedded in the file (PNG text chunks,
        # etc.), it does not read the pixels. An empty result then means "not OCRed", not "no text".
        "ocr_performed": ocr_result.engine_used.startswith("TESSERACT"),
        "raw_text": ocr_result.raw_bilingual_text,
        "normalized_text": ocr_result.normalized_ascii_text,
        "detected_scripts": ocr_result.detected_scripts,
        "document_category": ocr_result.document_category,
        "extracted_utrs": ocr_result.extracted_utrs,
        "extracted_pans": ocr_result.extracted_pans,
        "extracted_ifscs": ocr_result.extracted_ifscs,
        "extracted_amounts_inr": ocr_result.extracted_amounts_inr,
        "vpas": unique_vpas,
        "confidence_score": ocr_result.confidence_score,
        # The score is fixed per matched rule (e.g. 0.95 when a PAN pattern is found). It is not the OCR
        # engine's recognition confidence and says nothing about how accurate the text is.
        "confidence_basis": "classification rule strength; not OCR recognition confidence",
    }


@app.get("/api/chats/threads")
def get_chat_threads(
    app: Optional[str] = Query(None, description="App filter e.g. WhatsApp, Telegram"),
    thread_id: Optional[str] = Query(None, description="Specific thread ID for fetching message history"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Returns conversation thread summaries or message history for a selected thread."""
    clean_limit = limit if isinstance(limit, int) else 50
    clean_offset = offset if isinstance(offset, int) else 0
    clean_app = app if isinstance(app, str) else None
    clean_thread_id = thread_id if isinstance(thread_id, str) else None

    try:
        if clean_thread_id:
            # Fetch messages belonging to this thread
            page_df, total = _active_store.get_paginated_rows(
                table_name="chats",
                filters={"thread_id": clean_thread_id},
                sort_col="id",
                sort_asc=True,
                limit=clean_limit,
                offset=clean_offset,
            )
            return {
                "success": True,
                "thread_id": clean_thread_id,
                "messages": page_df.to_dict("records") if not page_df.empty else [],
                "total": total,
            }

        # Otherwise return thread list summary
        summary_df = _active_store.get_chat_threads_summary(
            app_filter=clean_app,
            limit=clean_limit,
            offset=clean_offset,
        )

        threads: List[Dict[str, Any]] = []
        if not summary_df.empty:
            for r in summary_df.to_dict("records"):
                threads.append({
                    "Application": r.get("Application", "Unknown"),
                    "Thread_ID": r.get("Thread_ID", ""),
                    "Contact_Thread": r.get("Thread_Title", r.get("Thread_ID", "")),
                    "Chat_Type": r.get("Chat_Type", "DIRECT"),
                    "Message_Count": r.get("Total_Messages", 0),
                    "Deleted_Count": r.get("Deleted_Carved_Count", 0),
                    "Last_Timestamp": r.get("Last_Timestamp_IST", ""),
                    "Participant_Identifier": r.get("Participant_Identifier", ""),
                })

        return {"success": True, "threads": threads, "count": len(threads)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/fusion/bank-statement")
def fuse_bank_statement(req: FusionBankRequest):
    """Parses external bank statement CSV/XLSX and reconciles against active case UPI/banking ledger."""
    try:
        if req.statement_path and os.path.exists(req.statement_path):
            bank_df = parse_bank_statement(req.statement_path, filename=os.path.basename(req.statement_path))
        elif req.csv_content:
            bank_df = parse_bank_statement(req.csv_content.encode("utf-8"), filename=req.filename or "statement.csv")
        else:
            raise HTTPException(status_code=400, detail="Must provide statement_path or csv_content")

        if bank_df.empty:
            return {"success": False, "message": "Failed to parse bank statement rows", "matched_count": 0}

        # Fetch current transactions from case store
        conn = _active_store._get_connection()
        device_tx_df = pd.read_sql_query("SELECT * FROM transactions", conn)
        conn.close()

        reconciliation_df = reconcile_bank_statement_with_device(bank_df, device_tx_df)

        matched_count = len(reconciliation_df[reconciliation_df["Reconciliation_Status"] == "MATCHED_REFERENCE"]) if "Reconciliation_Status" in reconciliation_df.columns else 0
        unmatched_bank = len(reconciliation_df[reconciliation_df["Reconciliation_Status"] == "NOT_FOUND_ON_PHONE"]) if "Reconciliation_Status" in reconciliation_df.columns else 0

        return {
            "success": True,
            "bank_records_count": len(bank_df),
            "matched_count": matched_count,
            "unmatched_bank_count": unmatched_bank,
            "probable_count": int((reconciliation_df["Reconciliation_Status"] == "PROBABLE_AMOUNT_DATE").sum()) if "Reconciliation_Status" in reconciliation_df.columns else 0,
            "reconciliation_rows": reconciliation_df.to_dict("records")[:200],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/fusion/cdr")
def fuse_cdr_record(req: FusionCdrRequest):
    """Parses telecom CDR (Call Detail Record) CSV and correlates with financial/VoIP timestamps."""
    try:
        if req.cdr_path and os.path.exists(req.cdr_path):
            cdr_df = parse_cdr_record(req.cdr_path, filename=os.path.basename(req.cdr_path))
        elif req.csv_content:
            cdr_df = parse_cdr_record(req.csv_content.encode("utf-8"), filename=req.filename or "cdr.csv")
        else:
            raise HTTPException(status_code=400, detail="Must provide cdr_path or csv_content")

        if cdr_df.empty:
            return {"success": False, "message": "Failed to parse CDR records", "correlated_count": 0}

        conn = _active_store._get_connection()
        device_tx_df = pd.read_sql_query("SELECT * FROM transactions", conn)
        conn.close()

        correlated_df = correlate_cdr_with_transactions(cdr_df, device_tx_df, window_minutes=15)

        return {
            "success": True,
            "cdr_count": len(cdr_df),
            "correlated_transactions_count": len(correlated_df),
            "correlation_rows": correlated_df.to_dict("records")[:200],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/network-html")
def get_graph_network_html():
    """Returns standalone interactive PyVis network graph HTML."""
    html_content = _case_state.get("pyvis_html")
    if not html_content:
        html_content = """
        <html>
        <body style="background:#0b1320;color:#9ca3af;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;">
            <div style="text-align:center;">
                <h3>No Evidence Ingested</h3>
                <p>Ingest an evidence container to view interactive syndicate transaction graph.</p>
            </div>
        </body>
        </html>
        """
    return Response(content=html_content, media_type="text/html")


@app.get("/api/graph/charge-sheet-chain")
def get_charge_sheet_chain():
    """Returns structured forensic evidence chain for court chargesheets under Indian law."""
    return {
        "success": True,
        "chain": _case_state.get("charge_sheet_chain", {}),
        "mule_alerts": _case_state.get("mule_alerts", []),
        "syndicate_roles": _case_state.get("syndicate_roles", []),
    }


@app.get("/api/graph/mule-network")
def get_graph_mule_network():
    """
    Returns structured JSON topology of the money laundering / mule network,
    including nodes, edges, mule alerts, syndicate roles, and 5-stage Sankey coordinates.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    transactions_df = pd.DataFrame()
    if _case_state["loaded"] and _active_store is not None:
        try:
            conn = _active_store._get_connection()
            transactions_df = pd.read_sql_query("SELECT * FROM transactions", conn)
            conn.close()
        except Exception:
            transactions_df = pd.DataFrame()

    if not transactions_df.empty:
        g = build_transaction_graph(transactions_df)
        for node_id, data in g.nodes(data=True):
            in_edges = g.in_edges(node_id, data=True)
            out_edges = g.out_edges(node_id, data=True)
            total_in = sum(float(d.get("amount", 0.0)) for _, _, d in in_edges)
            total_out = sum(float(d.get("amount", 0.0)) for _, _, d in out_edges)
            nodes.append({
                "id": str(node_id),
                "entity": str(node_id),
                "type": data.get("type", "External"),
                "inflow": total_in,
                "outflow": total_out,
                "apps_used": data.get("apps_used", []),
                "role": "Pass-through lead (in > Rs 50,000 and out > Rs 40,000)" if total_in > 50000 and total_out > 40000 else "Unclassified",
            })
        for u, v, data in g.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "amount": float(data.get("amount", 0.0)),
                "app": data.get("app", "UPI"),
                "flow": data.get("flow", "TRANSFER"),
                "timestamp": data.get("timestamp", ""),
                "txid": data.get("txid", ""),
            })

    sankey_nodes: List[SankeyNode] = []
    sankey_flows: List[SankeyFlowRibbon] = []
    if edges:
        # Stage = hop distance from sources (nodes with no inflow), capped at the 5 columns.
        incoming = {n["id"] for n in nodes if n["inflow"] > 0}
        depth: Dict[str, int] = {n["id"]: 0 for n in nodes if n["id"] not in incoming}
        if not depth:
            depth = {nodes[0]["id"]: 0}
        changed = True
        guard = 0
        while changed and guard < 50:
            changed = False
            guard += 1
            for e in edges:
                if e["source"] in depth and e["target"] not in depth:
                    depth[e["target"]] = min(4, depth[e["source"]] + 1)
                    changed = True
        stage_cols = SankeyLaunderingCanvas.STAGE_ORDER
        for n in nodes:
            sankey_nodes.append(SankeyNode(
                node_id=n["id"], stage=stage_cols[depth.get(n["id"], 0)], label=n["id"],
            ))
        pair_amounts: Dict[Tuple[str, str], float] = {}
        for e in edges:
            pair_amounts[(e["source"], e["target"])] = pair_amounts.get((e["source"], e["target"]), 0.0) + e["amount"]
        sankey_flows = [
            SankeyFlowRibbon(source_node_id=u, target_node_id=v, amount_inr=amt)
            for (u, v), amt in pair_amounts.items()
        ]
    canvas = SankeyLaunderingCanvas()
    layout_res = canvas.compute_layout(sankey_nodes, sankey_flows)
    _case_state["_last_sankey_layout"] = layout_res

    serialized_stages = {}
    for st, snodes in layout_res.stages.items():
        serialized_stages[st.value] = [
            {"node_id": sn.node_id, "label": sn.label, "x": sn.x, "y": sn.y, "height": sn.height}
            for sn in snodes
        ]
    serialized_ribbons = [
        {
            "source": r.source_node_id,
            "target": r.target_node_id,
            "amount_inr": r.amount_inr,
            "thickness_px": r.thickness_px,
            "path": r.rendered_svg_path,
        }
        for r in layout_res.ribbons
    ]
    serialized_fans = [
        {
            "target": f.target_node_id,
            "count": f.transfer_count,
            "total_inr": f.total_amount_inr,
            "badge": f.rendered_badge_text,
        }
        for f in layout_res.smurfing_fans
    ]

    return {
        "success": True,
        "empty": not nodes,
        "message": "" if nodes else "No successful, directed transactions in this case to graph.",
        "nodes": nodes,
        "edges": edges,
        "mule_alerts": _case_state.get("mule_alerts", []),
        "syndicate_roles": _case_state.get("syndicate_roles", []),
        "sankey_layout": {
            "stages": serialized_stages,
            "ribbons": serialized_ribbons,
            "smurfing_fans": serialized_fans,
        },
    }


@app.get("/api/graph/sankey-svg")
def get_graph_sankey_svg():
    """Returns an SVG money trail built from the loaded case's transactions (empty-state SVG if none)."""
    get_graph_mule_network()  # refreshes the layout from the case store
    layout = _case_state.get("_last_sankey_layout")
    svg_markup = render_layout_svg(layout) if layout is not None else render_layout_svg(
        SankeyLaunderingCanvas().compute_layout([], [])
    )
    return Response(content=svg_markup, media_type="image/svg+xml")


@app.post("/api/sqlite/inspect")
def inspect_sqlite_db(req: SqliteInspectRequest):
    """Inspects any SQLite database from the case or disk, returns tables, schema, rows, and KV pairs."""
    try:
        from parsers.deep_sqlite import dump_sqlite_tables, extract_kv_pairs
        target_path = _resolve_case_file(req.db_path, for_sqlite=True)

        table_dfs = dump_sqlite_tables(target_path, max_rows_per_table=req.limit)
        tables_meta = []
        for tname, df in table_dfs.items():
            tables_meta.append({
                "table_name": tname,
                "row_count": len(df),
                "columns": list(df.columns),
            })

        selected_table = req.table_name or (tables_meta[0]["table_name"] if tables_meta else None)
        selected_rows = []
        kv_pairs = []
        if selected_table and selected_table in table_dfs:
            target_df = table_dfs[selected_table]
            selected_rows = target_df.to_dict("records")
            kv_df = extract_kv_pairs(target_df)
            if not kv_df.empty:
                kv_pairs = kv_df.to_dict("records")

        return {
            "success": True,
            "db_path": target_path,
            "tables": tables_meta,
            "selected_table": selected_table,
            "rows": selected_rows,
            "kv_pairs": kv_pairs,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "tables": [], "rows": []}


@app.get("/api/inspector/hex")
def get_inspector_hex(
    file_path: str = Query(..., description="File path"),
    offset: int = Query(0, ge=0, description="Byte offset"),
    window_size: int = Query(4096, ge=128, le=65536, description="Window size in bytes"),
):
    """Reads 4KB byte window centered on offset, computes SHA-256 hash, and formats hex lines."""
    clean_path = file_path if isinstance(file_path, str) else ""
    clean_offset = offset if isinstance(offset, int) else 0
    clean_window = window_size if isinstance(window_size, int) else 4096

    if _active_store is None:
        raise HTTPException(status_code=412, detail="Precondition Failed: No forensic case is currently loaded.")
    clean_path = _resolve_case_file(clean_path)

    try:
        hex_data = _active_store.read_provenance_hex_window(
            file_path=clean_path,
            byte_offset=clean_offset,
            window_size=clean_window,
        )
        if hex_data.get("error"):
            raise HTTPException(status_code=404, detail=hex_data["error"])
        raw_hex = hex_data.get("raw_hex", "")
        raw_bytes = bytes.fromhex(raw_hex) if raw_hex else b""
        chunk_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        return {
            "success": True,
            "file_path": hex_data.get("file_path", clean_path),
            "target_offset": hex_data.get("target_offset", clean_offset),
            "target_length": hex_data.get("target_length", 64),
            "start_offset": hex_data.get("start_offset", clean_offset),
            "window_bytes": hex_data.get("window_bytes", len(raw_bytes)),
            "sha256": chunk_sha256,
            "hex_lines": hex_data.get("hex_lines", []),
            "raw_hex": raw_hex,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ReportParticulars(BaseModel):
    case_number: Optional[str] = ""
    agency: Optional[str] = ""
    examiner_name: Optional[str] = ""
    designation: Optional[str] = ""
    requesting_officer: Optional[str] = ""
    notes: Optional[str] = ""


_TX_DIRECTION = {"DEBIT": "OUTGOING", "CREDIT": "INCOMING"}


def _stamp_transaction_evidence(fr: pd.DataFrame, vfs_path: str) -> None:
    """X-13: give each transaction its provenance line and direction at ingest.

    Forensic_Provenance lists every source row that contributed (file :: table :: RowID :: State).
    Direction follows the recorded Type; a TRANSFER has no established direction, so it stays empty.
    """
    if "Source_Rows" in fr.columns:
        fr["Forensic_Provenance"] = fr["Source_Rows"].map(lambda v: compose_tx_provenance(vfs_path, v))
    else:
        fr["Forensic_Provenance"] = None
    if "Type" in fr.columns:
        fr["Direction"] = fr["Type"].map(lambda t: _TX_DIRECTION.get(str(t).strip().upper()))
    else:
        fr["Direction"] = None
    # Source_Rows is folded into Forensic_Provenance; the store has no column for it.
    if "Source_Rows" in fr.columns:
        del fr["Source_Rows"]


def _require_case() -> None:
    if not _case_state.get("loaded"):
        raise HTTPException(status_code=412, detail="Open evidence first. A report is built only from a loaded case.")


def _report_facts(particulars: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    _require_case()
    parts = dict(particulars or {})
    # Fall back to what was entered when the evidence was opened; never to a placeholder.
    if not parts.get("examiner_name"):
        parts["examiner_name"] = _case_state.get("examiner_name") or ""
    if not parts.get("agency"):
        parts["agency"] = _case_state.get("agency_name") or ""
    findings = list_findings()["findings"]
    from parsers import case_tag_report
    conn = _active_store._get_connection()
    try:
        tag_data = case_tag_report.tag_facts(conn)
    finally:
        conn.close()
    return examination_report.build_facts(
        _case_state, _active_store.get_project_tree_counts(), findings, _audit_summary(), parts, _tool_environment(), tag_data
    )


_NO_STORE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


@app.post("/api/report/examination")
def examination_report_post(req: ReportParticulars):
    """Examination report (HTML): recorded facts, limitations, pinned findings and the audit log. No legal wording."""
    _require_case()
    # Record the generation first, then render, so the audit section lists it.
    _audit_event("report_generated", {"kind": "examination_report"})
    facts = _report_facts(req.model_dump(exclude_none=True))
    return Response(
        content=examination_report.render_report_html(facts), media_type="text/html; charset=utf-8",
        headers={**_NO_STORE, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline';",
                 "Content-Disposition": 'inline; filename="examination_report.html"'},
    )


@app.get("/api/report/facts")
def report_facts(format: str = Query("json", pattern="^(json|csv)$")):
    """The facts annexure as JSON or CSV, for copying into the lab's own forms."""
    _require_case()
    _audit_event("report_generated", {"kind": "facts_annexure", "format": format})
    facts = _report_facts(None)
    if format == "csv":
        return Response(content=examination_report.render_facts_csv(facts), media_type="text/csv; charset=utf-8",
                        headers={**_NO_STORE, "Content-Disposition": 'attachment; filename="case_facts.csv"'})
    return Response(content=examination_report.render_facts_json(facts), media_type="application/json",
                    headers={**_NO_STORE, "Content-Disposition": 'attachment; filename="case_facts.json"'})


@app.get("/api/report/accounts-of-interest")
def accounts_of_interest(format: str = Query("json", pattern="^(json|csv)$")):
    """Accounts from payment records the examiner tagged; accounts shared with complainant/excluded/privileged records are listed apart."""
    from parsers import case_tag_report
    _require_case()
    conn = _active_store._get_connection()
    try:
        data = case_tag_report.accounts_of_interest(conn)
    finally:
        conn.close()
    _audit_event("report_generated", {"kind": "accounts_of_interest", "format": format, "listed": len(data["accounts"]), "left_out": len(data["left_out"])})
    if format == "csv":
        return Response(content=case_tag_report.accounts_csv(data), media_type="text/csv; charset=utf-8",
                        headers={**_NO_STORE, "Content-Disposition": 'attachment; filename="accounts_of_interest.csv"'})
    return data


@app.get("/api/audit")
def get_audit_log():
    if not _case_state.get("loaded"):
        raise HTTPException(status_code=412, detail="No case is loaded.")
    return _audit_summary()


class PackageItemIn(BaseModel):
    path: str
    disposition: Optional[str] = None   # INCLUDE or a WITHHOLD_* reason; there is no default
    note: Optional[str] = ""


class PackageRequest(BaseModel):
    items: List[PackageItemIn] = []
    mask_terms: List[str] = []          # e.g. a person's name, removed from names, notes and cards
    acknowledge_tagged: bool = False    # go ahead although an INCLUDE file holds records tagged privileged / complainant / excluded


@app.post("/api/report/package")
def build_review_package(req: PackageRequest):
    """Portable review package. Fails closed: every item needs a decision or nothing is written."""
    _require_case()
    items = []
    for it in req.items:
        items.append(review_package.PackageItem(
            source_path=_resolve_case_file(it.path), disposition=it.disposition, note=it.note or ""))
    from parsers import case_tag_report
    conn = _active_store._get_connection()
    try:
        flags = case_tag_report.files_with_keep_out_records(conn, [i.source_path for i in items])
    finally:
        conn.close()
    for i in items:
        i.tag_flags = flags.get(i.source_path)
    case_id = str(_case_state.get("case_id"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(_active_store.case_workspace, "review_packages",
                           re.sub(r"[^A-Za-z0-9._-]", "_", case_id)[:60] + "_" + stamp)
    led, _err = _get_audit()
    try:
        res = review_package.build_package(case_id, items, out_dir, req.mask_terms,
                                           audit_head=led.head_hash if led else "", acknowledge_tagged=req.acknowledge_tagged)
    except review_package.PackageRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _audit_event("package_built", {"included": res.included, "withheld": res.withheld, "merkle_root": res.merkle_root,
                                   "tag_warning_acknowledged": bool(req.acknowledge_tagged and any(i.tag_flags and i.disposition == "INCLUDE" for i in items))})
    return {"success": True, "directory": res.directory, "viewer_path": res.viewer_path,
            "included": res.included, "withheld": res.withheld, "merkle_root": res.merkle_root}


_MEDIA_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".heic", ".bmp", ".mp4", ".mov", ".3gp", ".avi", ".mkv")


@app.get("/api/case/media-candidates")
def get_media_candidates(limit: int = Query(500, ge=1, le=5000)):
    """Media files of the loaded case that exist on disk and can be packaged (empty list if none)."""
    if not _case_state.get("loaded"):
        return {"success": True, "items": [], "message": "No case loaded."}
    conn = _active_store._get_connection()
    try:
        rows = conn.execute(
            "SELECT vfs_path, file_name, file_size, local_disk_path FROM vfs_files "
            "WHERE is_materialized = 1 AND local_disk_path <> '' ORDER BY vfs_path LIMIT ?", (limit * 4,)
        ).fetchall()
    finally:
        conn.close()
    items = [
        {
            "path": r["local_disk_path"],
            "vfs_path": r["vfs_path"],
            "file_name": r["file_name"],
            "file_size": r["file_size"],
        }
        for r in rows
        if str(r["file_name"]).lower().endswith(_MEDIA_EXTS) and os.path.isfile(r["local_disk_path"])
    ][:limit]
    return {"success": True, "items": items}


def _detect_os_type(files: List[str]) -> str:
    """'ios', 'android' or 'unknown', from the layout of the extraction (not assumed)."""
    norm = [f.replace(chr(92), "/").lower() for f in files]
    ios = any(
        n.endswith(("/manifest.db", "/info.plist", "/chatstorage.sqlite")) or "/private/var/" in n
        or "/library/sms/sms.db" in n
        for n in norm
    )
    android = any(
        n.endswith("/build.prop") or "/data/data/" in n or "/com.whatsapp/" in n or "/shared_prefs/" in n
        for n in norm
    )
    if ios and not android:
        return "ios"
    if android and not ios:
        return "android"
    return "unknown"


# ------------------------------------------------------------------------------
# Preserved Endpoints for Backward Compatibility
# ------------------------------------------------------------------------------

class CaseOpenResponse(BaseModel):
    success: bool
    workspace: str
    db_path: str
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    case_loaded: bool
    records_count: int


@app.post("/api/case/open", response_model=CaseOpenResponse)
async def open_case_workspace(req: CaseOpenRequest):
    global _active_store, _case_state

    if _ingest_lock.locked():
        raise HTTPException(
            status_code=409,
            detail="Cannot switch workspace while an ingestion pipeline is actively executing.",
        )

    # 1. Path canonicalization and directory validation
    ws = os.path.abspath(req.workspace_dir)
    if not os.path.isdir(ws):
        raise HTTPException(
            status_code=404,
            detail=f"Specified workspace directory does not exist: {ws}",
        )

    # 2. Strict db_name sanitization (prohibit path traversal)
    clean_db_name = os.path.basename(req.db_name or "bharat_case_store.db")
    if not clean_db_name.endswith((".db", ".sqlite", ".sqlite3")):
        raise HTTPException(
            status_code=400,
            detail="Invalid database file format. Must end with .db, .sqlite, or .sqlite3",
        )
    target_db_path = os.path.join(ws, clean_db_name)
    if not os.path.isfile(target_db_path):
        raise HTTPException(
            status_code=404,
            detail=f"Database file not found in workspace: {target_db_path}",
        )

    async with _ingest_lock:
        # Offload store initialization and schema validation to threadpool
        def _rebind_store() -> Tuple[CaseUIPaginatorStore, Dict[str, Any], int]:
            new_store = CaseUIPaginatorStore(case_workspace=ws, db_name=clean_db_name)
            conn = new_store._get_connection()
            try:
                cur = conn.cursor()
                # Inspect for metadata table if existing
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='case_metadata'")
                has_meta = cur.fetchone() is not None
                meta_dict: Dict[str, Any] = {}
                if has_meta:
                    cur.execute("SELECT key, value FROM case_metadata")
                    meta_dict = {row["key"]: row["value"] for row in cur.fetchall()}

                # Count total records across primary categories
                total_records = 0
                for table in ["transactions", "chats", "contacts", "calls", "locations"]:
                    cur.execute(f"SELECT COUNT(*) as c FROM sqlite_master WHERE type='table' AND name=?", (table,))
                    if cur.fetchone()["c"] > 0:
                        cur.execute(f"SELECT COUNT(*) as c FROM {table}")
                        total_records += cur.fetchone()["c"]
                return new_store, meta_dict, total_records
            finally:
                conn.close()

        loop = asyncio.get_running_loop()
        new_store, meta, total_recs = await loop.run_in_executor(_thread_pool, _rebind_store)

        _active_store = new_store

        # A case written by 5B.2 or later has a case file: everything is restored from it, nothing is processed again.
        if os.path.isfile(os.path.join(ws, CASE_FILE_NAME)):
            cf_open = CaseFile(ws)
            cf_open.touch_opened()
            _case_state = _case_state_from_file(ws, cf_open)
            _case_state["counts"] = _active_store.get_project_tree_counts()
        else:
            # Older workspace: only what its store and its metadata table hold.
            recovered_case_id = meta.get("case_id") or os.path.basename(ws)
            recovered_case_name = meta.get("case_name") or f"Case Workspace: {recovered_case_id}"
            evidence_path = meta.get("evidence_path") or ws

            _case_state = {
                "loaded": True,
                "case_id": recovered_case_id,
                "case_name": recovered_case_name,
                "evidence_path": evidence_path,
                "examiner_name": meta.get("examiner_name", ""),
                "agency_name": meta.get("agency_name", ""),
                "extractions": [{"evidenceId": recovered_case_id, "sourcePath": evidence_path}],
                "counts": _active_store.get_project_tree_counts(),
                "owner_dossier": json.loads(meta.get("owner_dossier", "{}")),
                "device_metadata": json.loads(meta.get("device_metadata", "{}")),
                "hashes": json.loads(meta.get("hashes", "{}")),
                "mule_alerts": json.loads(meta.get("mule_alerts", "[]")),
                "syndicate_roles": json.loads(meta.get("syndicate_roles", "[]")),
                "charge_sheet_chain": json.loads(meta.get("charge_sheet_chain", "{}")),
                "pyvis_html": meta.get("pyvis_html"),
                "workspace_dir": ws,
            }

    _audit_event("case_opened", {"workspace": os.path.basename(str(ws))})
    return CaseOpenResponse(
        success=True,
        workspace=_active_store.case_workspace,
        db_path=_active_store.db_path,
        case_id=_case_state["case_id"],
        case_name=_case_state["case_name"],
        case_loaded=True,
        records_count=total_recs,
    )


class ArtifactCategoryEnum(str, Enum):
    UPI_TRANSACTIONS = "upi_transactions"
    TRANSACTIONS = "transactions"
    CHATS = "chats"
    CONTACTS = "contacts"
    CALLS = "calls"
    LOCATIONS = "locations"
    OS_SPILLOVER = "os_spillover"
    NOTIFICATIONS = "notifications"
    CUSTODIAL_WALLETS = "custodial_wallets"
    P2P_ORDERS = "p2p_orders"
    FIAT_CRYPTO_BRIDGE = "fiat_crypto_bridge"
    CRYPTO_ADDRESSES = "crypto_addresses"
    VFS_FILES = "vfs_files"


class PaginatedRecordsResponse(BaseModel):
    success: bool
    category: str
    table_name: str
    rows: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    page: int
    total_pages: int
    apps_available: List[str]


@app.get("/api/case/records", response_model=PaginatedRecordsResponse)
async def get_paginated_records(
    category: ArtifactCategoryEnum = Query(..., description="Target artifact category"),
    page: int = Query(1, ge=1, le=100000, description="1-indexed page number"),
    page_size: int = Query(100, ge=1, le=1000, description="Records per page"),
    search: Optional[str] = Query(None, description="FTS5 search query term"),
    recovery_filter: Optional[str] = Query(None, description="Filter: ALL, ACTIVE, WAL, CARVED, SPILLOVER"),
    ephemeral_filter: Optional[str] = Query(None, description="Filter: VIEW_ONCE, DISAPPEARING, REVOKED, ATTACHMENTS"),
    app: Optional[str] = Query(None, description="App filter"),
    evidence_item: Optional[str] = Query(None, description="Only records from this evidence item (device)"),
):
    """Legacy paginated endpoint with strict pagination constraints and case validation."""
    if not _case_state["loaded"]:
        raise HTTPException(
            status_code=412,
            detail="Precondition Failed: No case is currently loaded. Ingest evidence or open a case workspace first.",
        )

    offset = (page - 1) * page_size
    loop = asyncio.get_running_loop()

    # Offload the synchronous query_artifacts execution to the threadpool
    result = await loop.run_in_executor(
        _thread_pool,
        lambda: query_artifacts(
            category=category.value,
            app_filter=app,
            recovery_filter=recovery_filter,
            ephemeral_filter=ephemeral_filter,
            search_query=search,
            limit=page_size,
            offset=offset,
            evidence_item=evidence_item,
        )
    )

    total_count = result.get("total", 0)
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1

    return PaginatedRecordsResponse(
        success=True,
        category=result["category"],
        table_name=result["table_name"],
        rows=result["rows"],
        total=total_count,
        limit=result["limit"],
        offset=result["offset"],
        page=page,
        total_pages=total_pages,
        apps_available=result.get("apps_available", []),
    )


class HexInspectorResponse(BaseModel):
    success: bool
    file_path: str
    file_size: int = 0
    offset: int = 0
    window_size: int = 4096
    hex_dump: str = ""
    ascii_dump: str = ""
    is_eof: bool = False
    target_offset: Optional[int] = None
    target_length: Optional[int] = None
    start_offset: Optional[int] = None
    window_bytes: Optional[int] = None
    sha256: Optional[str] = None
    hex_lines: Optional[List[Dict[str, Any]]] = None
    raw_hex: Optional[str] = None


@app.get("/api/case/hex-window", response_model=HexInspectorResponse)
async def get_hex_window(
    file_path: str = Query(..., description="Relative path within workspace or evidence"),
    offset: int = Query(..., ge=0, description="Target byte offset"),
    window_size: int = Query(4096, ge=256, le=65536, description="Byte window size"),
    evidence_item: Optional[str] = Query(None, description="Evidence item (device) the path belongs to"),
):
    """Legacy hex window endpoint with boundary validation and threadpool execution."""
    if not _case_state["loaded"]:
        raise HTTPException(
            status_code=412,
            detail="Precondition Failed: No forensic case is currently loaded.",
        )

    # Resolve and sandbox file path (same rules as every other endpoint: case workspace or evidence source only)
    abs_target = _resolve_case_file(file_path, evidence_item=evidence_item if isinstance(evidence_item, str) else None)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        _thread_pool,
        lambda: get_inspector_hex(file_path=abs_target, offset=offset, window_size=window_size)
    )
    file_sz = os.path.getsize(abs_target) if os.path.isfile(abs_target) else 0
    raw_hex = result.get("raw_hex", "")
    raw_bytes = bytes.fromhex(raw_hex) if raw_hex else b""
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
    result.update({
        "file_size": file_sz,
        "offset": offset,
        "window_size": window_size,
        "hex_dump": raw_hex,
        "ascii_dump": ascii_str,
        "is_eof": (offset + len(raw_bytes)) >= file_sz,
    })
    return HexInspectorResponse(**result)


class BenchmarkResponse(BaseModel):
    success: bool
    dump_path: str
    output_dir: str
    ledger_path: str
    report_path: str
    duration_seconds: float
    executive_summary: Dict[str, Any]
    vendor_differential: Dict[str, Any]


@app.post("/api/benchmark/run", response_model=BenchmarkResponse)
async def run_benchmark(req: BenchmarkRequest):
    """Executes the 5-Stage Forensic Benchmark Pipeline under strict concurrency lock and threadpool.

    Developer tool: disabled unless BHARAT_ENABLE_BENCHMARK=1, so a production build exposes no
    endpoint that ingests an arbitrary path and writes reports elsewhere.
    """
    if os.environ.get("BHARAT_ENABLE_BENCHMARK") != "1":
        raise HTTPException(status_code=404, detail="Benchmark endpoint is disabled in this build.")
    if _benchmark_lock.locked():
        raise HTTPException(
            status_code=409,
            detail="Conflict: A forensic benchmark pipeline is already running. Please await its completion.",
        )

    # 1. Path sanitization
    abs_dump = os.path.abspath(req.dump_path)
    if not os.path.exists(abs_dump):
        raise HTTPException(status_code=404, detail=f"Dump path not found: {abs_dump}")

    if req.output_dir:
        abs_out = os.path.abspath(req.output_dir)
        # Sandbox output_dir to prevent arbitrary overwrites of system folders
        if not (_is_within(abs_out, DEFAULT_WORKSPACE_ROOT) or _is_within(abs_out, tempfile.gettempdir())):
            raise HTTPException(
                status_code=403,
                detail=f"Output directory must reside within workspace root ({DEFAULT_WORKSPACE_ROOT}) or system temp.",
            )
    else:
        abs_out = os.path.join(tempfile.gettempdir(), f"bharat_pa_benchmark_{int(datetime.now(timezone.utc).timestamp())}")

    os.makedirs(abs_out, exist_ok=True)

    async with _benchmark_lock:
        start_ts = datetime.now(timezone.utc).timestamp()

        def _execute_benchmark() -> Dict[str, Any]:
            recorder = ForensicBenchmarkRecorder(
                dump_path=abs_dump,
                output_dir=abs_out,
                verbose=bool(req.verbose),
            )
            return recorder.run_full_pipeline()

        loop = asyncio.get_running_loop()
        try:
            telemetry = await loop.run_in_executor(_thread_pool, _execute_benchmark)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Benchmark pipeline failed during execution: {type(e).__name__}: {str(e)}",
            )

        elapsed = round(datetime.now(timezone.utc).timestamp() - start_ts, 2)
        exec_summary = telemetry.get("stage5_executive_summary")
        if not exec_summary:
            raise HTTPException(
                status_code=502,
                detail="Benchmark executed but failed to generate stage 5 executive summary telemetry.",
            )

        return BenchmarkResponse(
            success=True,
            dump_path=abs_dump,
            output_dir=abs_out,
            ledger_path=os.path.join(abs_out, "benchmark_telemetry_ledger.json"),
            report_path=os.path.join(abs_out, "COVERAGE_COMPARISON_REPORT.md"),
            duration_seconds=elapsed,
            executive_summary=exec_summary,
            vendor_differential=telemetry.get("stage4_vendor_differential", {}),
        )


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))

    if host == "0.0.0.0":
        print("[!] SECURITY WARNING: Binding Bharat-PA Forensics API to 0.0.0.0 exposes forensic evidence and workstation files without network authentication.")
        print("[!] Ensure this instance is behind an authenticated reverse proxy or an isolated forensic VLAN.")

    print(f"[*] Starting Bharat-PA Forensics API on http://{host}:{port}")
    uvicorn.run(
        "parsers.api_server:app",
        host=host,
        port=port,
        reload=False,
        access_log=True,
        timeout_keep_alive=65,
    )


if __name__ == "__main__":
    main()
