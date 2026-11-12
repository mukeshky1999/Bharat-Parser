"""
Bharat-PA Forensics — High-Performance Local REST API Server
Bridges Python 1 TB+ FTS5 Paginated Case Store, Native Windows File/Folder Pickers,
Streaming Forensic Ingestion Pipeline, Graph Intelligence, and Section 63 BSA 2023 Generator
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
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from tools.forensic_benchmark_recorder import ForensicBenchmarkRecorder
from src.chat_reconstructor_and_redline.myers_redline_engine import MyersRedlineEngine
from src.chat_reconstructor_and_redline.models import DiffTokenType
from src.financial_graph_and_storyboard.sankey_canvas import SankeyCanvasRenderer, SankeyLaunderingCanvas, render_layout_svg
from src.financial_graph_and_storyboard.models import SankeyNode, SankeyFlowRibbon, SankeyStageColumn
from src.dossier_and_exhibits.exhibit_packager import ExhibitAndDefensePackager
from src.dossier_and_exhibits.models import SensitiveMediaItem, RedactionTag, MuleTransactionEntry
from src.unk_triage_and_bsa_studio.freeze_deconfliction import NodalFreezeDeconflictionCenter
from src.dossier_and_exhibits.nodal_freeze_and_requisitions import NodalFreezeExporter
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
    description="High-performance backend API for Indian UPI, Chat Forensics, 1 TB+ Case Store, and Section 63 BSA Compliance",
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


class Sec230MediaInput(BaseModel):
    path: str
    redaction_tag: Optional[str] = None  # required: a RedactionTag value (DISCLOSABLE to release)


class Sec230BnssRequest(BaseModel):
    case_id: Optional[str] = None
    output_dir: Optional[str] = None
    anonymize_victim_identity: bool = True
    victim_name: Optional[str] = None
    items: Optional[List[Sec230MediaInput]] = None


class NcrpFreezeRequest(BaseModel):
    case_id: Optional[str] = None
    output_dir: Optional[str] = None
    complainant_account: Optional[str] = None
    acknowledgement_no: Optional[str] = None
    complainant_vpa: Optional[str] = None
    state_ut: Optional[str] = None
    police_station: Optional[str] = None
    investigating_officer: Optional[str] = None
    crime_category: Optional[str] = None
    candidates: Optional[List[Dict[str, Any]]] = None
    transactions: Optional[List[Dict[str, Any]]] = None


class OcrAnalyzeRequest(BaseModel):
    image_path: str


class Sec63BsaRequest(BaseModel):
    case_id: Optional[str] = None
    case_name: Optional[str] = None
    examiner_name: Optional[str] = None
    designation: Optional[str] = None
    fsl_lab: Optional[str] = None
    fir_number: Optional[str] = None
    io_name: Optional[str] = None
    police_station: Optional[str] = None
    court_name: Optional[str] = None


# ------------------------------------------------------------------------------
# Hashing & File Utilities
# ------------------------------------------------------------------------------

def _hash_stream(path: str, md5_h, sha_h) -> int:
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            md5_h.update(chunk)
            sha_h.update(chunk)
    return total


def compute_hashes_streaming(file_path: str) -> Dict[str, Any]:
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
        total_bytes = _hash_stream(file_path, md5_hasher, sha256_hasher)
    else:
        entries: List[Tuple[str, str, int]] = []
        for root, dirs, files in os.walk(file_path):
            dirs.sort()
            for name in sorted(files):
                full_p = os.path.join(root, name)
                rel = os.path.relpath(full_p, file_path).replace("\\", "/")
                f_sha = hashlib.sha256()
                f_md5 = hashlib.md5()
                size = _hash_stream(full_p, f_md5, f_sha)
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


def _resolve_case_file(requested: str, *, for_sqlite: bool = False) -> str:
    """
    Resolves a client-supplied path to a file the active case may read.

    Only the case workspace and the evidence source are allowed. When SQLite is going to open the
    file, a path inside the original evidence folder is redirected to the identical file in the
    case working copy, so the original is never touched.
    """
    if not requested or not isinstance(requested, str):
        raise HTTPException(status_code=400, detail="A file path is required.")
    ws = os.path.abspath(_active_store.case_workspace)
    ev = _case_state.get("evidence_path") if _case_state.get("loaded") else None

    candidates = [os.path.abspath(requested), os.path.abspath(os.path.join(ws, requested))]
    # Parsers record paths relative to the evidence root ("data/data/com.whatsapp/databases/msgstore.db"):
    # try the case working copy, then the evidence folder itself.
    if ".." not in re.split(r"[\\/]+", requested) and not os.path.isabs(requested):
        candidates.append(os.path.abspath(os.path.join(ws, "working_copy", requested)))
        if ev and os.path.isdir(ev):
            candidates.append(os.path.abspath(os.path.join(ev, requested)))
    allowed_missing = False
    for cand in candidates:
        in_ws = _is_within(cand, ws)
        in_ev = bool(ev) and _is_within(cand, ev)
        if not (in_ws or in_ev):
            continue
        if not os.path.isfile(cand):
            allowed_missing = True
            continue
        if for_sqlite and in_ev and not in_ws:
            wc = os.path.join(ws, "working_copy")
            rel = os.path.relpath(cand, ev if os.path.isdir(ev) else os.path.dirname(ev))
            mapped = os.path.join(wc, rel)
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


# ------------------------------------------------------------------------------
# Core Ingestion Pipeline Implementation
# ------------------------------------------------------------------------------

def _execute_ingestion_pipeline(
    evidence_path: str,
    case_id: str,
    case_name: str,
    examiner_name: str,
    agency_name: str,
) -> Dict[str, Any]:
    global _active_store, _case_state

    abs_evidence = os.path.abspath(evidence_path)
    if not os.path.exists(abs_evidence):
        raise HTTPException(status_code=404, detail=f"Evidence path not found: {abs_evidence}")

    workspace_dir = os.path.abspath(os.path.join(DEFAULT_WORKSPACE_ROOT, case_id))
    os.makedirs(workspace_dir, exist_ok=True)
    extracted_dbs_dir = os.path.join(workspace_dir, "extracted_dbs")
    os.makedirs(extracted_dbs_dir, exist_ok=True)

    # 1. Compute Pre-Ingestion SHA-256 and MD5
    hashes = compute_hashes_streaming(abs_evidence)

    # 2. Extract or Index Forensic DBs
    p_low = abs_evidence.lower()
    is_archive = p_low.endswith((".ufdr", ".ufd", ".tar", ".tar.gz", ".tgz", ".zip", ".xry", ".ofb", ".e01", ".ex01", ".l01"))

    catalog_entries: List[Dict[str, Any]] = []
    working_copy_dir: Optional[str] = None
    processing_log: List[Dict[str, str]] = []

    def _log_failure(stage: str, path: str, exc: BaseException) -> None:
        processing_log.append({
            "stage": stage,
            "file": os.path.basename(path),
            "status": "FAILED",
            "error": f"{type(exc).__name__}: {exc}",
        })

    if p_low.endswith((".ufd", ".xry", ".ofb")) and not zipfile.is_zipfile(abs_evidence):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported container: {os.path.basename(abs_evidence)} is not a ZIP-based "
                   "extraction. Nothing was ingested.",
        )

    if is_archive:
        container_engine = TerabyteForensicContainerEngine(abs_evidence, workspace_dir)
        container_engine.index_and_materialize_targets()
        # Collect materialized DBs
        discovered_files: List[str] = []
        for root, _, files in os.walk(extracted_dbs_dir):
            for f in files:
                discovered_files.append(os.path.join(root, f))
    elif os.path.isdir(abs_evidence):
        # Evidence is never opened in place: SQLite creates -shm/-wal side files and may
        # checkpoint. Parse a byte-identical working copy instead.
        working_copy_dir = os.path.join(workspace_dir, "working_copy")
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
        working_copy_dir = os.path.join(workspace_dir, "working_copy")
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

    # Iterate over discovered files
    for file_path in discovered_files:
        f_low = file_path.lower()

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

        # Determine relative / virtual file system path for accurate plugin matching
        if is_archive and file_path.startswith(extracted_dbs_dir):
            vfs_path = os.path.relpath(file_path, extracted_dbs_dir).replace("\\", "/")
        elif working_copy_dir and file_path.startswith(working_copy_dir):
            vfs_path = os.path.relpath(file_path, working_copy_dir).replace("\\", "/")
        else:
            vfs_path = file_path.replace("\\", "/")

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
                if arts:
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

            # Crypto P2P parsing
            try:
                crypto_df = parse_crypto_p2p_artifacts(file_path, app_name=app_label)
                if crypto_df is not None and not crypto_df.empty:
                    crypto_p2p_records.append(crypto_df)
            except Exception as exc:
                _log_failure("crypto_p2p", file_path, exc)

    # 4. Reconciliation and Cross-App Enrichment
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
    g = build_transaction_graph(combined_txs_df)
    roles_df = classify_syndicate_roles(g, combined_txs_df)
    mule_alerts = detect_mule_behavior(g, combined_txs_df)
    pyvis_html = generate_pyvis_network_html(g, mule_alerts, roles_df)

    # 8. Commit All Data to SQLite+FTS5 Case Store
    # Opening the same case id again must not add the records a second time: start from an empty store.
    # (The findings file is separate and is kept.)
    for suffix in ("", "-wal", "-shm"):
        stale = os.path.join(workspace_dir, "bharat_case_store.db" + suffix)
        if os.path.isfile(stale):
            os.remove(stale)
    store = CaseUIPaginatorStore(workspace_dir, db_name="bharat_case_store.db")

    if all_chats_list:
        combined_chats = pd.concat(all_chats_list, ignore_index=True)
        store.ingest_dataframe_chunked("chats", combined_chats)

    if not combined_txs_df.empty:
        store.ingest_dataframe_chunked("transactions", combined_txs_df)

    if all_contacts_list:
        combined_contacts = pd.concat(all_contacts_list, ignore_index=True)
        store.ingest_dataframe_chunked("contacts", combined_contacts)

    if all_calls_list:
        combined_calls = pd.concat(all_calls_list, ignore_index=True)
        store.ingest_dataframe_chunked("calls", combined_calls)

    if all_locations_list:
        combined_locations = pd.concat(all_locations_list, ignore_index=True)
        store.ingest_dataframe_chunked("locations", combined_locations)

    if all_spillover_list:
        combined_spillover = pd.concat(all_spillover_list, ignore_index=True)
        store.ingest_dataframe_chunked("os_spillover", combined_spillover)

    if not combined_crypto_df.empty:
        store.ingest_dataframe_chunked("p2p_orders", combined_crypto_df)

    if not aligned_fiat_crypto_df.empty:
        store.ingest_dataframe_chunked("fiat_crypto_bridge", aligned_fiat_crypto_df)

    if catalog_entries:
        catalog_df = pd.DataFrame(catalog_entries)
        store.ingest_dataframe_chunked("vfs_files", catalog_df)

    for tbl, cols in store.last_dropped_columns.items():
        if cols:
            processing_log.append({
                "stage": "ingest_schema", "file": tbl, "status": "WARNING",
                "error": f"Columns with data not stored: {', '.join(cols)}",
            })

    # Post-ingestion integrity check: re-hash the original evidence and compare.
    post_hashes = compute_hashes_streaming(abs_evidence)
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

    _case_state = {
        "loaded": True,
        "case_id": case_id,
        "case_name": case_name,
        "evidence_path": abs_evidence,
        "examiner_name": examiner_name,
        "agency_name": agency_name,
        "extractions": [
            {
                "evidenceId": case_id,
                "sourcePath": abs_evidence,
                "type": "PHYSICAL_OR_LOGICAL",
                "hashes": hashes,
                "deviceMetadata": device_meta,
            }
        ],
        "counts": counts,
        "owner_dossier": serializable_dossier,
        "hashes": hashes,
        "processing_log": processing_log,
        "mule_alerts": mule_alerts,
        "syndicate_roles": roles_df.to_dict("records") if not roles_df.empty else [],
        "device_metadata": device_meta,
        "pyvis_html": pyvis_html,
        "charge_sheet_chain": {
            "case_id": case_id,
            "evidence_hash_sha256": hashes.get("sha256"),
            "mule_alerts_count": len(mule_alerts),
            "syndicate_entities_count": len(roles_df) if not roles_df.empty else 0,
            "roles": roles_df.to_dict("records") if not roles_df.empty else [],
            "alerts": mule_alerts,
        },
    }

    return {
        "success": True,
        "case_id": case_id,
        "case_name": case_name,
        "workspace_dir": workspace_dir,
        "db_path": _active_store.db_path,
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
    }


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

    case_id = req.case_id or f"CASE_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    case_name = req.case_name or os.path.splitext(os.path.basename(req.evidence_path))[0]
    examiner = req.examiner_name or ""
    agency = req.agency_name or ""

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
            )
            return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


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


def _build_sec63_response(officer: Optional[Dict[str, Any]] = None):
    officer = officer or {}
    """
    Generates statutory Certificate under Section 63(4)(c)
    Bharatiya Sakshya Adhiniyam, 2023 (BSA).
    Returns clean printable court-admissible HTML.
    """
    if not _case_state.get("loaded"):
        raise HTTPException(
            status_code=412,
            detail="Precondition Failed: load a case before generating a certificate.",
        )
    e = html_lib.escape  # all evidence-derived strings are escaped before entering HTML
    case_id = e(str(officer.get("case_id") or _case_state.get("case_id") or "Not recorded"))
    case_name = e(str(officer.get("case_name") or _case_state.get("case_name") or "Not recorded"))
    hashes = _case_state.get("hashes", {})
    sha256_hash = e(str(hashes.get("sha256", "Not recorded")))
    md5_hash = e(str(hashes.get("md5", "Not recorded")))
    post_sha256 = hashes.get("postIngestionSha256")
    post_md5 = hashes.get("postIngestionMd5")
    size_bytes = int(hashes.get("fileSizeBytes", 0) or 0)
    dev_meta = _case_state.get("device_metadata") or {}
    counts = _active_store.get_project_tree_counts()
    processing_log = _case_state.get("processing_log") or []
    failed_files = [x for x in processing_log if x.get("status") == "FAILED"]

    if post_sha256 is None:
        integrity_line = "NOT RECORDED - no post-ingestion hash exists for this case."
        integrity_class = "warn"
    elif hashes.get("integrityMatch"):
        integrity_line = "MATCH - the evidence hashed identically before and after processing."
        integrity_class = "ok"
    else:
        integrity_line = "MISMATCH - the evidence hash CHANGED during processing. Do not rely on this output."
        integrity_class = "bad"

    def _off(key: str) -> str:
        val = str(officer.get(key) or "").strip()
        return e(val) if val else "<em>Not provided</em>"

    def _dev(key: str) -> str:
        return e(str(dev_meta.get(key, "Not recorded")))

    total_chats = counts.get("chats_all", {}).get("total", 0)
    total_upi = counts.get("upi_all", {}).get("total", 0)
    total_calls = counts.get("calls_all", {}).get("total", 0)
    total_contacts = counts.get("contacts_all", {}).get("total", 0)

    now_iso = datetime.now(timezone.utc).strftime("%d-%B-%Y %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Section 63(4)(c) BSA Certificate - Case {case_id}</title>
<style>
    body {{
        font-family: 'Times New Roman', serif;
        line-height: 1.6;
        color: #111827;
        padding: 40px;
        background: #ffffff;
        max-width: 860px;
        margin: auto;
    }}
    .header {{
        text-align: center;
        border-bottom: 2px solid #000;
        padding-bottom: 12px;
        margin-bottom: 24px;
    }}
    .title {{
        font-size: 18pt;
        font-weight: bold;
        text-transform: uppercase;
        margin: 4px 0;
    }}
    .subtitle {{
        font-size: 12pt;
        font-weight: bold;
    }}
    .act {{
        font-size: 11pt;
        font-style: italic;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 16px 0;
        font-size: 10.5pt;
    }}
    th, td {{
        border: 1px solid #374151;
        padding: 6px 10px;
        text-align: left;
    }}
    th {{
        background-color: #f3f4f6;
        font-weight: bold;
    }}
    .mono {{
        font-family: 'Courier New', monospace;
        word-break: break-all;
    }}
    .declaration {{
        margin: 20px 0;
        text-align: justify;
        font-size: 11pt;
    }}
    .ok {{ color: #065f46; }}
    .warn {{ color: #92400e; }}
    .bad {{ color: #991b1b; }}
    .signatures {{
        margin-top: 50px;
        display: flex;
        justify-content: space-between;
    }}
    .sig-box {{
        width: 45%;
        border-top: 1px solid #000;
        padding-top: 8px;
        text-align: center;
        font-size: 11pt;
    }}
</style>
</head>
<body>
<div class="header">
    <div class="subtitle">GOVERNMENT OF INDIA / STATE POLICE DEPARTMENT</div>
    <div class="title">CERTIFICATE OF ELECTRONIC EVIDENCE</div>
    <div class="act">Under Section 63(4)(c) of the Bharatiya Sakshya Adhiniyam, 2023 (BSA)<br>
    (In substitution of Section 65B of the Indian Evidence Act, 1872)</div>
</div>

<p>I, the undersigned Digital Forensic Examiner, do hereby solemnly certify and declare as follows:</p>

<table>
    <tr><th colspan="2">1. PARTICULARS OF ELECTRONIC EVIDENCE RECORD</th></tr>
    <tr><td width="35%">Case Reference ID:</td><td><strong>{case_id}</strong></td></tr>
    <tr><td>Case Name / Title:</td><td>{case_name}</td></tr>
    <tr><td>Source Evidence File / Path:</td><td class="mono">{_dev("evidenceSourcePath")}</td></tr>
    <tr><td>Evidence File Size:</td><td>{size_bytes:,} Bytes ({size_bytes / (1024*1024):.2f} MB)</td></tr>
    <tr><td>Pre-Ingestion SHA-256 Hash:</td><td class="mono"><strong>{sha256_hash}</strong></td></tr>
    <tr><td>Pre-Ingestion MD5 Hash:</td><td class="mono">{md5_hash}</td></tr>
    <tr><td>Post-Ingestion SHA-256 Hash:</td><td class="mono">{e(str(post_sha256)) if post_sha256 else "Not recorded"}</td></tr>
    <tr><td>Post-Ingestion MD5 Hash:</td><td class="mono">{e(str(post_md5)) if post_md5 else "Not recorded"}</td></tr>
    <tr><td>Hash Comparison:</td><td class="{integrity_class}"><strong>{integrity_line}</strong></td></tr>
    <tr><td>Target Hardware Model:</td><td>{_dev("model")} ({_dev("manufacturer")})</td></tr>
    <tr><td>OS / Build:</td><td>{_dev("androidVersion")} / {_dev("buildNumber")}</td></tr>
    <tr><td>Device Serial / IMEI:</td><td>{_dev("serialNumber")} / {_dev("imei1")}</td></tr>
</table>

<table>
    <tr><th colspan="2">1A. OFFICER AND CASE PARTICULARS (as entered by the examiner)</th></tr>
    <tr><td width="35%">FIR Number:</td><td>{_off("fir_number")}</td></tr>
    <tr><td>Police Station:</td><td>{_off("police_station")}</td></tr>
    <tr><td>Court:</td><td>{_off("court_name")}</td></tr>
    <tr><td>Examiner:</td><td>{_off("examiner_name")}, {_off("designation")}</td></tr>
    <tr><td>Laboratory:</td><td>{_off("fsl_lab")}</td></tr>
    <tr><td>Investigating Officer / Custodian:</td><td>{_off("io_name")}</td></tr>
</table>

<table>
    <tr><th colspan="4">2. PARSED DIGITAL ARTIFACT SUMMARY</th></tr>
    <tr>
        <th>Category</th><th>Active</th><th>Recovered (WAL / Carved)</th><th>Total Records</th>
    </tr>
    <tr>
        <td>UPI & Banking Transactions</td>
        <td>{counts.get("upi_all", {}).get("active", 0)}</td>
        <td>{counts.get("upi_all", {}).get("wal_and_carved", 0)}</td>
        <td>{total_upi}</td>
    </tr>
    <tr>
        <td>Instant Messaging & Social Chats</td>
        <td>{counts.get("chats_all", {}).get("active", 0)}</td>
        <td>{counts.get("chats_all", {}).get("wal_and_carved", 0)}</td>
        <td>{total_chats}</td>
    </tr>
    <tr>
        <td>Call Logs (Cellular CDR & VoIP)</td>
        <td>{counts.get("calls_all", {}).get("active", 0)}</td>
        <td>{counts.get("calls_all", {}).get("wal_and_carved", 0)}</td>
        <td>{total_calls}</td>
    </tr>
    <tr>
        <td>Contacts & Counterparty Dossiers</td>
        <td>{counts.get("contacts_all", {}).get("active", 0)}</td>
        <td>{counts.get("contacts_all", {}).get("wal_and_carved", 0)}</td>
        <td>{total_contacts}</td>
    </tr>
</table>

<div class="declaration">
    <p><strong>3. PROCESSING FACTS RECORDED BY THE SOFTWARE:</strong></p>
    <p>(a) Evidence was not opened in place. Folders and single files were copied to a case working copy, and archives were extracted into the case workspace, before any database was opened.</p>
    <p>(b) SHA-256 and MD5 were computed over the original evidence before processing and again after processing. Result: <strong>{integrity_line}</strong></p>
    <p>(c) Files processed: {len([x for x in processing_log if x.get("stage") == "parse_database" and x.get("status") == "OK"])} database(s) parsed without error; <strong>{len(failed_files)}</strong> processing step(s) failed{"" if not failed_files else " (see list below)"}.</p>
    <p>(d) The examiner must personally confirm, by signature, that the forensic workstation operated properly and that the details above are correct. The software does not make that declaration.</p>
    {"".join(f'<p class="mono">FAILED: {e(str(x.get("stage")))} / {e(str(x.get("file")))} - {e(str(x.get("error")))}</p>' for x in failed_files[:50])}
</div>

<div class="signatures">
    <div class="sig-box">
        <strong>Forensic Examiner Signature</strong><br>
        Cyber Crime Forensic Laboratory<br>
        Timestamp: {now_iso}
    </div>
    <div class="sig-box">
        <strong>Investigating Officer / In-Charge</strong><br>
        Special Cyber Crime Police Station<br>
        Seal & Official Stamp
    </div>
</div>
</body>
</html>"""
    headers = {
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline';",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Content-Disposition": 'inline; filename="sec63_certificate.html"',
    }
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers=headers,
    )


@app.get("/api/report/sec63-bsa")
def generate_sec63_bsa_certificate():
    """Section 63(4)(c) BSA certificate generated only from facts recorded for the loaded case."""
    return _build_sec63_response()


@app.post("/api/report/sec63-bsa")
def generate_sec63_bsa_certificate_post(req: Sec63BsaRequest):
    """Same certificate, with the officer/court particulars supplied by the examiner (all escaped)."""
    return _build_sec63_response(req.model_dump(exclude_none=True))


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


@app.post("/api/report/sec230-bnss")
def generate_sec230_bnss_report(req: Sec230BnssRequest):
    """
    Generates Section 230 BNSS statutory defense disclosure bundle.
    Automatically withholds intimate / CSAM media and replaces them with
    Statutory Judicial-Inspection Notice Cards (P. Gopalkrishnan v. State of Kerala, 2019),
    and anonymizes victim identity under Section 72 BNS, 2023.
    """
    case_id = req.case_id or _case_state.get("case_id") or "CASE_SEC230_DEFAULT"
    out_dir = req.output_dir or os.path.join(DEFAULT_WORKSPACE_ROOT, case_id, "sec230_bnss_bundle")
    os.makedirs(out_dir, exist_ok=True)

    if not req.items:
        raise HTTPException(
            status_code=422,
            detail="No media items supplied. Select the case media files to package; "
                   "nothing is generated from built-in samples.",
        )

    if req.anonymize_victim_identity and not (req.victim_name or "").strip():
        raise HTTPException(status_code=422, detail="Victim anonymisation is on: enter the victim name to redact.")

    packager = ExhibitAndDefensePackager()

    valid_tags = {t.value: t for t in RedactionTag}
    sample_items = []
    for item in req.items:
        if not item.redaction_tag:
            raise HTTPException(
                status_code=422,
                detail=f"No redaction decision for {os.path.basename(item.path)}: choose a tag for every item "
                       "(DISCLOSABLE to release it).",
            )
        if item.redaction_tag not in valid_tags:
            raise HTTPException(status_code=422, detail=f"Unknown redaction tag: {item.redaction_tag}")
        real_path = _resolve_case_file(item.path)
        with open(real_path, "rb") as fh:
            raw = fh.read()
        sample_items.append(
            SensitiveMediaItem(
                canonical_path=real_path,
                file_name=os.path.basename(real_path),
                sha256_hex=hashlib.sha256(raw).hexdigest(),
                md5_hex=hashlib.md5(raw).hexdigest(),
                raw_bytes=raw,
                redaction_tag=valid_tags[item.redaction_tag],
                timestamps_utc=datetime.fromtimestamp(os.path.getmtime(real_path), timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ) + " (file modification time)",
            )
        )

    try:
        result = packager.package_section_230_defense_bundle(
            case_id=case_id,
            items=sample_items,
            output_dir=out_dir,
            anonymize_victim_identity=req.anonymize_victim_identity,
            victim_name=req.victim_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "success": True,
        "case_id": case_id,
        "bundle_path": result.bundle_path,
        "pocso_withheld_count": result.pocso_withheld_count,
        "html_viewer_path": result.html_viewer_path,
        "statutory_mandate": "Section 230 BNSS 2023 / P. Gopalkrishnan v. State of Kerala (2019)",
    }


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


def _derive_ncrp_candidates(complainant_account: str = "") -> List[Dict[str, Any]]:
    """Beneficiary accounts/VPAs of successful outgoing transactions in the loaded case."""
    if not _case_state.get("loaded") or _active_store is None:
        return []
    conn = _active_store._get_connection()
    try:
        rows = conn.execute(
            "SELECT COALESCE(NULLIF(Account,''), NULLIF(VPA,''), Counterparty) AS acct, "
            "VPA, Counterparty, SUM(Amount) AS vol FROM transactions "
            "WHERE UPPER(COALESCE(Type,'')) = 'DEBIT' "
            "AND UPPER(COALESCE(Status,'')) NOT GLOB '*FAIL*' AND UPPER(COALESCE(Status,'')) NOT GLOB '*PEND*' "
            "AND UPPER(COALESCE(Status,'')) NOT GLOB '*UNKNOWN*' AND UPPER(COALESCE(Status,'')) NOT GLOB '*DELETED*' "
            "GROUP BY acct HAVING acct IS NOT NULL AND acct <> '' ORDER BY vol DESC"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "account_no": str(r["acct"]),
            "ifsc": "",
            "vpa": str(r["VPA"] or ""),
            "is_complainant_victim": bool(complainant_account) and str(r["acct"]).strip() == complainant_account,
            "volume_inr": float(r["vol"] or 0.0),
            "counterparty_name": str(r["Counterparty"] or ""),
        }
        for r in rows
    ]


@app.get("/api/report/ncrp-candidates")
def get_ncrp_candidates(complainant_account: str = Query("")):
    """Candidate beneficiary accounts derived from the loaded case (empty list if none)."""
    cands = _derive_ncrp_candidates(complainant_account.strip())
    return {"success": True, "candidates": cands, "count": len(cands)}


@app.post("/api/report/ncrp-freeze")
@app.post("/api/report/1930-ncrp")
def generate_ncrp_freeze_report(req: NcrpFreezeRequest):
    """
    Evaluates candidate freeze accounts and exports de-conflicted 14-column 1930 NCRP bank lien sheets.
    Enforces Complainant / Victim Safeguard Lock (freeze_checkbox_disabled = True) to prevent victim freezes.
    """
    case_id = req.case_id or _case_state.get("case_id") or "CASE_NCRP_1930"
    out_dir = req.output_dir or os.path.join(DEFAULT_WORKSPACE_ROOT, case_id, "ncrp_1930_exports")
    os.makedirs(out_dir, exist_ok=True)

    complainant_account = str(req.complainant_account or "").strip()
    acknowledgement_no = str(req.acknowledgement_no or "").strip()
    if not complainant_account or not acknowledgement_no:
        raise HTTPException(
            status_code=422,
            detail="Complainant account and NCRP acknowledgement number are required.",
        )

    candidates = req.candidates or _derive_ncrp_candidates(complainant_account)
    if not candidates:
        raise HTTPException(
            status_code=422,
            detail="No candidate accounts: the case has no successful outgoing transactions to freeze against.",
        )

    comp_acc = complainant_account.lower()
    comp_vpa = str(req.complainant_vpa or "").strip().lower()
    for c in candidates:
        acc = str(c.get("account_no", "")).strip().lower()
        vpa = str(c.get("vpa", "")).strip().lower()
        if (comp_acc and acc == comp_acc) or (comp_vpa and (vpa == comp_vpa or acc == comp_vpa)):
            c["is_complainant_victim"] = True

    center = NodalFreezeDeconflictionCenter()
    evaluated = center.evaluate_freeze_candidates(candidates)

    csv_text = center.generate_1930_ncrp_csv(
        evaluated_candidates=evaluated,
        complainant_account=complainant_account,
        acknowledgement_no=acknowledgement_no,
        state_ut=req.state_ut or "",
        police_station=req.police_station or "",
        investigating_officer=req.investigating_officer or "",
        crime_category=req.crime_category or "",
    )

    csv_filename = "ncrp_1930_bank_freeze_packet.csv"
    csv_path = os.path.join(out_dir, csv_filename)
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(csv_text)

    sha256_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()

    victim_safeguards = [
        {
            "account_no": c.account_no,
            "is_victim": c.is_complainant_victim,
            "is_freeze_locked": c.is_freeze_locked,
            "freeze_checkbox_disabled": c.freeze_checkbox_disabled,
            "role_badge": c.role_badge,
        }
        for c in evaluated
    ]

    target_freezes = [c for c in evaluated if not c.is_freeze_locked and not c.is_utility_excluded]
    total_lien_amount = sum(c.volume_inr for c in target_freezes)

    return {
        "success": True,
        "csv_path": csv_path,
        "csv_content": csv_text,
        "sha256": sha256_hash,
        "total_accounts_evaluated": len(evaluated),
        "total_freeze_targets": len(target_freezes),
        "total_lien_amount_inr": total_lien_amount,
        "safeguards": victim_safeguards,
        "portal": "I4C NCRP 1930 CFCFRMS Bank Lien Cart",
    }


@app.get("/api/report/ncrp-freeze")
def get_ncrp_freeze_csv(
    case_id: Optional[str] = Query(None),
    complainant_account: str = Query(...),
    acknowledgement_no: str = Query(...),
):
    """Returns the 14-column 1930 NCRP Bank Lien CSV derived from the loaded case's transactions."""
    req = NcrpFreezeRequest(
        case_id=case_id, complainant_account=complainant_account, acknowledgement_no=acknowledgement_no
    )
    res = generate_ncrp_freeze_report(req)
    csv_content = res.get("csv_content", "")
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ncrp_1930_bank_freeze.csv"'},
    )

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

        # Atomically synchronize _case_state to prevent torn reads and stale certificate generation
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
):
    """Legacy hex window endpoint with boundary validation and threadpool execution."""
    if not _case_state["loaded"]:
        raise HTTPException(
            status_code=412,
            detail="Precondition Failed: No forensic case is currently loaded.",
        )

    # Resolve and sandbox file path (same rules as every other endpoint: case workspace or evidence source only)
    abs_target = _resolve_case_file(file_path)

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
