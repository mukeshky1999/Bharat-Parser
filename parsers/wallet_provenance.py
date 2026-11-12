"""
parsers/wallet_provenance.py

Provenance and evidentiary-weight layer for custodial wallet records.

Every wallet record gets:
  - Source_SHA256 (from BSAComplianceEngine inner artifact registry)
  - Source_File_Size
  - Row_ID (sqlite rowid where recoverable)
  - Extraction_Timestamp_IST
  - Evidence_Weight  →  HIGH / MEDIUM / LOW
  - Chain_Of_Custody_ID (UUID per record)

This mirrors how UPI records are already proven by fs_handler + BSAComplianceEngine.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


_RECOVERY_WEIGHT = {
    "Active B-Tree":             "HIGH",
    "WAL Rollback Revision":     "HIGH",
    "DELETED (Freelist Carved)": "MEDIUM",
    "BLOB Extracted":            "HIGH",
    "Raw String Carved":         "MEDIUM",
    "UNKNOWN":                   "LOW",
}


def _now_ist_iso() -> str:
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    ist = utc_now.astimezone(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    return ist.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+05:30"


def _sha256_file(path: str, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while c := f.read(chunk):
                h.update(c)
        return h.hexdigest().upper()
    except Exception:
        return "READ_ERROR"


class WalletProvenance:
    """Attach chain-of-custody metadata to wallet records."""

    def __init__(self, case_id: str = "UNSPECIFIED"):
        self.case_id = case_id
        self.extraction_ts = _now_ist_iso()
        self._file_hash_cache: Dict[str, Dict[str, Any]] = {}

    def _file_meta(self, db_path: str) -> Dict[str, Any]:
        p = str(Path(db_path).resolve())
        if p not in self._file_hash_cache:
            self._file_hash_cache[p] = {
                "path": p,
                "name": Path(p).name,
                "size": Path(p).stat().st_size if Path(p).exists() else 0,
                "sha256": _sha256_file(p),
            }
        return self._file_hash_cache[p]

    def annotate(
        self,
        wallet_df: pd.DataFrame,
        source_db_path: str,
        bsa_engine=None,
    ) -> pd.DataFrame:
        """
        Returns the wallet DataFrame with provenance columns appended.
        Also registers the wallet DB in the BSA engine's inner artifact manifest.
        """
        if wallet_df.empty:
            return wallet_df
        out = wallet_df.copy()
        meta = self._file_meta(source_db_path)

        # Register with BSA engine if provided
        if bsa_engine is not None and hasattr(bsa_engine, "register_inner_artifact"):
            for app_label in out["Wallet_App"].unique():
                try:
                    bsa_engine.register_inner_artifact(
                        app_label=app_label,
                        relative_db_path=str(Path(source_db_path).name),
                        extracted_temp_path=str(Path(source_db_path).resolve()),
                    )
                except Exception:
                    pass

        out["Source_SHA256"] = meta["sha256"]
        out["Source_File_Size"] = meta["size"]
        out["Extraction_TS_IST"] = self.extraction_ts
        out["Case_ID"] = self.case_id
        out["Evidence_Weight"] = out["Recovery_Method"].map(
            lambda m: _RECOVERY_WEIGHT.get(str(m), "LOW")
        )
        # A random UUID per run is not a custody chain and changes on every export. This is a stable
        # record identifier derived from the case, the source file hash and the row itself.
        out["Chain_Of_Custody_ID"] = [
            str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.case_id}|{meta['sha256']}|{i}|{row_repr}")).upper()
            for i, row_repr in enumerate(out.astype(str).agg("|".join, axis=1))
        ]
        return out

    @staticmethod
    def compute_evidence_summary(wallet_df: pd.DataFrame) -> Dict[str, Any]:
        """Roll-up for Tab 7 / certificate."""
        if wallet_df.empty:
            return {"total_records": 0, "by_weight": {}, "by_wallet": {}, "by_class": {}}
        return {
            "total_records": int(len(wallet_df)),
            "by_weight": wallet_df["Evidence_Weight"].value_counts().to_dict()
                if "Evidence_Weight" in wallet_df else {},
            "by_wallet": wallet_df["Wallet_App"].value_counts().to_dict(),
            "by_class": wallet_df["Data_Class"].value_counts().to_dict(),
            "unique_addresses": int(wallet_df["Address"].dropna().nunique())
                if "Address" in wallet_df else 0,
            "unique_chains": int(wallet_df["Chain"].dropna().nunique())
                if "Chain" in wallet_df else 0,
        }

    @staticmethod
    def export_provenance_json(wallet_df: pd.DataFrame, case_id: str) -> str:
        """Tamper-evident provenance export for the certificate bundle."""
        if wallet_df.empty:
            return json.dumps({"case_id": case_id, "records": []}, indent=2)
        keep = [
            "Chain_Of_Custody_ID", "Case_ID", "Wallet_App", "Data_Class",
            "Source_Artifact", "Source_SHA256", "Source_File_Size",
            "Recovery_Method", "Evidence_Weight", "Extraction_TS_IST",
            "Direction", "Chain", "Address", "Asset",
            "Amount_Crypto", "Amount_INR", "Timestamp_UTC",
        ]
        present = [c for c in keep if c in wallet_df.columns]
        payload = {
            "case_id": case_id,
            "generated_ist": _now_ist_iso(),
            "record_count": int(len(wallet_df)),
            "records": wallet_df[present].to_dict(orient="records"),
        }
        canonical = json.dumps(payload, sort_keys=True)
        payload["master_seal_sha256"] = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest().upper()
        return json.dumps(payload, indent=2)
