"""
Sub-Engine 4.3C: WalletConnect v2 Multi-Chain Session & Phishing Drainer Decoder.
Parses wc@2: pairing and session storage keys, resolves CAIP-10 multi-chain accounts,
and audits JSON-RPC requests to detect gasless Permit / Permit2 drainer signatures.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.validators.models import (
    WalletConnectAuditRecord,
    WalletConnectRecordType,
)

DRAINER_PRIMARY_TYPES = ("Permit", "PermitSingle", "PermitBatch", "OrderComponents")


class WalletConnectDecoder:
    """Decodes WalletConnect v2 storage states and audits phishing requests."""

    def __init__(self) -> None:
        self.supported_namespaces = ("eip155", "tron", "solana", "bip122")

    def parse_rpc_record(
        self,
        rpc_entry: Dict[str, Any],
        dapp_name: Optional[str] = None,
        dapp_url: str = "",
        source_vfs_file_id: int = 0,
    ) -> WalletConnectAuditRecord:
        """
        Audits a WalletConnect JSON-RPC request/response pair for phishing drainers.
        """
        rpc_id = rpc_entry.get("id")
        topic = rpc_entry.get("topic")
        method = rpc_entry.get("method", "")
        params = rpc_entry.get("params", [])
        response = rpc_entry.get("response", {})

        is_drainer = 0
        rec_type = WalletConnectRecordType.WC_V2_JSON_RPC_TRANSACTION

        # Check for eth_signTypedData_v4 gasless permit phishing
        if "signtypeddata" in method.lower():
            if len(params) > 1:
                typed_data_raw = params[1]
                try:
                    if isinstance(typed_data_raw, str):
                        typed_data = json.loads(typed_data_raw)
                    else:
                        typed_data = typed_data_raw
                    primary_type = typed_data.get("primaryType", "")
                    if any(dt.lower() == primary_type.lower() for dt in DRAINER_PRIMARY_TYPES):
                        is_drainer = 1
                        rec_type = WalletConnectRecordType.WC_V2_EIP712_PERMIT_SIGNATURE
                except Exception:
                    is_drainer = 0

        ev_state = EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            provenance_pointer=f"wc2::rpc::{rpc_id}",
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )

        return WalletConnectAuditRecord(
            source_vfs_file_id=source_vfs_file_id,
            wc_record_type=rec_type,
            session_topic_hex=str(topic) if topic else None,
            dapp_peer_name=dapp_name,
            dapp_peer_url=dapp_url,
            rpc_method_and_params_json=json.dumps(rpc_entry),
            is_phishing_permit_drainer_sig=is_drainer,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            evidentiary_state=ev_state,
        )

    def parse_session_record(
        self,
        session_entry: Dict[str, Any],
        app_instance_id: int = 0,
        source_vfs_file_id: int = 0,
    ) -> WalletConnectAuditRecord:
        """
        Parses a WalletConnect v2 session object, resolving CAIP-10 multi-chain accounts.
        """
        topic = session_entry.get("topic")
        expiry = session_entry.get("expiry", 0)
        peer_meta = session_entry.get("peer", {}).get("metadata", {})
        dapp_name = peer_meta.get("name")
        dapp_url = peer_meta.get("url", "")

        # Extract CAIP-10 accounts across all approved namespaces
        namespaces = session_entry.get("namespaces", {})
        caip10_accounts: List[str] = []
        for ns_key, ns_val in namespaces.items():
            if isinstance(ns_val, dict):
                accounts = ns_val.get("accounts", [])
                caip10_accounts.extend(accounts)

        # Calculate session pairing start time: expiry - 7 days (604,800 s)
        paired_iso: Optional[str] = None
        expiry_iso: Optional[str] = None
        if expiry > 0:
            exp_ts = int(expiry)
            expiry_iso = ForensicTimestamp.from_unix_seconds(exp_ts).utc_iso8601
            paired_ts = max(0, exp_ts - 604800)
            paired_iso = ForensicTimestamp.from_unix_seconds(paired_ts).utc_iso8601

        ev_state = EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            provenance_pointer=f"wc2::session::{topic}",
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )

        return WalletConnectAuditRecord(
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
            wc_record_type=WalletConnectRecordType.WC_V2_PAIRING_OR_SESSION,
            session_topic_hex=str(topic) if topic else None,
            dapp_peer_name=dapp_name,
            dapp_peer_url=dapp_url,
            exposed_caip10_accounts_json=json.dumps(caip10_accounts) if caip10_accounts else None,
            session_paired_utc_iso=paired_iso,
            session_expiry_utc_iso=expiry_iso,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            evidentiary_state=ev_state,
        )
