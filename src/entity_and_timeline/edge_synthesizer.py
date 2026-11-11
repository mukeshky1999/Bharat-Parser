"""
Sub-Engine 8.1B: Typed Directed Graph Edge Synthesizer.
Constructs forensic relationship edges across resolved Master Entity Nodes:
- COMMUNICATED_WITH (chat messages, calls, platform tags, deleted evidence flags).
- TRANSFERRED_FIAT_TO (cumulative INR volume, UPI/IMPS rails, UTRs).
- SETTLED_P2P_ESCROW_WITH (P2P trades, buy/sell volumes, order IDs).
- TRANSFERRED_CRYPTO_TO (blockchain token volumes, txids).
Adheres strictly to AGENTS.md Forensic Invariants and Section 4 of Module 8.1 Specification.
"""

import json
from typing import Any, Dict, List, Optional

from src.entity_and_timeline.models import GraphEdgeRecord, GraphEdgeVerb


class GraphEdgeSynthesizer:
    """Synthesizes typed directed relationship edges between forensic entities."""

    def __init__(self):
        self._next_edge_uid = 1

    def create_communication_edge(
        self,
        source_uid: int,
        target_uid: int,
        interactions: List[Dict[str, Any]],
    ) -> GraphEdgeRecord:
        """Constructs a COMMUNICATED_WITH relationship edge aggregating chat/call exchanges."""
        count = len(interactions)
        platforms: List[str] = []
        has_deleted = 0
        timestamps: List[str] = []
        pointers: List[str] = []

        for item in interactions:
            plat = item.get("platform")
            if plat and plat not in platforms:
                platforms.append(plat)
            if item.get("is_deleted"):
                has_deleted = 1
            ts = item.get("utc_iso")
            if ts:
                timestamps.append(ts)
            ptr = item.get("pointer")
            if ptr:
                pointers.append(ptr)

        timestamps.sort()
        first_ts = timestamps[0] if timestamps else None
        last_ts = timestamps[-1] if timestamps else None

        edge = GraphEdgeRecord(
            graph_edge_uid=self._next_edge_uid,
            source_entity_uid=source_uid,
            target_entity_uid=target_uid,
            edge_verb=GraphEdgeVerb.COMMUNICATED_WITH.value,
            interaction_count=count,
            total_fiat_value_inr=0.0,
            total_crypto_value_summary=None,
            platforms_and_rails_json=json.dumps(platforms),
            has_deleted_or_hidden_evidence=has_deleted,
            supporting_record_pointers_json=json.dumps(pointers),
            first_interaction_utc_iso=first_ts,
            last_interaction_utc_iso=last_ts,
            platforms_and_rails=platforms,
            supporting_record_pointers=pointers,
        )
        self._next_edge_uid += 1
        return edge

    def create_fiat_transfer_edge(
        self,
        source_uid: int,
        target_uid: int,
        transfers: List[Dict[str, Any]],
    ) -> GraphEdgeRecord:
        """Constructs a TRANSFERRED_FIAT_TO relationship edge aggregating bank/UPI transfers."""
        count = len(transfers)
        total_inr = sum(float(t.get("amount_inr", 0.0)) for t in transfers)
        rails: List[str] = []
        pointers: List[str] = []
        timestamps: List[str] = []

        for t in transfers:
            rail = t.get("rail", "UPI")
            if rail not in rails:
                rails.append(rail)
            utr = t.get("utr")
            if utr:
                pointers.append(f"UTR:{utr}")
            ts = t.get("utc_iso")
            if ts:
                timestamps.append(ts)

        timestamps.sort()
        first_ts = timestamps[0] if timestamps else None
        last_ts = timestamps[-1] if timestamps else None

        edge = GraphEdgeRecord(
            graph_edge_uid=self._next_edge_uid,
            source_entity_uid=source_uid,
            target_entity_uid=target_uid,
            edge_verb=GraphEdgeVerb.TRANSFERRED_FIAT_TO.value,
            interaction_count=count,
            total_fiat_value_inr=total_inr,
            total_crypto_value_summary=None,
            platforms_and_rails_json=json.dumps(rails),
            has_deleted_or_hidden_evidence=0,
            supporting_record_pointers_json=json.dumps(pointers),
            first_interaction_utc_iso=first_ts,
            last_interaction_utc_iso=last_ts,
            platforms_and_rails=rails,
            supporting_record_pointers=pointers,
        )
        self._next_edge_uid += 1
        return edge

    def create_crypto_transfer_edge(
        self,
        source_uid: int,
        target_uid: int,
        transfers: List[Dict[str, Any]],
    ) -> GraphEdgeRecord:
        """Constructs a TRANSFERRED_CRYPTO_TO relationship edge aggregating on-chain/CEX transactions."""
        count = len(transfers)
        token_sums: Dict[str, float] = {}
        chains: List[str] = []
        pointers: List[str] = []

        for t in transfers:
            token = t.get("token", "USDT")
            chain = t.get("chain", "TRON")
            amt = float(t.get("amount", 0.0))
            token_sums[token] = token_sums.get(token, 0.0) + amt
            if chain not in chains:
                chains.append(chain)
            txid = t.get("txid")
            if txid:
                pointers.append(f"TXID:{txid}")

        crypto_summary = ", ".join(f"{amt:,.2f} {tok}" for tok, amt in token_sums.items())

        edge = GraphEdgeRecord(
            graph_edge_uid=self._next_edge_uid,
            source_entity_uid=source_uid,
            target_entity_uid=target_uid,
            edge_verb=GraphEdgeVerb.TRANSFERRED_CRYPTO_TO.value,
            interaction_count=count,
            total_fiat_value_inr=0.0,
            total_crypto_value_summary=crypto_summary,
            platforms_and_rails_json=json.dumps(chains),
            has_deleted_or_hidden_evidence=0,
            supporting_record_pointers_json=json.dumps(pointers),
            first_interaction_utc_iso=None,
            last_interaction_utc_iso=None,
            platforms_and_rails=chains,
            supporting_record_pointers=pointers,
        )
        self._next_edge_uid += 1
        return edge
