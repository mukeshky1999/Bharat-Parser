"""
Sub-Engine 4.4D: The 4-Way "Rupee-to-USDT" Money Laundering Chain Correlator.
Fuses Phase 3 (UPI & Banking), Phase 4.2 (CEX P2P), and Phase 4.1 (Self-Custody Wallets).
Complies with Section 6 of Phase 4 Module 4.4 Specification.
"""

from datetime import datetime, timezone
import itertools
import json
from typing import Dict, List, Optional

from src.seedhunter.models import (
    LaunderingPattern,
    LaunderingChainRecord,
    Phase3UPIPayment,
    Phase4P2POrder,
    Phase4CryptoWithdrawal,
)


def _parse_iso(iso_str: str) -> Optional[datetime]:
    """Parses an ISO-8601 timestamp string into a timezone-aware UTC datetime."""
    if not iso_str:
        return None
    try:
        clean = iso_str.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


class RupeeToCryptoCorrelator:
    """Master cross-phase correlation engine reconstructing fiat-to-crypto laundering chains."""

    def __init__(self) -> None:
        self.reconstructed_chains: List[LaunderingChainRecord] = []

    def correlate(
        self,
        upi_transactions: List[Phase3UPIPayment],
        p2p_orders: List[Phase4P2POrder],
        withdrawals: List[Phase4CryptoWithdrawal],
        chat_message_refs: Optional[Dict[str, str]] = None,
    ) -> List[LaunderingChainRecord]:
        """
        Correlates Phase 3 UPI debits, Phase 4.2 CEX P2P orders, Phase 4 withdrawals,
        and Phase 5 chat references into end-to-end money laundering chains.
        """
        chains: List[LaunderingChainRecord] = []
        if chat_message_refs is None:
            chat_message_refs = {}

        for order in p2p_orders:
            if order.fiat_currency.upper() != "INR":
                continue

            order_dt = _parse_iso(order.created_utc_iso)
            order_amt = order.fiat_total_amount

            # 1. Gather Candidate Phase 3 UPI Payments
            candidate_upis: List[Phase3UPIPayment] = []
            for upi in upi_transactions:
                upi_dt = _parse_iso(upi.timestamp_utc_iso)
                if order_dt and upi_dt:
                    diff_mins = (upi_dt - order_dt).total_seconds() / 60.0
                    if -30.0 <= diff_mins <= 60.0:
                        candidate_upis.append(upi)
                else:
                    candidate_upis.append(upi)

            matched_upis: List[Phase3UPIPayment] = []
            pattern = LaunderingPattern.SINGLE_UPI_TO_P2P_USDT

            # Tier B: Single-transfer exact match
            for upi in candidate_upis:
                if abs(upi.amount_inr - order_amt) <= 1.0:
                    matched_upis = [upi]
                    pattern = LaunderingPattern.SINGLE_UPI_TO_P2P_USDT
                    break

            # Tier C: Split-UPI Smurfing Subset-Sum Correlator
            if not matched_upis and len(candidate_upis) >= 2:
                for k in range(2, min(6, len(candidate_upis) + 1)):
                    found = False
                    for subset in itertools.combinations(candidate_upis, k):
                        sub_sum = sum(u.amount_inr for u in subset)
                        if abs(sub_sum - order_amt) <= 1.0:
                            matched_upis = list(subset)
                            pattern = LaunderingPattern.SPLIT_UPI_SMURFING_TO_P2P_USDT
                            found = True
                            break
                    if found:
                        break

            if not matched_upis:
                continue

            # 2. Correlate Hop 3: CEX Withdrawal / Pay
            matched_withdrawal: Optional[Phase4CryptoWithdrawal] = None
            p2p_comp_dt = _parse_iso(order.completed_utc_iso) or order_dt
            for w in withdrawals:
                w_dt = _parse_iso(w.timestamp_utc_iso)
                if p2p_comp_dt and w_dt:
                    diff_hours = (w_dt - p2p_comp_dt).total_seconds() / 3600.0
                    if 0.0 <= diff_hours <= 24.0:
                        if abs(w.amount - order.crypto_quantity) <= 10.0 or w.currency == order.crypto_currency:
                            matched_withdrawal = w
                            break
                else:
                    if abs(w.amount - order.crypto_quantity) <= 10.0:
                        matched_withdrawal = w
                        break

            # 3. Hop 4: Self-Custody / Wallet info
            hop4_json = None
            if matched_withdrawal:
                hop4_data = {
                    "destination_address": matched_withdrawal.destination_address,
                    "blockchain_network": matched_withdrawal.blockchain_network,
                    "txid": matched_withdrawal.txid,
                    "matches_local_wallet": matched_withdrawal.matches_local_wallet,
                }
                hop4_json = json.dumps(hop4_data)

            # 4. Hop 5: Chat Confirmation Reference
            chat_ref = chat_message_refs.get(order.order_number)
            if not chat_ref and matched_withdrawal:
                chat_ref = chat_message_refs.get(matched_withdrawal.txid)

            # 5. Timestamps and hop1 JSON
            hop1_descriptions = [
                f"UTR {u.utr_reference} (INR {u.amount_inr:.1f})" for u in matched_upis
            ]
            total_fiat = sum(u.amount_inr for u in matched_upis)
            earliest_dt_str = min(u.timestamp_utc_iso for u in matched_upis)
            completion_dt_str = (
                matched_withdrawal.timestamp_utc_iso
                if matched_withdrawal
                else order.completed_utc_iso
            )

            chain_record = LaunderingChainRecord(
                chain_pattern_classification=pattern,
                hop1_phase3_tx_master_uids_json=json.dumps(hop1_descriptions),
                hop1_total_fiat_outflow_inr=total_fiat,
                hop2_cex_p2p_order_uid=order.p2p_order_uid,
                hop2_acquired_crypto_amount=f"{order.crypto_quantity:.2f} {order.crypto_currency} ({order.exchange_name} P2P Order #{order.order_number})",
                hop3_cex_withdrawal_or_pay_uid=matched_withdrawal.transfer_uid if matched_withdrawal else None,
                hop4_self_custody_or_swap_json=hop4_json,
                hop5_chat_confirmation_msg_uid=chat_ref,
                chain_start_utc_iso=earliest_dt_str,
                chain_completion_utc_iso=completion_dt_str,
            )
            chains.append(chain_record)

        self.reconstructed_chains.extend(chains)
        return chains
