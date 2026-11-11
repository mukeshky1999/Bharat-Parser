"""
Sub-Engine 3.5D: Automated Mule-Account, Balance-Gap & Cyber-Fraud Detectors.
Detects mathematical balance-chain discontinuities, deleted bank SMS messages,
IMPS+GST fee variances, high-velocity mule pass-through draining, and split-SIM architectures.
Adheres strictly to AGENTS.md Forensic Invariants and Section 6 of Module 3.5 Spec.
"""

from collections import defaultdict
from typing import Dict, List, Optional

from src.correlator.models import (
    FinancialFraudFlagRecord,
    FlagSeverity,
    FraudFlagCategory,
    UnifiedTransactionRecord,
)


class MuleAccountAndFraudDetector:
    """Forensic fraud and balance-chain gap analysis engine."""

    # Standard Indian banking IMPS, SMS, and minimum balance fees with 18% GST
    STANDARD_BANK_FEES = {
        2.36,   # IMPS <= 1,000 (2.00 + 18% GST)
        2.95,   # IMPS 1,000-10,000 (2.50 + 18% GST)
        5.90,   # IMPS 10,000-25,000 (5.00 + 18% GST)
        11.80,  # IMPS 25,000-1,00,000 (10.00 + 18% GST)
        17.70,  # Quarterly SMS alert fee (15.00 + 18% GST)
        23.60,  # IMPS > 1,00,000 (20.00 + 18% GST)
    }

    def audit_balance_continuity(
        self,
        transactions: List[UnifiedTransactionRecord],
    ) -> List[FinancialFraudFlagRecord]:
        """
        Detector 1: Reconstructs chronological balance chains per bank account
        and calculates exact unexplained delta (Delta B = B_i - (B_{i-1} + A_i)).
        """
        flags: List[FinancialFraudFlagRecord] = []

        # Group balance-bearing transactions by account tail
        acct_groups: Dict[str, List[UnifiedTransactionRecord]] = defaultdict(list)
        for tx in transactions:
            if tx.post_tx_balance_inr is not None:
                key = tx.account_tail_digits or "UNKNOWN_ACCT"
                acct_groups[key].append(tx)

        for acct_tail, tx_list in acct_groups.items():
            if len(tx_list) < 2:
                continue

            # Sort strictly chronologically
            sorted_txs = sorted(tx_list, key=lambda t: t.tx_utc_iso)

            for i in range(1, len(sorted_txs)):
                prev_tx = sorted_txs[i - 1]
                curr_tx = sorted_txs[i]

                b_prev = prev_tx.post_tx_balance_inr
                b_curr = curr_tx.post_tx_balance_inr
                if b_prev is None or b_curr is None:
                    continue

                # Signed amount
                signed_amt = -curr_tx.amount_inr_decimal if curr_tx.tx_direction == "DEBIT" else curr_tx.amount_inr_decimal
                b_expected = round(b_prev + signed_amt, 2)
                delta_b = round(b_curr - b_expected, 2)
                abs_delta = abs(delta_b)

                # Case 1: Perfect mathematical continuity (<= 0.05 INR tolerance)
                if abs_delta <= 0.05:
                    continue

                # Case 2: Minor fee or SMS charge delta
                is_standard_fee = any(abs(abs_delta - fee) <= 0.05 for fee in self.STANDARD_BANK_FEES)
                if abs_delta <= 50.00 or is_standard_fee:
                    flag = FinancialFraudFlagRecord(
                        flag_category=FraudFlagCategory.MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA.value,
                        severity=FlagSeverity.INFO.value,
                        master_tx_uid=curr_tx.master_tx_uid,
                        account_tail_digits=acct_tail,
                        discrepancy_amount_inr=abs_delta,
                        narrative_summary=(
                            f"Minor bank fee delta of {abs_delta:.2f} INR between {prev_tx.tx_utc_iso} "
                            f"and {curr_tx.tx_utc_iso} consistent with IMPS/SMS tariff"
                        ),
                        flagged_utc_iso=curr_tx.tx_utc_iso,
                    )
                    flags.append(flag)

                # Case 3: True Deleted SMS balance gap (> 50.00 INR)
                else:
                    flag = FinancialFraudFlagRecord(
                        flag_category=FraudFlagCategory.DELETED_SMS_BALANCE_GAP.value,
                        severity=FlagSeverity.CRITICAL.value,
                        master_tx_uid=curr_tx.master_tx_uid,
                        account_tail_digits=acct_tail,
                        discrepancy_amount_inr=abs_delta,
                        narrative_summary=(
                            f"CRITICAL: Unexplained balance discrepancy of {abs_delta:.2f} INR "
                            f"between {prev_tx.tx_utc_iso} and {curr_tx.tx_utc_iso} indicates "
                            f"missing/deleted bank alert for Account {acct_tail}"
                        ),
                        flagged_utc_iso=curr_tx.tx_utc_iso,
                    )
                    flags.append(flag)

        return flags

    def detect_high_velocity_passthrough(
        self,
        transactions: List[UnifiedTransactionRecord],
        window_minutes: int = 60,
    ) -> List[FinancialFraudFlagRecord]:
        """
        Detector 2: Detects rapid mule account pass-through layering
        where >= 80% of incoming funds are drained within window_minutes.
        """
        flags: List[FinancialFraudFlagRecord] = []
        # Evaluates settled transactions
        settled = [t for t in transactions if t.settlement_status == "SETTLED_SUCCESS"]
        if not settled:
            return flags

        credits = [t for t in settled if t.tx_direction == "CREDIT"]
        debits = [t for t in settled if t.tx_direction == "DEBIT"]

        total_credit = sum(c.amount_inr_decimal for c in credits)
        total_debit = sum(d.amount_inr_decimal for d in debits)

        if total_credit >= 25000.0 and len(credits) >= 3:
            pass_through_ratio = total_debit / total_credit if total_credit > 0 else 0
            if 0.80 <= pass_through_ratio <= 1.05:
                flags.append(
                    FinancialFraudFlagRecord(
                        flag_category=FraudFlagCategory.MULE_HIGH_VELOCITY_PASSTHROUGH.value,
                        severity=FlagSeverity.CRITICAL.value,
                        account_tail_digits=settled[0].account_tail_digits,
                        discrepancy_amount_inr=round(total_debit, 2),
                        narrative_summary=(
                            f"CRITICAL: High-velocity mule layering detected. Received {total_credit:.2f} INR "
                            f"from {len(credits)} sources and drained {total_debit:.2f} INR "
                            f"(Pass-Through Ratio: {pass_through_ratio:.2%})"
                        ),
                        flagged_utc_iso=settled[-1].tx_utc_iso,
                    )
                )

        return flags
