"""
Phase 3: Fiat-to-Crypto Temporal Alignment & Layering Bridge.
Correlates domestic UPI/IMPS INR debits with cryptocurrency P2P escrow orders
and on-chain movements to prove cash-to-digital-asset layering.
"""

from typing import Any, Dict, List
import pandas as pd


def align_fiat_to_crypto(
    upi_timeline: pd.DataFrame,
    p2p_orders: pd.DataFrame,
    window_minutes: int = 45,
    amount_tolerance_pct: float = 8.0,
) -> pd.DataFrame:
    """
    Correlates UPI debits with crypto P2P orders using temporal proximity and monetary value.

    Criteria:
    1. UPI Debit occurred within [-window_minutes, +window_minutes] of P2P Order creation.
    2. Fiat amount in INR matches within amount_tolerance_pct (accounting for merchant P2P premiums).

    Vectorised implementation (merge + filter) instead of O(n*m) nested loops.
    """
    output_cols = [
        'Alignment_Confidence',
        'UPI_Transaction_ID',
        'UPI_Debit_Time',
        'UPI_Amount_INR',
        'UPI_Counterparty_VPA',
        'Crypto_Platform',
        'P2P_Order_ID',
        'P2P_Order_Time',
        'Crypto_Asset_Acquired',
        'Crypto_Amount',
        'P2P_Counterparty',
        'Time_Delta_Minutes',
        'Evidentiary_Insight',
    ]

    if upi_timeline.empty or p2p_orders.empty:
        return pd.DataFrame(columns=output_cols)

    if ('Type' not in upi_timeline.columns
            or 'Date' not in upi_timeline.columns
            or 'Amount' not in upi_timeline.columns):
        return pd.DataFrame(columns=output_cols)

    # Ensure expected columns exist in inputs
    for c in ['Type', 'Date', 'Amount', 'Transaction_ID', 'Counterparty']:
        if c not in upi_timeline.columns:
            upi_timeline = upi_timeline.copy()
            upi_timeline[c] = 'DEBIT' if c == 'Type' else ('N/A' if c in ('Transaction_ID', 'Counterparty') else None)

    for c in ['Date', 'Fiat_Amount_INR', 'Platform', 'Order_ID', 'Asset', 'Crypto_Amount', 'Counterparty_Alias']:
        if c not in p2p_orders.columns:
            p2p_orders = p2p_orders.copy()
            p2p_orders[c] = 'USDT' if c == 'Asset' else ('Unknown' if c in ('Platform', 'Counterparty_Alias') else None)

    upi_debits = upi_timeline[upi_timeline['Type'] == 'DEBIT'].copy()
    if upi_debits.empty:
        return pd.DataFrame(columns=output_cols)

    upi_debits['Parsed_Time'] = pd.to_datetime(upi_debits['Date'], errors='coerce')
    upi_debits = upi_debits.dropna(subset=['Parsed_Time', 'Amount'])
    if upi_debits.empty:
        return pd.DataFrame(columns=output_cols)

    p2p_valid = p2p_orders.copy()
    p2p_valid['Parsed_Time'] = pd.to_datetime(p2p_valid['Date'], errors='coerce')
    p2p_valid = p2p_valid.dropna(subset=['Parsed_Time'])
    if p2p_valid.empty:
        return pd.DataFrame(columns=output_cols)

    # --- Build slim frames for the cross-product merge ---
    upi_small = upi_debits[
        ['Parsed_Time', 'Amount', 'Transaction_ID', 'Date', 'Counterparty']
    ].rename(
        columns={
            'Parsed_Time': 'UPI_Time',
            'Amount': 'UPI_Amount_INR',
            'Date': 'UPI_Debit_Time',
            'Counterparty': 'UPI_Counterparty_VPA',
            'Transaction_ID': 'UPI_Transaction_ID',
        }
    )

    p2p_small = p2p_valid[
        ['Parsed_Time', 'Fiat_Amount_INR', 'Platform', 'Order_ID',
         'Date', 'Asset', 'Crypto_Amount', 'Counterparty_Alias']
    ].rename(
        columns={
            'Parsed_Time': 'P2P_Time',
            'Date': 'P2P_Order_Time',
            'Platform': 'Crypto_Platform',
            'Order_ID': 'P2P_Order_ID',
            'Asset': 'Crypto_Asset_Acquired',
            'Counterparty_Alias': 'P2P_Counterparty',
        }
    )

    # Guard against Cartesian explosion
    if len(upi_small) * len(p2p_small) > 500000:
        upi_small = upi_small.tail(2000)
        p2p_small = p2p_small.tail(250)

    # Cartesian join via a dummy key
    upi_small['_join'] = 1
    p2p_small['_join'] = 1
    merged = upi_small.merge(p2p_small, on='_join').drop(columns='_join')

    # Time delta in minutes
    merged['Time_Delta_Minutes'] = (
        (merged['P2P_Time'] - merged['UPI_Time']).abs().dt.total_seconds() / 60.0
    )
    merged = merged[merged['Time_Delta_Minutes'] <= window_minutes].copy()
    if merged.empty:
        return pd.DataFrame(columns=output_cols)

    # --- Confidence assignment (matches original semantics) ---
    def _confidence(row):
        delta = row['Time_Delta_Minutes']
        upi_amt = row['UPI_Amount_INR']
        p2p_amt = row['Fiat_Amount_INR']
        if pd.notna(p2p_amt) and p2p_amt > 0 and pd.notna(upi_amt) and upi_amt > 0:
            pct = (abs(upi_amt - p2p_amt) / upi_amt) * 100.0
            if pct <= amount_tolerance_pct:
                return (
                    'HIGH (Direct Fiat-to-USDT Conversion)'
                    if delta <= 15 else 'HIGH (Value & Time Match)'
                )
            if pct <= 20.0:
                return 'MEDIUM (Split Escrow / Partial Order)'
            return None
        return 'LOW-MEDIUM (Temporal Proximity Only)'

    merged['Alignment_Confidence'] = merged.apply(_confidence, axis=1)

    # Retain row if: amount matched (confidence set) OR within tight 20-minute window.
    retain_mask = (
        merged['Alignment_Confidence'].notna()
        | (merged['Time_Delta_Minutes'] <= 20)
    )
    merged = merged[retain_mask].copy()

    # Temporal-only rows that failed the confidence check become MEDIUM (Temporal Match)
    merged.loc[
        merged['Alignment_Confidence'].isna(), 'Alignment_Confidence'
    ] = 'MEDIUM (Temporal Match)'

    # --- Evidentiary narrative ---
    def _build_insight(r):
        upi_val = r['UPI_Amount_INR']
        amt_str = f"₹{upi_val:,.2f}" if pd.notna(upi_val) else "₹0.00"
        return (
            f"UPI Debit of {amt_str} aligned with "
            f"{r['Crypto_Platform']} P2P order "
            f"({r['Crypto_Amount']} {r['Crypto_Asset_Acquired']}) within "
            f"{round(r['Time_Delta_Minutes'], 1)} minutes."
        )

    merged['Evidentiary_Insight'] = merged.apply(_build_insight, axis=1)

    merged['Time_Delta_Minutes'] = merged['Time_Delta_Minutes'].round(1)
    merged['UPI_Debit_Time'] = merged['UPI_Debit_Time'].astype(str)
    merged['P2P_Order_Time'] = merged['P2P_Order_Time'].astype(str)

    return (
        merged[output_cols]
        .sort_values(by='Time_Delta_Minutes', ascending=True)
        .reset_index(drop=True)
    )


def align_bank_to_custodial_onramp(
    bank_or_upi_df: pd.DataFrame,
    custodial_wallet_records: pd.DataFrame,
    window_minutes: int = 60,
    amount_tolerance_pct: float = 8.0,
) -> pd.DataFrame:
    """
    Correlates domestic Bank or UPI debits with custodial wallet FIAT_ONRAMP records
    (e.g., INR deposits/buys on Coinbase, Crypto.com, Bitget, MEXC).

    Returns a normalized DataFrame proving money flow from fiat banking into digital asset exchanges.
    """
    output_cols = [
        'Alignment_Confidence',
        'Bank_Transaction_ID',
        'Bank_Debit_Time',
        'Bank_Amount_INR',
        'Wallet_App',
        'Order_ID',
        'Onramp_Time_UTC',
        'Crypto_Asset_Acquired',
        'Crypto_Amount',
        'INR_Rate_At_Tx',
        'Time_Delta_Minutes',
        'Evidentiary_Insight',
    ]

    if bank_or_upi_df.empty or custodial_wallet_records.empty:
        return pd.DataFrame(columns=output_cols)

    # 1. Filter fiat debits from bank statement or master UPI timeline
    b_df = bank_or_upi_df.copy()
    if 'Type' in b_df.columns:
        debits = b_df[b_df['Type'].astype(str).str.upper() == 'DEBIT'].copy()
        debits['Debit_Amt'] = pd.to_numeric(debits.get('Amount'), errors='coerce')
        debits['Tx_ID'] = debits.get('Transaction_ID', '')
        debits['Tx_Time_Raw'] = debits.get('Date', '')
    elif 'Debit' in b_df.columns:
        debits = b_df[pd.to_numeric(b_df['Debit'], errors='coerce') > 0].copy()
        debits['Debit_Amt'] = pd.to_numeric(debits['Debit'], errors='coerce')
        debits['Tx_ID'] = debits.get('Ref_UTR', '')
        debits['Tx_Time_Raw'] = debits.get('Date', '')
    else:
        debits = pd.DataFrame()

    if debits.empty:
        return pd.DataFrame(columns=output_cols)

    debits['Parsed_Time'] = pd.to_datetime(debits['Tx_Time_Raw'], errors='coerce', utc=True)
    debits = debits.dropna(subset=['Parsed_Time', 'Debit_Amt'])
    if debits.empty:
        return pd.DataFrame(columns=output_cols)

    # 2. Filter FIAT_ONRAMP records from custodial wallet records
    cw = custodial_wallet_records.copy()
    mask = (
        cw.get('Data_Class', pd.Series(dtype=str)).astype(str).str.upper().isin(['FIAT_ONRAMP', 'DEPOSIT'])
        | cw.get('Direction', pd.Series(dtype=str)).astype(str).str.upper().isin(['FIAT_ONRAMP'])
    )
    onramps = cw[mask].copy()
    if onramps.empty:
        return pd.DataFrame(columns=output_cols)

    onramps['Amount_INR_Num'] = pd.to_numeric(onramps.get('Amount_INR'), errors='coerce')
    onramps['Parsed_Time'] = pd.to_datetime(onramps.get('Timestamp_UTC'), errors='coerce', utc=True)
    onramps = onramps.dropna(subset=['Parsed_Time'])
    if onramps.empty:
        return pd.DataFrame(columns=output_cols)

    # 3. Vectorized cartesian join with size cap
    b_slim = debits[['Parsed_Time', 'Debit_Amt', 'Tx_ID', 'Tx_Time_Raw']].copy()
    c_cols = ['Parsed_Time', 'Amount_INR_Num', 'Wallet_App', 'Order_ID', 'Timestamp_UTC', 'Asset', 'Amount_Crypto', 'INR_Rate_At_Tx']
    for cc in c_cols:
        if cc not in onramps.columns:
            onramps[cc] = None
    c_slim = onramps[c_cols].copy()

    if len(b_slim) * len(c_slim) > 500000:
        b_slim = b_slim.tail(2000)
        c_slim = c_slim.tail(250)

    b_slim['_k'] = 1
    c_slim['_k'] = 1
    m = b_slim.merge(c_slim, on='_k').drop(columns='_k')

    m['Time_Delta_Minutes'] = (m['Parsed_Time_y'] - m['Parsed_Time_x']).abs().dt.total_seconds() / 60.0
    m = m[m['Time_Delta_Minutes'] <= window_minutes].copy()
    if m.empty:
        return pd.DataFrame(columns=output_cols)

    def _conf(row):
        delta = row['Time_Delta_Minutes']
        b_amt = row['Debit_Amt']
        c_amt = row['Amount_INR_Num']
        if pd.notna(c_amt) and c_amt > 0 and pd.notna(b_amt) and b_amt > 0:
            pct = (abs(b_amt - c_amt) / b_amt) * 100.0
            if pct <= amount_tolerance_pct:
                return 'HIGH (Direct Fiat On-Ramp Conversion)' if delta <= 15 else 'HIGH (Value & Time Match)'
            if pct <= 20.0:
                return 'MEDIUM (Fee-Adjusted / Partial On-Ramp)'
        return 'LOW-MEDIUM (Temporal Proximity Match)'

    m['Alignment_Confidence'] = m.apply(_conf, axis=1)

    def _narrative(row):
        b_val = row['Debit_Amt']
        amt_str = f"₹{b_val:,.2f}" if pd.notna(b_val) else "₹0.00"
        c_asset = row.get('Asset') or 'Crypto'
        c_amt = row.get('Amount_Crypto')
        c_str = f" ({c_amt} {c_asset})" if pd.notna(c_amt) and c_amt else ""
        return (
            f"Fiat Debit of {amt_str} aligned with {row.get('Wallet_App', 'Exchange')} "
            f"on-ramp order{c_str} within {round(row['Time_Delta_Minutes'], 1)} minutes."
        )

    m['Evidentiary_Insight'] = m.apply(_narrative, axis=1)

    m = m.rename(columns={
        'Tx_ID': 'Bank_Transaction_ID',
        'Tx_Time_Raw': 'Bank_Debit_Time',
        'Debit_Amt': 'Bank_Amount_INR',
        'Timestamp_UTC': 'Onramp_Time_UTC',
        'Asset': 'Crypto_Asset_Acquired',
        'Amount_Crypto': 'Crypto_Amount',
    })

    for c in output_cols:
        if c not in m.columns:
            m[c] = None

    return m[output_cols].sort_values(by='Time_Delta_Minutes', ascending=True).reset_index(drop=True)
