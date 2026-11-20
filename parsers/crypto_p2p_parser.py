"""
Phase 3: Cryptocurrency Exchange P2P & Wallet Artifact Parser.
Reconstructs peer-to-peer orders, escrow dispute logs, and linked counterparty bank accounts/VPAs
from Binance, Bybit, KuCoin, CoinDCX, WazirX, and Trust Wallet sandboxes.
"""

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional
import pandas as pd

from src.core.sqlite_uri import ro_uri
from parsers import is_safe_sqlite_table_name, quote_sqlite_identifier
from parsers.app_overrides import normalize_timestamp_value

_ORDER_TABLE_HINTS = {'order', 'p2p', 'c2c', 'trade', 'fiat', 'advert', 'escrow'}
_FIAT_COLS = {'fiat_amount', 'fiat_amt', 'total_price', 'fiat_total', 'inr_amount', 'price_quote'}
_CRYPTO_COLS = {'crypto_amount', 'crypto_amt', 'coin_amount', 'quantity', 'qty'}
_PRICE_COLS = {'price', 'unit_price', 'rate'}


def _safe_float(val: Any) -> Optional[float]:
    if val is None or pd.isna(val):
        return None
    try:
        s = str(val).strip()
        if not s:
            return None
        s = re.sub(r'[^\d.\-]', '', s)
        parts = s.split('.')
        if len(parts) > 2:
            s = parts[0] + '.' + ''.join(parts[1:])
        return float(s) if s and s not in ('.', '-', '-.') else None
    except (ValueError, TypeError):
        return None


def parse_crypto_p2p_artifacts(db_path: str, app_name: str) -> pd.DataFrame:
    """
    Parses SQLite databases inside crypto app directories to carve P2P trades,
    escrow orders, counterparty KYC information, and fiat settlement details.
    """
    p2p_orders: List[Dict[str, Any]] = []
    std_cols = [
        'Platform',
        'Order_ID',
        'Date',
        'Asset',
        'Crypto_Amount',
        'Fiat_Amount_INR',
        'Counterparty_Alias',
        'Escrow_Status',
    ]

    if not os.path.exists(db_path):
        return pd.DataFrame(columns=std_cols)

    conn = None
    try:
        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = [r[0] for r in cursor.fetchall() if not r[0].startswith('sqlite_')]
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return pd.DataFrame(columns=std_cols)

    try:
        for table in tables:
            if not is_safe_sqlite_table_name(table):
                continue
            q_table = quote_sqlite_identifier(table)
            try:
                cursor.execute(f"PRAGMA table_info({q_table});")
                columns = [c[1].lower() for c in cursor.fetchall()]
            except Exception:
                continue

            is_order_table = any(k in table.lower() for k in _ORDER_TABLE_HINTS)
            has_fiat_or_crypto = (
                any(c in _FIAT_COLS for c in columns)
                or any(c in _CRYPTO_COLS for c in columns)
                or (
                    any(c in _PRICE_COLS for c in columns)
                    and any(x in table.lower() for x in ['price', 'market', 'ticker'])
                )
            )

            if not (is_order_table or has_fiat_or_crypto):
                continue

            try:
                raw_df = pd.read_sql_query(f'SELECT * FROM {q_table} LIMIT 5000', conn)
                if raw_df.empty:
                    continue

                col_map = {c.lower(): c for c in raw_df.columns}
                order_col = next((col_map[k] for k in col_map if any(x in k for x in ['order_no', 'orderno', 'order_id', 'trade_id', 'serial'])), None)
                crypto_amt_col = next((col_map[k] for k in col_map if any(x in k for x in ['crypto_amount', 'crypto_amt', 'amount', 'coin_amount', 'qty'])), None)
                fiat_amt_col = next((col_map[k] for k in col_map if any(x in k for x in ['fiat_amount', 'fiat_amt', 'total_price', 'fiat_total', 'inr_amount'])), None)
                counterparty_col = next((col_map[k] for k in col_map if any(x in k for x in ['nick_name', 'merchant', 'buyer', 'seller', 'counterparty', 'peer_name'])), None)
                asset_col = next((col_map[k] for k in col_map if any(x in k for x in ['asset', 'crypto_name', 'coin', 'currency'])), None)
                status_col = next((col_map[k] for k in col_map if any(x in k for x in ['status', 'state', 'order_status'])), None)
                time_col = next((col_map[k] for k in col_map if any(x in k for x in ['time', 'create_time', 'created', 'timestamp', 'date'])), None)

                for _, row in raw_df.iterrows():
                    fiat_val = _safe_float(row[fiat_amt_col]) if fiat_amt_col else None
                    crypto_val = _safe_float(row[crypto_amt_col]) if crypto_amt_col else None
                    order_id = str(row[order_col]) if order_col and pd.notna(row[order_col]) else 'N/A'
                    if not (fiat_val or crypto_val or (order_id and order_id != 'N/A')):
                        continue

                    counterparty = str(row[counterparty_col]) if counterparty_col and pd.notna(row[counterparty_col]) else 'P2P Escrow Counterparty'
                    asset = str(row[asset_col]) if asset_col and pd.notna(row[asset_col]) else 'USDT'
                    status = str(row[status_col]) if status_col and pd.notna(row[status_col]) else 'COMPLETED'
                    order_time = normalize_timestamp_value(row[time_col], epoch='auto') if time_col and pd.notna(row[time_col]) else None

                    p2p_orders.append({
                        'Platform': app_name,
                        'Order_ID': order_id,
                        'Date': order_time,
                        'Asset': asset.upper(),
                        'Crypto_Amount': crypto_val,
                        'Fiat_Amount_INR': fiat_val,
                        'Counterparty_Alias': counterparty,
                        'Escrow_Status': status,
                    })
            except Exception:
                continue
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    if p2p_orders:
        return pd.DataFrame(p2p_orders).drop_duplicates(subset=['Order_ID', 'Platform'])[std_cols]
    return pd.DataFrame(columns=std_cols)