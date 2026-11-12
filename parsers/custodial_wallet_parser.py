"""
parsers/custodial_wallet_parser.py (v2.0 — 15 wallets)

Custodial + hybrid crypto wallet forensic extractor.

Tier 1 (10): Coinbase, Crypto.com, Bitget, MEXC, Gate.io, Kraken, Nexo,
             Bitstamp, Blockchain.com, Bitget Wallet
Tier 2 (5):  YouHodler, BitMart, HTX, Giottus, Mudrex

Seven data classes + fiat orders, extracted with:
  - 100% read-only SQLite (?mode=ro)
  - Schema-agnostic content classification fallback
  - Per-wallet schema overrides where confident
  - Provenance tagging (delegated to wallet_provenance)
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

try:
    from fs_handler import _log_forensic_error
except Exception:  # pragma: no cover
    def _log_forensic_error(context, err):
        logging.getLogger("parsers.wallet").warning("Forensic error in %s: %s", context, err)


# ═══════════════════════════════════════════════════════════════════════════
# Wallet signatures — all 15 wallets
# ═══════════════════════════════════════════════════════════════════════════

WALLET_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ─── Tier 1 ────────────────────────────────────────────────────────────
    "Coinbase": {
        "tier": 1,
        "package_android": "com.coinbase.android",
        "bundle_ios": "com.coinbase.consumer",
        "db_patterns": ["coinbase.db", "consumer.db", "wallet.db", "transactions.db"],
        "kyc_tables":     ["user_profile", "profile", "kyc", "account_user"],
        "address_tables": ["wallet_accounts", "chain_accounts", "addresses", "accounts"],
        "tx_tables":      ["transactions", "wallet_transactions", "activity", "transfers"],
        "recipient_tables": ["address_book", "saved_addresses", "beneficiaries"],
        "fiat_tables":    ["buys", "sells", "fiat_orders", "purchases", "trades"],
        "earn_tables":    ["staking", "earn", "rewards", "stakes"],
        "holdings_tables": ["balances", "holdings", "wallet_balances", "portfolio"],
    },
    "Crypto.com": {
        "tier": 1,
        "package_android": "co.mona.android",
        "bundle_ios": "co.mona.Mona",
        "db_patterns": ["cryptocom.db", "mona.db", "wallet.db"],
        "kyc_tables":     ["kyc_data", "user_info", "profile"],
        "address_tables": ["wallet_addresses", "crypto_accounts"],
        "tx_tables":      ["transactions", "wallet_tx", "activity"],
        "recipient_tables": ["address_book", "external_addresses"],
        "fiat_tables":    ["fiat_deposits", "fiat_withdrawals", "purchases"],
        "earn_tables":    ["earn", "stake", "card_cashback"],
        "holdings_tables": ["balances", "holdings"],
    },
    "Bitget": {
        "tier": 1,
        "package_android": "com.bitget.exchange",
        "bundle_ios": "com.bitget.exchange",
        "db_patterns": ["bitget.db", "wallet.db"],
        "kyc_tables":     ["kyc", "user_kyc", "profile"],
        "address_tables": ["deposit_addresses", "withdraw_addresses", "wallet_addresses"],
        "tx_tables":      ["transactions", "wallet_transactions", "p2p_orders"],
        "recipient_tables": ["address_book", "beneficiaries"],
        "fiat_tables":    ["p2p_orders", "fiat_orders"],
        "earn_tables":    ["earn", "staking"],
        "holdings_tables": ["balances", "assets"],
    },
    "MEXC": {
        "tier": 1,
        "package_android": "com.mexcpro.client",
        "bundle_ios": "com.mexc.exchange",
        "db_patterns": ["mexc.db", "wallet.db"],
        "kyc_tables":     ["kyc_info", "user_profile"],
        "address_tables": ["deposit_address", "withdraw_address"],
        "tx_tables":      ["orders", "transactions", "p2p_orders"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["p2p_orders", "fiat_orders"],
        "earn_tables":    ["earn", "staking"],
        "holdings_tables": ["balances", "assets"],
    },
    "Gate.io": {
        "tier": 1,
        "package_android": "io.gate.gateapp",
        "bundle_ios": "io.gate.gateapp",
        "db_patterns": ["gate.db", "gateio.db", "wallet.db"],
        "kyc_tables":     ["kyc", "user_info"],
        "address_tables": ["deposit_address", "withdraw_address"],
        "tx_tables":      ["orders", "transactions", "wallet_tx"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["p2p_orders", "fiat_orders"],
        "earn_tables":    ["earn", "staking", "lending"],
        "holdings_tables": ["balances", "spot_balances"],
    },
    "Kraken": {
        "tier": 1,
        "package_android": "com.kraken.invest.app",
        "bundle_ios": "com.kraken.invest.app",
        "db_patterns": ["kraken.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["deposit_methods", "addresses"],
        "tx_tables":      ["ledger", "trades", "transactions"],
        "recipient_tables": ["withdrawal_addresses", "address_book"],
        "fiat_tables":    ["deposits", "withdrawals", "fiat_orders"],
        "earn_tables":    ["staking", "earn"],
        "holdings_tables": ["balances", "wallet_balances"],
    },
    "Nexo": {
        "tier": 1,
        "package_android": "com.nexowallet",
        "bundle_ios": "com.nexo.mobile",
        "db_patterns": ["nexo.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["wallet_addresses", "deposit_addresses"],
        "tx_tables":      ["transactions", "wallet_transactions"],
        "recipient_tables": ["saved_addresses", "beneficiaries"],
        "fiat_tables":    ["deposits", "withdrawals"],
        "earn_tables":    ["earn", "savings", "loans"],
        "holdings_tables": ["balances", "portfolio"],
    },
    "Bitstamp": {
        "tier": 1,
        "package_android": "net.bitstamp.app",
        "bundle_ios": "net.bitstamp.app",
        "db_patterns": ["bitstamp.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["deposit_addresses", "withdrawal_addresses"],
        "tx_tables":      ["transactions", "trades", "wallet_tx"],
        "recipient_tables": ["address_book", "beneficiaries"],
        "fiat_tables":    ["fiat_deposits", "fiat_withdrawals"],
        "earn_tables":    ["staking", "earn"],
        "holdings_tables": ["balances", "portfolio"],
    },
    "Blockchain.com": {
        "tier": 1,
        "package_android": "com.blockchainvault",
        "bundle_ios": "com.blockchainvault",
        "db_patterns": ["blockchain.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile", "user"],
        "address_tables": ["accounts", "addresses", "wallets"],
        "tx_tables":      ["txs", "transactions", "tx_history"],
        "recipient_tables": ["address_book", "contacts"],
        "fiat_tables":    ["fiat_orders", "buys", "sells"],
        "earn_tables":    ["earn", "interest"],
        "holdings_tables": ["balances", "wallet_balances"],
    },
    "Bitget Wallet": {
        "tier": 1,
        "package_android": "com.bitkeep.wallet",
        "bundle_ios": "com.bitkeep.wallet",
        "db_patterns": ["bitkeep.db", "wallet.db", "bkwallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["wallets", "addresses", "accounts"],
        "tx_tables":      ["txs", "transactions", "wallet_history"],
        "recipient_tables": ["address_book", "contacts"],
        "fiat_tables":    ["fiat_orders", "buys", "sells"],
        "earn_tables":    ["earn", "staking", "defi"],
        "holdings_tables": ["balances", "wallet_balances", "tokens"],
    },

    # ─── Tier 2 ────────────────────────────────────────────────────────────
    "YouHodler": {
        "tier": 2,
        "package_android": "com.youhodler.youhodler",
        "bundle_ios": "com.youhodler.youhodler",
        "db_patterns": ["youhodler.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["wallet_addresses"],
        "tx_tables":      ["transactions", "wallet_transactions"],
        "recipient_tables": ["saved_addresses"],
        "fiat_tables":    ["deposits", "withdrawals"],
        "earn_tables":    ["earn", "loans", "savings"],
        "holdings_tables": ["balances"],
    },
    "BitMart": {
        "tier": 2,
        "package_android": "com.bitmart.exchange",
        "bundle_ios": "com.bitmart.exchange",
        "db_patterns": ["bitmart.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["deposit_address", "withdraw_address"],
        "tx_tables":      ["orders", "transactions", "p2p_orders"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["p2p_orders", "fiat_orders"],
        "earn_tables":    ["earn", "staking"],
        "holdings_tables": ["balances"],
    },
    "HTX": {
        "tier": 2,
        "package_android": "com.huobi.app",
        "bundle_ios": "com.huobi.app",
        "db_patterns": ["huobi.db", "htx.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["deposit_address", "withdraw_address"],
        "tx_tables":      ["orders", "transactions", "p2p_orders"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["p2p_orders", "fiat_orders"],
        "earn_tables":    ["earn", "staking"],
        "holdings_tables": ["balances"],
    },
    "Giottus": {
        "tier": 2,
        "package_android": "com.giottus",
        "bundle_ios": "com.giottus",
        "db_patterns": ["giottus.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["wallet_addresses", "addresses"],
        "tx_tables":      ["transactions", "wallet_transactions"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["fiat_orders", "deposits", "withdrawals"],
        "earn_tables":    ["earn", "staking"],
        "holdings_tables": ["balances"],
    },
    "Mudrex": {
        "tier": 2,
        "package_android": "com.mudrex",
        "bundle_ios": "com.mudrex",
        "db_patterns": ["mudrex.db", "wallet.db"],
        "kyc_tables":     ["kyc", "profile"],
        "address_tables": ["wallet_addresses"],
        "tx_tables":      ["transactions", "investments"],
        "recipient_tables": ["address_book"],
        "fiat_tables":    ["fiat_orders", "deposits"],
        "earn_tables":    ["earn", "investments"],
        "holdings_tables": ["balances", "portfolio"],
    },
}

DEFAULT_TABLE_HINTS: Dict[str, List[str]] = {
    "kyc_tables":     ["kyc", "profile", "user"],
    "address_tables": ["address", "wallet_account", "chain_account"],
    "tx_tables":      ["transaction", "activity", "transfer"],
    "recipient_tables": ["address_book", "beneficiar", "saved_addr", "contact"],
    "fiat_tables":    ["buy", "sell", "fiat", "purchase", "order"],
    "earn_tables":    ["earn", "stak", "reward", "loan"],
    "holdings_tables": ["balance", "holding", "portfolio", "asset"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Chain detection (extended with bech32, TON, more)
# ═══════════════════════════════════════════════════════════════════════════

_EVM_RE     = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TRX_RE     = re.compile(r"^T[a-zA-HJ-NP-Z1-9]{33}$")
_BTC_LEG    = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BTC_BECH   = re.compile(r"^(bc1|tb1)[a-z0-9]{25,90}$")
_LTC_BECH   = re.compile(r"^ltc1[a-z0-9]{25,90}$")
_LTC_LEG    = re.compile(r"^[LM][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_DOGE_RE    = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
_XRP_RE     = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")
_ATOM_RE    = re.compile(r"^cosmos1[a-z0-9]{38,58}$")
_BNB_BEACON = re.compile(r"^bnb1[a-z0-9]{38,58}$")
_ADA_RE     = re.compile(r"^addr1[a-z0-9]{50,110}$")
_XTZ_RE     = re.compile(r"^tz[123][a-zA-Z0-9]{33}$")
_TON_RE     = re.compile(r"^(EQ|UQ|0:)[a-zA-Z0-9_\-]{46,48}$")
_SOL_CAND   = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def detect_chain_from_address(addr: Optional[str]) -> Optional[str]:
    if not addr or not isinstance(addr, str):
        return None
    a = addr.strip()
    if not a:
        return None
    if _EVM_RE.match(a):     return "EVM"
    if _TRX_RE.match(a):     return "TRX"
    if _BTC_BECH.match(a):   return "BTC"
    if _LTC_BECH.match(a):   return "LTC"
    if _BTC_LEG.match(a):    return "BTC"
    if _LTC_LEG.match(a):    return "LTC"
    if _DOGE_RE.match(a):    return "DOGE"
    if _XRP_RE.match(a):     return "XRP"
    if _ATOM_RE.match(a):    return "ATOM"
    if _BNB_BEACON.match(a): return "BNB"
    if _ADA_RE.match(a):     return "ADA"
    if _XTZ_RE.match(a):     return "XTZ"
    if _TON_RE.match(a):     return "TON"
    if _SOL_CAND.match(a):   return "SOL"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# SQLite helpers
# ═══════════════════════════════════════════════════════════════════════════

def _open_ro(db_path: str) -> sqlite3.Connection:
    p = Path(db_path).resolve()
    return sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)


def _safe_tables(conn: sqlite3.Connection) -> List[str]:
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name;"
        )
        return [r[0] for r in cur.fetchall() if isinstance(r[0], str)]
    except sqlite3.DatabaseError as e:
        _log_forensic_error("wallet.list_tables", e)
        return []


def _safe_sample(conn: sqlite3.Connection, table: str, limit: int = 500) -> pd.DataFrame:
    try:
        safe_table = table.replace('"', '""')
        df = pd.read_sql_query(f'SELECT * FROM "{safe_table}" LIMIT {int(limit)}', conn)
        if len(df) >= int(limit):
            total = _safe_rowcount(conn, table)
            if total > len(df):
                # Never truncate silently: the examiner must know rows were not read.
                logging.getLogger("parsers.wallet").warning(
                    "TRUNCATED: table %s has %d rows, only the first %d were read", table, total, len(df))
        return df
    except Exception as e:
        _log_forensic_error(f"wallet.sample.{table}", e)
        return pd.DataFrame()


def _safe_rowcount(conn: sqlite3.Connection, table: str) -> int:
    try:
        safe_table = table.replace('"', '""')
        return int(conn.execute(f'SELECT count(*) FROM "{safe_table}"').fetchone()[0])
    except Exception:
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# Column-content classification
# ═══════════════════════════════════════════════════════════════════════════

def _classify_by_content(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    if df.empty:
        return {}
    n = min(len(df), 200)
    s = df.head(n)

    def first_column_matching(pred) -> Optional[str]:
        for col in s.columns:
            vals = s[col].dropna().astype(str).head(50)
            if len(vals) == 0:
                continue
            hits = sum(1 for v in vals if pred(v))
            min_hits = min(3, len(vals)) if len(vals) < 3 else max(3, int(len(vals) * 0.7))
            if hits >= min_hits:
                return col
        return None

    def is_address(v):
        return detect_chain_from_address(v) is not None

    def is_evm(v):
        return bool(_EVM_RE.match(v))

    def is_tx_hash(v):
        if re.match(r"^0x[a-fA-F0-9]{64}$", v): return True
        if re.match(r"^[a-fA-F0-9]{64}$", v):   return True
        if re.match(r"^[1-9A-HJ-NP-Za-km-z]{86,90}$", v): return True
        return False

    def is_ts_num(v):
        try:
            n = float(v)
        except ValueError:
            return False
        return (1_420_000_000 <= n <= 2_050_000_000
                or 1_420_000_000_000 <= n <= 2_050_000_000_000
                or 400_000_000 <= n <= 1_100_000_000)

    def is_ts_iso(v):
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", v))

    def is_amount(v):
        try:
            n = float(v)
        except ValueError:
            return False
        return 0 < abs(n) < 1e12

    def is_chain_enum(v):
        return v.upper() in {"BTC", "ETH", "TRX", "TRON", "SOL", "SOLANA",
                             "XRP", "ATOM", "ADA", "DOT", "BNB", "MATIC",
                             "POLYGON", "LTC", "DOGE", "BCH", "XTZ", "EVM", "TON"}

    roles = {
        "address":     first_column_matching(is_address),
        "evm_address": first_column_matching(is_evm),
        "tx_hash":     first_column_matching(is_tx_hash),
        "timestamp":   first_column_matching(is_ts_num) or first_column_matching(is_ts_iso),
        "amount":      first_column_matching(is_amount),
        "chain":       first_column_matching(is_chain_enum),
    }

    # Column name fallback heuristic
    col_names_lower = {str(c).lower(): c for c in s.columns}
    if not roles["address"]:
        for k in ("address", "addr", "wallet_address", "deposit_address", "recipient", "to_address", "from_address"):
            if k in col_names_lower:
                roles["address"] = col_names_lower[k]
                break
    if not roles["amount"]:
        for k in ("amount", "balance", "crypto_amount", "value", "native_amount", "quantity"):
            if k in col_names_lower:
                roles["amount"] = col_names_lower[k]
                break
    if not roles["timestamp"]:
        for k in ("created_at", "timestamp", "created", "date", "time", "updated_at", "tx_time"):
            if k in col_names_lower:
                roles["timestamp"] = col_names_lower[k]
                break
    if not roles["tx_hash"]:
        for k in ("tx_hash", "txhash", "network_hash", "hash", "txid", "tx_id", "transaction_hash"):
            if k in col_names_lower:
                roles["tx_hash"] = col_names_lower[k]
                break
    if not roles["chain"]:
        for k in ("chain", "network", "blockchain"):
            if k in col_names_lower:
                roles["chain"] = col_names_lower[k]
                break

    return roles


# ═══════════════════════════════════════════════════════════════════════════
# Timestamp / risk
# ═══════════════════════════════════════════════════════════════════════════

_COCOA_OFFSET = 978_307_200


def _normalize_timestamp(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if re.match(r"^\d{4}-\d{2}-\d{2}", s):
        try:
            return pd.to_datetime(s, utc=True).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None
    try:
        n = float(s)
    except ValueError:
        return None
    try:
        if 1_420_000_000_000 <= n <= 2_050_000_000_000:
            return pd.to_datetime(n, unit="ms", utc=True).strftime("%Y-%m-%dT%H:%M:%SZ")
        if 1_420_000_000 <= n <= 2_050_000_000:
            return pd.to_datetime(n, unit="s", utc=True).strftime("%Y-%m-%dT%H:%M:%SZ")
        if 400_000_000 <= n <= 1_100_000_000:
            return pd.to_datetime(n + _COCOA_OFFSET, unit="s", utc=True).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
    return None


def compute_risk_badge(amount_inr: Optional[float], ts_iso: Optional[str], direction: Optional[str]) -> str:
    if amount_inr is None:
        return "🟢 Normal"
    a = abs(float(amount_inr))
    if direction in ("DEPOSIT", "FIAT_ONRAMP") and 45_000 <= a < 50_000:
        return "🔴 High (Near ₹50k Structuring)"
    if a >= 500_000:
        return "🔴 High (≥ ₹5L Single Tx)"
    if a >= 50_000:
        return "🟡 High Value (≥ ₹50k)"
    if ts_iso:
        try:
            hour = int(ts_iso[11:13])
            if a >= 2_000 and 0 <= hour < 5:
                return "🟡 Odd-Hour (12AM-5AM)"
        except Exception:
            pass
    return "🟢 Normal"


# ═══════════════════════════════════════════════════════════════════════════
# Record template
# ═══════════════════════════════════════════════════════════════════════════

def _empty_record(app_label: str, source_artifact: str, data_class: str) -> Dict[str, Any]:
    return {
        "Wallet_App": app_label,
        "Source_Artifact": source_artifact,
        "Recovery_Method": "Active B-Tree",
        "Data_Class": data_class,
        "KYC_Name": None, "KYC_PAN": None, "KYC_Aadhaar_Masked": None,
        "Linked_Bank_Acct": None, "Linked_UPI": None,
        "Linked_Email": None, "Linked_Phone": None,
        "Chain": "UNKNOWN", "Address": None, "Address_Type": None, "Asset": None,
        "Amount_Crypto": None, "Amount_INR": None,
        "INR_Rate_At_Tx": None, "Fee_INR": None,
        "Direction": None,
        "Counterparty_Address": None, "Counterparty_Label": None,
        "TxHash": None, "Order_ID": None,
        "Timestamp_UTC": None, "Risk_Badge": "🟢 Normal",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Base wallet parser
# ═══════════════════════════════════════════════════════════════════════════

class BaseWalletParser:
    def __init__(self, db_path: str, app_label: str, owner_identifiers=None):
        self.db_path = db_path
        self.app_label = app_label
        self.owner_identifiers = owner_identifiers or {}
        self.signature = WALLET_SIGNATURES.get(app_label, {})
        self._conn = None
        self._tables: List[str] = []

    def __enter__(self):
        self._conn = _open_ro(self.db_path)
        self._tables = _safe_tables(self._conn)
        return self

    def __exit__(self, *exc):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass

    def _find_tables(self, hint_key: str) -> List[str]:
        hints = self.signature.get(hint_key) or []
        found = [t for t in self._tables if any(h in t.lower() for h in hints)]
        if not found:
            default_hints = DEFAULT_TABLE_HINTS.get(hint_key, [])
            found = [t for t in self._tables if any(h in t.lower() for h in default_hints)]
        return found

    def parse(self) -> pd.DataFrame:
        opened_here = False
        if self._conn is None:
            self._conn = _open_ro(self.db_path)
            self._tables = _safe_tables(self._conn)
            opened_here = True
        try:
            records: List[Dict[str, Any]] = []
            for label, fn in [
                ("KYC", self._parse_kyc),
                ("DEPOSIT_ADDRESS", self._parse_deposit_addresses),
                ("RECIPIENT", self._parse_saved_recipients),
                ("HOLDING", self._parse_holdings),
                ("ACTIVITY", self._parse_transactions),
                ("FIAT", self._parse_fiat_orders),
                ("EARN", self._parse_earn_stake),
            ]:
                try:
                    rows = fn()
                    if rows:
                        records.extend(rows)
                except Exception as e:
                    _log_forensic_error(f"wallet.{label}.{self.app_label}", e)
            if not records:
                return pd.DataFrame()
            df = pd.DataFrame(records)
            for c in _empty_record("", "", "").keys():
                if c not in df.columns:
                    df[c] = None
            return df[list(_empty_record("", "", "").keys())]
        finally:
            if opened_here and self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
                self._tables = []

    # -- per class ------------------------------------------------------
    def _parse_kyc(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("kyc_tables"):
            df = _safe_sample(self._conn, table, limit=50)
            if df.empty:
                continue
            for _, row in df.head(3).iterrows():
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "KYC")
                cl = {str(c).lower(): c for c in df.columns}

                def pick(*names):
                    for n in names:
                        for k, orig in cl.items():
                            if n in k:
                                v = row[orig]
                                if v is not None and str(v).strip() and str(v).lower() not in ("null", "none", "0"):
                                    return v
                    return None

                r["KYC_Name"]           = pick("full_name", "legal_name", "name", "account_holder")
                r["KYC_PAN"]            = pick("pan", "pan_number", "tax_id")
                r["KYC_Aadhaar_Masked"] = pick("aadhaar", "aadhar", "national_id")
                r["Linked_Email"]       = pick("email")
                r["Linked_Phone"]       = pick("phone", "mobile", "msisdn")
                r["Linked_UPI"]         = pick("vpa", "upi")
                r["Linked_Bank_Acct"]   = pick("bank_account", "account_number", "iban")
                if any(r[k] for k in ("KYC_Name", "KYC_PAN", "Linked_Email", "Linked_Phone")):
                    out.append(r)
        return out

    def _parse_deposit_addresses(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("address_tables"):
            df = _safe_sample(self._conn, table, limit=2000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            addr_col = roles.get("address") or roles.get("evm_address")
            chain_col = roles.get("chain")
            if not addr_col:
                continue
            asset_col = next(
                (c for c in df.columns if str(c).lower() in
                 ("asset", "coin", "currency", "symbol", "ticker")), None
            )
            for _, row in df.iterrows():
                addr = row.get(addr_col)
                if not isinstance(addr, str):
                    continue
                chain = detect_chain_from_address(addr)
                if not chain:
                    continue
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "DEPOSIT_ADDRESS")
                r["Chain"] = chain
                r["Address"] = addr
                r["Address_Type"] = "SELF_DEPOSIT"
                if asset_col and row.get(asset_col):
                    r["Asset"] = str(row[asset_col])
                if chain_col and row.get(chain_col):
                    r["Chain"] = str(row[chain_col]).upper()
                out.append(r)
        return out

    def _parse_saved_recipients(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("recipient_tables"):
            df = _safe_sample(self._conn, table, limit=2000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            addr_col = roles.get("address") or roles.get("evm_address")
            if not addr_col:
                continue
            label_col = next(
                (c for c in df.columns if str(c).lower() in
                 ("name", "label", "alias", "nickname", "contact_name")), None
            )
            for _, row in df.iterrows():
                addr = row.get(addr_col)
                if not isinstance(addr, str):
                    continue
                chain = detect_chain_from_address(addr)
                if not chain:
                    continue
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "RECIPIENT")
                r["Chain"] = chain
                r["Address"] = addr
                r["Address_Type"] = "SAVED_RECIPIENT"
                if label_col and row.get(label_col):
                    r["Counterparty_Label"] = str(row[label_col])
                out.append(r)
        return out

    def _parse_holdings(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("holdings_tables"):
            df = _safe_sample(self._conn, table, limit=5000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            amount_col = roles.get("amount")
            if not amount_col:
                continue
            asset_col = next(
                (c for c in df.columns if str(c).lower() in
                 ("asset", "coin", "currency", "symbol", "ticker")), None
            )
            for _, row in df.iterrows():
                try:
                    amt = float(row.get(amount_col))
                except (TypeError, ValueError):
                    continue
                if amt <= 0:
                    continue
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "HOLDING")
                r["Direction"] = "HOLDING"
                r["Amount_Crypto"] = amt
                if asset_col and row.get(asset_col):
                    r["Asset"] = str(row[asset_col])
                out.append(r)
        return out

    def _parse_transactions(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("tx_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            addr_col = roles.get("address") or roles.get("evm_address")
            txh_col = roles.get("tx_hash")
            ts_col = roles.get("timestamp")
            amount_col = roles.get("amount")
            if not (ts_col or amount_col):
                continue
            asset_col = next(
                (c for c in df.columns if str(c).lower() in
                 ("asset", "coin", "currency", "symbol", "ticker")), None
            )
            dir_col = next(
                (c for c in df.columns if str(c).lower() in
                 ("type", "direction", "kind", "operation", "action")), None
            )
            for _, row in df.iterrows():
                ts_iso = _normalize_timestamp(row.get(ts_col)) if ts_col else None
                try:
                    amt = float(row.get(amount_col)) if amount_col else None
                except (TypeError, ValueError):
                    amt = None
                if amt is None and not ts_iso and not row.get(addr_col):
                    continue
                raw_dir = str(row.get(dir_col, "")).upper() if dir_col else ""
                if any(k in raw_dir for k in ("BUY", "PURCHASE", "FIAT_ONRAMP")):
                    direction = "FIAT_ONRAMP"
                elif any(k in raw_dir for k in ("SELL", "SALE", "FIAT_OFFRAMP")):
                    direction = "FIAT_OFFRAMP"
                elif any(k in raw_dir for k in ("DEPOSIT", "RECEIVE", "TRANSFER_IN")):
                    direction = "DEPOSIT"
                elif any(k in raw_dir for k in ("WITHDRAW", "SEND", "TRANSFER_OUT")):
                    direction = "WITHDRAWAL"
                elif any(k in raw_dir for k in ("SWAP", "CONVERT", "EXCHANGE", "TRADE")):
                    direction = "SWAP_OUT"
                else:
                    direction = "UNKNOWN"
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", direction)
                r["Direction"] = direction
                r["Timestamp_UTC"] = ts_iso
                r["Amount_Crypto"] = amt
                if asset_col and row.get(asset_col):
                    r["Asset"] = str(row[asset_col])
                if addr_col and isinstance(row.get(addr_col), str):
                    a = row[addr_col]
                    chain = detect_chain_from_address(a)
                    if chain:
                        r["Chain"] = chain
                        r["Counterparty_Address"] = a
                        r["Address_Type"] = "COUNTERPARTY"
                if txh_col and row.get(txh_col):
                    r["TxHash"] = str(row[txh_col])
                r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
                out.append(r)
        return out

    def _parse_fiat_orders(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("fiat_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            ts_col = roles.get("timestamp")
            amount_col = roles.get("amount")
            if not amount_col:
                continue
            inr_col = next(
                (c for c in df.columns if "inr" in str(c).lower()
                 or "fiat_amount" in str(c).lower()
                 or "value_inr" in str(c).lower()), None
            )
            for _, row in df.iterrows():
                try:
                    amt = float(row.get(amount_col))
                except (TypeError, ValueError):
                    continue
                inr = None
                if inr_col:
                    try:
                        inr = float(row.get(inr_col))
                    except (TypeError, ValueError):
                        inr = None
                if amt <= 0 and (inr is None or inr <= 0):
                    continue
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "FIAT_ONRAMP")
                r["Direction"] = "FIAT_ONRAMP"
                r["Amount_Crypto"] = amt
                r["Amount_INR"] = inr
                if inr and amt:
                    r["INR_Rate_At_Tx"] = round(inr / amt, 2)
                r["Timestamp_UTC"] = _normalize_timestamp(row.get(ts_col)) if ts_col else None
                r["Risk_Badge"] = compute_risk_badge(inr, r["Timestamp_UTC"], "FIAT_ONRAMP")
                out.append(r)
        return out

    def _parse_earn_stake(self) -> List[Dict[str, Any]]:
        out = []
        for table in self._find_tables("earn_tables"):
            df = _safe_sample(self._conn, table, limit=5000)
            if df.empty:
                continue
            roles = _classify_by_content(df)
            amount_col = roles.get("amount")
            ts_col = roles.get("timestamp")
            if not amount_col:
                continue
            for _, row in df.iterrows():
                try:
                    amt = float(row.get(amount_col))
                except (TypeError, ValueError):
                    continue
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", "EARN")
                r["Direction"] = "EARN"
                r["Amount_Crypto"] = amt
                r["Timestamp_UTC"] = _normalize_timestamp(row.get(ts_col)) if ts_col else None
                out.append(r)
        return out


# ═══════════════════════════════════════════════════════════════════════════
# Specific overrides — Coinbase, Crypto.com, Bitget, MEXC
# ═══════════════════════════════════════════════════════════════════════════

class CoinbaseParser(BaseWalletParser):
    _TYPE_TO_DIRECTION = {
        "send":            "WITHDRAWAL",
        "receive":         "DEPOSIT",
        "buy":             "FIAT_ONRAMP",
        "sell":            "FIAT_OFFRAMP",
        "fiat_deposit":    "FIAT_ONRAMP",
        "fiat_withdrawal": "FIAT_OFFRAMP",
        "trade":           "SWAP_OUT",
        "pro_deposit":     "DEPOSIT",
        "pro_withdrawal":  "WITHDRAWAL",
    }

    def _parse_transactions(self):
        for table in self._find_tables("tx_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            cl = {str(c).lower(): c for c in df.columns}
            if not ("type" in cl and ("amount" in cl or "native_amount" in cl)):
                continue
            out = []
            for _, row in df.iterrows():
                raw_type = str(row[cl["type"]] or "").strip().lower()
                direction = self._TYPE_TO_DIRECTION.get(raw_type, "UNKNOWN")
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", direction)
                r["Direction"] = direction
                if "asset" in cl and row.get(cl["asset"]) is not None:
                    r["Asset"] = str(row[cl["asset"]])
                elif "native_currency" in cl and row.get(cl["native_currency"]) is not None:
                    r["Asset"] = str(row[cl["native_currency"]])
                if "id" in cl and row.get(cl["id"]) is not None:
                    r["Order_ID"] = str(row[cl["id"]])
                if "amount" in cl:
                    try:
                        r["Amount_Crypto"] = float(row[cl["amount"]])
                    except (TypeError, ValueError):
                        pass
                if "native_amount" in cl:
                    try:
                        r["Amount_INR"] = float(row[cl["native_amount"]])
                    except (TypeError, ValueError):
                        pass
                for ts_key in ("created_at", "created", "timestamp", "updated_at"):
                    if ts_key in cl:
                        r["Timestamp_UTC"] = _normalize_timestamp(row[cl[ts_key]])
                        if r["Timestamp_UTC"]:
                            break
                addr_key = "to_address" if direction == "WITHDRAWAL" else \
                           "from_address" if direction == "DEPOSIT" else None
                if addr_key and addr_key in cl and row.get(cl[addr_key]):
                    a = str(row[cl[addr_key]])
                    chain = detect_chain_from_address(a)
                    if chain:
                        r["Chain"] = chain
                        r["Counterparty_Address"] = a
                        r["Address_Type"] = "COUNTERPARTY"
                for hk in ("network_hash", "tx_hash", "hash"):
                    if hk in cl and row.get(cl[hk]):
                        r["TxHash"] = str(row[cl[hk]])
                        break
                r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
                out.append(r)
            if out:
                return out
        return super()._parse_transactions()


class CryptoComParser(BaseWalletParser):
    _TYPE_MAP = {
        "purchase": "FIAT_ONRAMP", "sale": "FIAT_OFFRAMP",
        "buy": "FIAT_ONRAMP", "sell": "FIAT_OFFRAMP",
        "deposit": "DEPOSIT", "receive": "DEPOSIT", "withdrawal": "WITHDRAWAL", "send": "WITHDRAWAL",
        "transfer_in": "DEPOSIT", "transfer_out": "WITHDRAWAL",
        "exchange": "SWAP_OUT", "swap": "SWAP_OUT", "trade": "SWAP_OUT",
        "rebate": "EARN", "cashback": "EARN",
        "card_purchase": "FIAT_OFFRAMP",
        "crypto_earn_deposit": "EARN",
    }

    def _parse_transactions(self):
        for table in self._find_tables("tx_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            cl = {str(c).lower(): c for c in df.columns}
            tcol = cl.get("transaction_type") or cl.get("tx_type") or cl.get("type")
            if not tcol:
                continue
            out = []
            for _, row in df.iterrows():
                raw = str(row[tcol] or "").strip().lower()
                direction = self._TYPE_MAP.get(raw, "UNKNOWN")
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", direction)
                r["Direction"] = direction
                for k in ("asset", "currency", "coin", "symbol"):
                    if k in cl and row.get(cl[k]):
                        r["Asset"] = str(row[cl[k]])
                        break
                for k in ("amount", "crypto_amount", "quantity"):
                    if k in cl:
                        try:
                            r["Amount_Crypto"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("fiat_amount", "amount_fiat", "native_amount"):
                    if k in cl:
                        try:
                            r["Amount_INR"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("created_at", "timestamp", "tx_time", "date"):
                    if k in cl:
                        r["Timestamp_UTC"] = _normalize_timestamp(row[cl[k]])
                        if r["Timestamp_UTC"]:
                            break
                for k in ("tx_hash", "hash", "transaction_hash"):
                    if k in cl and row.get(cl[k]):
                        r["TxHash"] = str(row[cl[k]])
                        break
                for k in ("address", "to_address", "wallet_address"):
                    if k in cl and row.get(cl[k]) and isinstance(row[cl[k]], str):
                        a = str(row[cl[k]])
                        ch = detect_chain_from_address(a)
                        if ch:
                            r["Chain"] = ch
                            r["Counterparty_Address"] = a
                            r["Address_Type"] = "COUNTERPARTY"
                            break
                r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
                out.append(r)
            if out:
                return out
        return super()._parse_transactions()


class BitgetParser(BaseWalletParser):
    _TYPE_MAP = {
        "deposit": "DEPOSIT", "receive": "DEPOSIT", "withdraw": "WITHDRAWAL", "withdrawal": "WITHDRAWAL", "send": "WITHDRAWAL",
        "buy": "FIAT_ONRAMP", "sell": "FIAT_OFFRAMP",
        "p2p_buy": "FIAT_ONRAMP", "p2p_sell": "FIAT_OFFRAMP",
        "transfer_in": "DEPOSIT", "transfer_out": "WITHDRAWAL",
        "swap": "SWAP_OUT", "convert": "SWAP_OUT", "trade": "SWAP_OUT",
    }

    def _parse_transactions(self):
        for table in self._find_tables("tx_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            cl = {str(c).lower(): c for c in df.columns}
            tcol = cl.get("type") or cl.get("order_type") or cl.get("side")
            if not tcol:
                continue
            out = []
            for _, row in df.iterrows():
                raw = str(row[tcol] or "").strip().lower()
                if "buy" in raw:
                    direction = "FIAT_ONRAMP"
                elif "sell" in raw:
                    direction = "FIAT_OFFRAMP"
                else:
                    direction = self._TYPE_MAP.get(raw, "UNKNOWN")
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", direction)
                r["Direction"] = direction
                for k in ("coin", "asset", "symbol", "currency"):
                    if k in cl and row.get(cl[k]):
                        r["Asset"] = str(row[cl[k]])
                        break
                for k in ("amount", "quantity", "size", "coin_amount"):
                    if k in cl:
                        try:
                            r["Amount_Crypto"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("total_price", "fiat_amount", "amount_inr", "price_total"):
                    if k in cl:
                        try:
                            r["Amount_INR"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("create_time", "created_at", "timestamp", "ctime"):
                    if k in cl:
                        r["Timestamp_UTC"] = _normalize_timestamp(row[cl[k]])
                        if r["Timestamp_UTC"]:
                            break
                for k in ("address", "to_address", "counterparty_address"):
                    if k in cl and row.get(cl[k]) and isinstance(row[cl[k]], str):
                        a = str(row[cl[k]])
                        ch = detect_chain_from_address(a)
                        if ch:
                            r["Chain"] = ch
                            r["Counterparty_Address"] = a
                            r["Address_Type"] = "COUNTERPARTY"
                            break
                r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
                out.append(r)
            if out:
                return out
        return super()._parse_transactions()


class MexcParser(BaseWalletParser):
    _TYPE_MAP = {
        "deposit": "DEPOSIT", "receive": "DEPOSIT", "withdraw": "WITHDRAWAL", "withdrawal": "WITHDRAWAL", "send": "WITHDRAWAL",
        "buy": "FIAT_ONRAMP", "sell": "FIAT_OFFRAMP",
        "trade_in": "DEPOSIT", "trade_out": "WITHDRAWAL",
        "convert": "SWAP_OUT", "swap": "SWAP_OUT", "trade": "SWAP_OUT",
    }

    def _parse_transactions(self):
        for table in self._find_tables("tx_tables"):
            df = _safe_sample(self._conn, table, limit=10_000)
            if df.empty:
                continue
            cl = {str(c).lower(): c for c in df.columns}
            tcol = cl.get("type") or cl.get("trade_type") or cl.get("side")
            if not tcol:
                continue
            out = []
            for _, row in df.iterrows():
                raw = str(row[tcol] or "").strip().lower()
                direction = self._TYPE_MAP.get(raw, "UNKNOWN")
                if direction == "UNKNOWN" and "p2p" in table.lower():
                    if "buy" in raw:
                        direction = "FIAT_ONRAMP"
                    elif "sell" in raw:
                        direction = "FIAT_OFFRAMP"
                r = _empty_record(self.app_label, f"{Path(self.db_path).name}::{table}", direction)
                r["Direction"] = direction
                for k in ("coin", "symbol", "asset", "currency"):
                    if k in cl and row.get(cl[k]):
                        r["Asset"] = str(row[cl[k]])
                        break
                for k in ("amount", "quantity", "vol", "qty"):
                    if k in cl:
                        try:
                            r["Amount_Crypto"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("total", "fiat_amount", "amount_inr", "price_total"):
                    if k in cl:
                        try:
                            r["Amount_INR"] = float(row[cl[k]])
                            break
                        except (TypeError, ValueError):
                            pass
                for k in ("create_time", "created_at", "timestamp", "date"):
                    if k in cl:
                        r["Timestamp_UTC"] = _normalize_timestamp(row[cl[k]])
                        if r["Timestamp_UTC"]:
                            break
                for k in ("address", "to_address"):
                    if k in cl and row.get(cl[k]) and isinstance(row[cl[k]], str):
                        a = str(row[cl[k]])
                        ch = detect_chain_from_address(a)
                        if ch:
                            r["Chain"] = ch
                            r["Counterparty_Address"] = a
                            r["Address_Type"] = "COUNTERPARTY"
                            break
                r["Risk_Badge"] = compute_risk_badge(r["Amount_INR"], r["Timestamp_UTC"], direction)
                out.append(r)
            if out:
                return out
        return super()._parse_transactions()


# ═══════════════════════════════════════════════════════════════════════════
# Registry + dispatch
# ═══════════════════════════════════════════════════════════════════════════

_PARSER_REGISTRY = {
    "Coinbase":      CoinbaseParser,
    "Crypto.com":    CryptoComParser,
    "Bitget":        BitgetParser,
    "MEXC":          MexcParser,
    # Remaining 11 use BaseWalletParser (content-classification)
}


def is_custodial_wallet_app(app_label: str) -> bool:
    if app_label in WALLET_SIGNATURES:
        return True
    al = (app_label or "").lower()
    for sig in WALLET_SIGNATURES.values():
        for k in ("package_android", "bundle_ios"):
            v = str(sig.get(k, "")).lower()
            if v and v in al:
                return True
    return False


def get_wallet_signature(app_label: str) -> Optional[Dict[str, Any]]:
    """Resolve app_label to a signature (exact or fuzzy)."""
    if app_label in WALLET_SIGNATURES:
        return WALLET_SIGNATURES[app_label]
    al = (app_label or "").lower()
    for name, sig in WALLET_SIGNATURES.items():
        for k in ("package_android", "bundle_ios"):
            v = str(sig.get(k, "")).lower()
            if v and v in al:
                return sig
    return None


def dispatch_custodial_wallet(
    db_path: str,
    app_label: str,
    owner_identifiers: Optional[Dict[str, Any]] = None,
) -> pd.DataFrame:
    """
    Entry point. Given a matched wallet DB, return a normalized DataFrame
    of all seven data classes plus fiat orders.

    Safe to call on any DB — returns empty DataFrame if nothing is extractable.
    """
    if not Path(db_path).exists():
        return pd.DataFrame()

    parser_cls = _PARSER_REGISTRY.get(app_label, BaseWalletParser)

    try:
        with parser_cls(db_path, app_label, owner_identifiers) as p:
            df = p.parse()
    except Exception as e:
        _log_forensic_error(f"wallet.dispatch.{app_label}", e)
        return pd.DataFrame()

    if df.empty:
        return df

    # Fill missing chains from addresses (defensive)
    if "Address" in df.columns and "Chain" in df.columns:
        mask = df["Chain"].isna() | (df["Chain"] == "UNKNOWN")
        if mask.any():
            df.loc[mask, "Chain"] = df.loc[mask, "Address"].apply(
                lambda a: detect_chain_from_address(a) or "UNKNOWN"
            )
    return df


# ═══════════════════════════════════════════════════════════════════════════
# Address manifest (plain CSV: address, network, source)
# ═══════════════════════════════════════════════════════════════════════════

def build_address_manifest(wallet_df: pd.DataFrame) -> pd.DataFrame:
    """
    Produce a chain-analytics import CSV: unique addresses with metadata.
    Deduplicates by (chain, address) and aggregates first/last seen + INR volume.
    """
    if wallet_df.empty or "Address" not in wallet_df.columns:
        return pd.DataFrame()

    df = wallet_df[wallet_df["Address"].notna()].copy()
    if df.empty:
        return pd.DataFrame()

    grouped = df.groupby(["Chain", "Address"], dropna=False).agg(
        wallet_app=("Wallet_App", "first"),
        address_type=("Address_Type", "first"),
        counterparty_label=("Counterparty_Label", "first"),
        first_seen_utc=("Timestamp_UTC", "min"),
        last_seen_utc=("Timestamp_UTC", "max"),
        total_inr_volume=("Amount_INR", lambda s: float(pd.to_numeric(s, errors="coerce").fillna(0).sum())),
        tx_count=("Address", "size"),
    ).reset_index()

    grouped.columns = [
        "chain", "address", "wallet_app", "address_type",
        "counterparty_label", "first_seen_utc", "last_seen_utc",
        "total_inr_volume", "tx_count",
    ]
    return grouped
