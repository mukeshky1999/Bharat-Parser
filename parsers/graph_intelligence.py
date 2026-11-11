"""
Phase 2 & 3: Enterprise Graph Intelligence, Syndicate Role Decomposition & Charge-Sheet Generation.
Aggregates parallel edges during visualization and uses WAL + 30s busy_timeout for concurrent multi-user access.
"""

from __future__ import annotations

import html
import os
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional
import networkx as nx
import pandas as pd
from pyvis.network import Network

_INDEX_DB_LOCK = threading.Lock()


def _norm_case(s: str) -> str:
    s = str(s).strip().lower()
    for suf in ('-test', '_test', '-dev', '_dev', '-temp', '-copy', '_copy'):
        if s.endswith(suf):
            s = s[:-len(suf)]
    return s


def build_transaction_graph(master_timeline: pd.DataFrame) -> nx.MultiDiGraph:
    """Constructs a directed NetworkX graph from mobile transaction ledgers."""
    g = nx.MultiDiGraph()
    if master_timeline.empty or 'Counterparty' not in master_timeline.columns:
        return g

    for _, row in master_timeline.iterrows():
        app = str(row.get('Application', 'UPI'))
        cparty = str(row.get('Counterparty', 'Unknown')).strip()
        amt = float(row.get('Amount', 0.0)) if pd.notna(row.get('Amount')) else 0.0
        flow = str(row.get('Type', 'TRANSFER')).upper()
        ts = str(row.get('Date', ''))
        txid = str(row.get('Transaction_ID', ''))

        if not cparty or cparty in ['Unknown', 'None', 'nan']:
            continue

        local_node = 'This Phone'
        if flow == 'DEBIT':
            u, v = local_node, cparty
        elif flow == 'CREDIT':
            u, v = cparty, local_node
        else:
            u, v = local_node, cparty

        g.add_node(u, entity=u, type='Local' if u == 'This Phone' else 'External')
        g.add_node(v, entity=v, type='Local' if v == 'This Phone' else 'External')

        if u == 'This Phone':
            apps = set(g.nodes[u].get('apps_used', []))
            apps.add(app)
            g.nodes[u]['apps_used'] = list(apps)
        if v == 'This Phone':
            apps = set(g.nodes[v].get('apps_used', []))
            apps.add(app)
            g.nodes[v]['apps_used'] = list(apps)

        g.add_edge(u, v, amount=amt, timestamp=ts, txid=txid, app=app, flow=flow, layer='FINANCIAL')

    return g


def fuse_multi_source_graph(
    g: nx.MultiDiGraph,
    bank_df: Optional[pd.DataFrame] = None,
    cdr_df: Optional[pd.DataFrame] = None,
    custodial_wallet_df: Optional[pd.DataFrame] = None,
) -> nx.MultiDiGraph:
    fused_g = g.copy()

    if bank_df is not None and not bank_df.empty:
        bank_root = "Bank Account (Official Statement)"
        fused_g.add_node(bank_root, entity=bank_root, type='Bank_Institution')
        for _, row in bank_df.iterrows():
            narration = str(row.get('Narration', ''))
            ref_utr = str(row.get('Ref_UTR', ''))
            vpa = row.get('Extracted_VPA')
            debit = float(row.get('Debit', 0.0))
            credit = float(row.get('Credit', 0.0))
            ts = str(row.get('Date', ''))
            target_cparty = vpa if vpa else (narration[:30] if narration else 'Bank Counterparty')

            if debit > 0:
                fused_g.add_node(target_cparty, entity=target_cparty, type='External')
                fused_g.add_edge(bank_root, target_cparty, amount=debit, timestamp=ts, txid=ref_utr, app='Bank_Statement', flow='DEBIT', layer='FINANCIAL')
            elif credit > 0:
                fused_g.add_node(target_cparty, entity=target_cparty, type='External')
                fused_g.add_edge(target_cparty, bank_root, amount=credit, timestamp=ts, txid=ref_utr, app='Bank_Statement', flow='CREDIT', layer='FINANCIAL')

    if cdr_df is not None and not cdr_df.empty:
        for _, row in cdr_df.iterrows():
            caller = str(row.get('Caller_A', '')).strip()
            callee = str(row.get('Receiver_B', '')).strip()
            c_time = str(row.get('Call_Time', '')).strip()
            dur = row.get('Duration_Sec', 0)
            c_type = str(row.get('Call_Type', 'VOICE')).strip()
            if caller and callee and caller.lower() not in ('nan', 'none', 'null') and callee.lower() not in ('nan', 'none', 'null'):
                fused_g.add_node(caller, entity=caller, type='Telecom_Node')
                fused_g.add_node(callee, entity=callee, type='Telecom_Node')
                fused_g.add_edge(caller, callee, amount=0.0, timestamp=c_time, txid=f"{c_type}_{dur}s", app='CDR', flow=c_type, layer='TELECOM')

    if custodial_wallet_df is not None and not custodial_wallet_df.empty:
        for _, row in custodial_wallet_df.iterrows():
            wallet_app = str(row.get('Wallet_App', 'Custodial Wallet')).strip()
            direction = str(row.get('Direction', '')).strip().upper()
            asset = str(row.get('Asset') or row.get('Chain') or 'Crypto').strip()
            chain = str(row.get('Chain', 'UNKNOWN')).strip()
            amt_inr = float(row.get('Amount_INR') or 0.0) if pd.notna(row.get('Amount_INR')) else 0.0
            amt_crypto = float(row.get('Amount_Crypto') or 0.0) if pd.notna(row.get('Amount_Crypto')) else 0.0
            cparty_addr = str(row.get('Counterparty_Address') or row.get('Address') or '').strip()
            cparty_label = str(row.get('Counterparty_Label') or '').strip()
            txhash = str(row.get('TxHash') or row.get('Order_ID') or '').strip()
            ts = str(row.get('Timestamp_UTC') or '').strip()

            wallet_node = f"Wallet ({wallet_app}: {asset})"
            fused_g.add_node(wallet_node, entity=wallet_node, type='Wallet', wallet_app=wallet_app)

            cparty_node = cparty_label if cparty_label else (cparty_addr if cparty_addr else f"External Counterparty ({chain})")

            if direction == 'DEPOSIT':
                fused_g.add_node(cparty_node, entity=cparty_node, type='Crypto_Counterparty')
                fused_g.add_edge(cparty_node, wallet_node, amount=amt_inr, crypto_amt=amt_crypto, asset=asset, timestamp=ts, txid=txhash, app=wallet_app, flow='DEPOSIT', layer='CRYPTO', edge_type='WALLET_TRANSFER')
            elif direction == 'WITHDRAWAL':
                fused_g.add_node(cparty_node, entity=cparty_node, type='Crypto_Counterparty')
                fused_g.add_edge(wallet_node, cparty_node, amount=amt_inr, crypto_amt=amt_crypto, asset=asset, timestamp=ts, txid=txhash, app=wallet_app, flow='WITHDRAWAL', layer='CRYPTO', edge_type='WALLET_TRANSFER')
            elif direction in ('FIAT_ONRAMP', 'BUY'):
                fiat_root = "Bank Account (Official Statement)"
                fused_g.add_node(fiat_root, entity=fiat_root, type='Bank_Institution')
                fused_g.add_edge(fiat_root, wallet_node, amount=amt_inr, crypto_amt=amt_crypto, asset=asset, timestamp=ts, txid=txhash, app=wallet_app, flow='FIAT_ONRAMP', layer='CRYPTO', edge_type='WALLET_TRANSFER')
            elif direction in ('FIAT_OFFRAMP', 'SELL'):
                fiat_root = "Bank Account (Official Statement)"
                fused_g.add_node(fiat_root, entity=fiat_root, type='Bank_Institution')
                fused_g.add_edge(wallet_node, fiat_root, amount=amt_inr, crypto_amt=amt_crypto, asset=asset, timestamp=ts, txid=txhash, app=wallet_app, flow='FIAT_OFFRAMP', layer='CRYPTO', edge_type='WALLET_TRANSFER')

    return fused_g


def classify_syndicate_roles(
    g: nx.MultiDiGraph, master_timeline: pd.DataFrame
) -> pd.DataFrame:
    if len(g.nodes) == 0:
        return pd.DataFrame()

    simple_g = nx.DiGraph()
    for u, v, data in g.edges(data=True):
        amt = data.get('amount', 1.0)
        if simple_g.has_edge(u, v):
            simple_g[u][v]['weight'] += amt
        else:
            simple_g.add_edge(u, v, weight=amt)

    try:
        betweenness = nx.betweenness_centrality(simple_g)
    except Exception:
        betweenness = {n: 0.0 for n in g.nodes()}

    roles: List[Dict[str, Any]] = []
    for node in g.nodes():
        if 'This Phone' in node or node == 'Bank Account (Official Statement)':
            continue

        in_edges = [d for _, _, d in g.in_edges(node, data=True) if d.get('layer') == 'FINANCIAL']
        out_edges = [d for _, _, d in g.out_edges(node, data=True) if d.get('layer') == 'FINANCIAL']

        in_amt = sum(d.get('amount', 0.0) for d in in_edges)
        out_amt = sum(d.get('amount', 0.0) for d in out_edges)
        total_vol = in_amt + out_amt
        in_cnt = len(in_edges)
        out_cnt = len(out_edges)
        bw = betweenness.get(node, 0.0)

        role = 'Regular Contact / Merchant'
        severity = 'INFO'
        if in_amt > 20000 and out_amt > 20000 and (in_amt * 0.7 <= out_amt <= in_amt * 1.3):
            role = 'Middleman / Rapid Pass-Through Account'
            severity = 'CRITICAL'
        elif in_cnt >= 3 and (out_cnt == 0 or out_amt < in_amt * 0.15):
            role = 'Primary Recipient (Money Receiver)'
            severity = 'HIGH'
        elif out_amt > 25000 and (in_cnt == 0 or in_amt < out_amt * 0.15):
            role = 'Major Funding Source (Money Sender)'
            severity = 'HIGH'
        elif in_amt > 15000 and out_amt > 15000:
            role = 'Two-Way Frequent Transactor'
            severity = 'MEDIUM'

        roles.append({
            'Entity': node,
            'Assigned_Role': role,
            'Risk_Severity': severity,
            'Betweenness_Centrality': round(bw, 4),
            'Inflow_Amount_INR': in_amt,
            'Outflow_Amount_INR': out_amt,
            'Total_Volume_INR': total_vol,
            'In_Degree': in_cnt,
            'Out_Degree': out_cnt,
        })

    if roles:
        return pd.DataFrame(roles).sort_values(by='Total_Volume_INR', ascending=False)
    return pd.DataFrame()


def extract_charge_sheet_chain(
    g: nx.MultiDiGraph,
    source_entity: str,
    target_entity: str,
    max_hops: int = 5,
) -> pd.DataFrame:
    output_cols = [
        'Hop_Index', 'Source_Node', 'Target_Node', 'Amount_INR',
        'Timestamp', 'Transaction_ID_UTR', 'App_Channel', 'Flow_Type'
    ]
    if source_entity not in g or target_entity not in g:
        return pd.DataFrame(columns=output_cols)

    simple_g = nx.DiGraph()
    for u, v, data in g.edges(data=True):
        if data.get('layer') == 'FINANCIAL':
            simple_g.add_edge(u, v)

    try:
        paths = list(nx.all_simple_paths(simple_g, source=source_entity, target=target_entity, cutoff=max_hops))
    except Exception:
        return pd.DataFrame(columns=output_cols)

    if not paths:
        return pd.DataFrame(columns=output_cols)

    primary_path = paths[0]
    chain_records: List[Dict[str, Any]] = []
    for idx in range(len(primary_path) - 1):
        u = primary_path[idx]
        v = primary_path[idx + 1]
        edges_data = [d for su, sv, d in g.edges(data=True) if su == u and sv == v and d.get('layer') == 'FINANCIAL']
        if not edges_data:
            continue
        primary_edge = edges_data[0]
        chain_records.append({
            'Hop_Index': f"Step {idx + 1}",
            'Source_Node': u,
            'Target_Node': v,
            'Amount_INR': primary_edge.get('amount', 0.0),
            'Timestamp': str(primary_edge.get('timestamp', '')),
            'Transaction_ID_UTR': str(primary_edge.get('txid', 'N/A')),
            'App_Channel': str(primary_edge.get('app', 'UPI')),
            'Flow_Type': str(primary_edge.get('flow', 'DEBIT')),
        })

    return pd.DataFrame(chain_records)


def detect_mule_behavior(
    g: nx.MultiDiGraph, master_timeline: pd.DataFrame
) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if master_timeline.empty:
        return alerts

    df = master_timeline.dropna(subset=['Amount']).copy()
    df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
    df = df.dropna(subset=['Amount'])
    if 'Date' in df.columns:
        df['Parsed_Date'] = pd.to_datetime(df['Date'], errors='coerce')
        df = df.sort_values(by='Parsed_Date')
    else:
        df['Parsed_Date'] = pd.NaT

    credits = df[df['Type'].astype(str).str.upper() == 'CREDIT']
    debits = df[df['Type'].astype(str).str.upper() == 'DEBIT']

    for _, c_row in credits.iterrows():
        c_time = c_row['Parsed_Date']
        c_amt = c_row['Amount']
        if pd.isna(c_time) or c_amt < 10000:
            continue
        window_end = c_time + pd.Timedelta(minutes=30)
        matching_debits = debits[
            (debits['Parsed_Date'] >= c_time) & (debits['Parsed_Date'] <= window_end)
        ]
        sum_debit = matching_debits['Amount'].sum()
        if sum_debit >= (c_amt * 0.85):
            out_parties = ', '.join(matching_debits['Counterparty'].astype(str).unique()[:3])
            alerts.append({
                'Entity': f"Received from: {c_row['Counterparty']} → Sent to: {out_parties}",
                'Pattern': 'Rapid Money Pass-Through (Funds Received & Forwarded Within 30 Mins)',
                'Severity': 'CRITICAL',
                'Confidence': 94,
                'Details': (
                    f"This device received ₹{c_amt:,.2f} from '{c_row['Counterparty']}' and immediately "
                    f"forwarded ₹{sum_debit:,.2f} to {out_parties} within 30 minutes."
                ),
            })

    for cparty, group in df[
        df['Type'].astype(str).str.upper() == 'CREDIT'
    ].groupby('Counterparty'):
        smurf_txns = group[(group['Amount'] >= 40000) & (group['Amount'] < 50000)]
        if len(smurf_txns) >= 2:
            alerts.append({
                'Entity': str(cparty),
                'Pattern': 'Split Transfers Just Below ₹50,000 Limit (Structuring)',
                'Severity': 'HIGH',
                'Confidence': 88,
                'Details': (
                    f"{len(smurf_txns)} separate incoming payments between ₹40,000 and "
                    f"₹49,999 from '{cparty}' (often used to avoid ₹50k PAN/reporting checks)."
                ),
            })

    for cparty in g.nodes():
        if 'This Phone' in str(cparty) or cparty == 'Bank Account (Official Statement)':
            continue
        in_amt = sum(
            d.get('amount', 0.0) for _, _, d in g.in_edges(cparty, data=True) if d.get('layer') == 'FINANCIAL'
        )
        out_amt = sum(
            d.get('amount', 0.0) for _, _, d in g.out_edges(cparty, data=True) if d.get('layer') == 'FINANCIAL'
        )
        if in_amt > 20000 and out_amt > 20000:
            alerts.append({
                'Entity': str(cparty),
                'Pattern': 'High-Value Two-Way Transfers (Money Sent Back & Forth)',
                'Severity': 'MEDIUM',
                'Confidence': 78,
                'Details': (
                    f"Heavy two-way activity with '{cparty}': Sent ₹{in_amt:,.2f} "
                    f"and Received ₹{out_amt:,.2f}."
                ),
            })

    return alerts


def generate_pyvis_network_html(
    g: nx.MultiDiGraph,
    alerts: List[Dict[str, Any]],
    roles_df: Optional[pd.DataFrame] = None,
) -> str:
    if len(g.nodes) == 0:
        return (
            '<html><body><h4 style="color:#8b949e;text-align:center;">'
            'No transaction connections available to visualize.</h4></body></html>'
        )

    net = Network(
        height='650px',
        width='100%',
        bgcolor='#0e1117',
        font_color='#f0f6fc',
        directed=True,
        cdn_resources='in_line',  # Bundles vis-network.min.js inline for air-gapped labs
    )
    net.barnes_hut(
        gravity=-3000,
        central_gravity=0.3,
        spring_length=160,
        spring_strength=0.05,
        damping=0.9,
    )

    role_map = {}
    if roles_df is not None and not roles_df.empty:
        for _, r in roles_df.iterrows():
            role_map[str(r['Entity'])] = str(r['Assigned_Role'])

    flagged_entities = set()
    for a in alerts:
        for fn in a.get('Flagged_Nodes', []):
            if fn:
                flagged_entities.add(str(fn).strip())
        ent = str(a.get('Entity', ''))
        matched_sep = False
        for sep in ('➔', '->', 'Sent to:', '→'):
            if sep in ent:
                matched_sep = True
                for part in re.split(r'➔|->|Sent to:|→', ent):
                    clean_ent = part.replace('Received from:', '').strip()
                    for sub in clean_ent.split(','):
                        if sub.strip():
                            flagged_entities.add(sub.strip())
                break
        if not matched_sep and ent:
            flagged_entities.add(ent)

    for node in g.nodes():
        node_type = g.nodes[node].get('type')
        is_local = 'This Phone' in str(node) or node == 'Bank Account (Official Statement)'
        is_telecom = node_type == 'Telecom_Node'
        is_wallet = node_type == 'Wallet'
        is_crypto_cparty = node_type == 'Crypto_Counterparty'
        role = role_map.get(node, 'Contact / Merchant')

        if node in flagged_entities or 'Pass-Through' in role:
            color = '#ef4444'
            size = 30
        elif 'Recipient' in role:
            color = '#f59e0b'
            size = 26
        elif 'Funding' in role:
            color = '#eab308'
            size = 26
        elif is_wallet:
            color = '#8b5cf6'
            size = 28
        elif is_crypto_cparty:
            color = '#ec4899'
            size = 24
        elif is_local:
            color = '#3b82f6'
            size = 34
        elif is_telecom:
            color = '#06b6d4'
            size = 22
        else:
            color = '#10b981'
            size = 20

        lbl_text = node[:25] + '...' if len(node) > 25 else node
        net.add_node(
            node,
            label=html.escape(lbl_text),
            title=html.escape(f"Account/ID: {node}\nCategory: {role}\nAlert Flagged: {'Yes' if node in flagged_entities else 'No'}"),
            color=color,
            size=size,
        )

    edge_groups: Dict[tuple, Dict[str, Any]] = {}
    for u, v, data in g.edges(data=True):
        layer = data.get('layer', 'FINANCIAL')
        flow = data.get('flow', 'TRANSFER')
        key = (u, v, layer, flow)
        if key not in edge_groups:
            edge_groups[key] = {
                'total_amt': 0.0,
                'count': 0,
                'latest_ts': str(data.get('timestamp', '')),
                'sample_txid': str(data.get('txid', '')),
            }
        edge_groups[key]['total_amt'] += float(data.get('amount', 0.0))
        edge_groups[key]['count'] += 1

    for (u, v, layer, flow), info in edge_groups.items():
        if layer == 'TELECOM':
            net.add_edge(
                u, v,
                value=1.5,
                title=f"Phone Calls ({info['count']}x)\nLast Call: {info['latest_ts']}",
                color='#38bdf8',
                dashes=True,
            )
        elif layer == 'CRYPTO':
            net.add_edge(
                u, v,
                value=2.5,
                title=(
                    f"Wallet Transfer ({flow})\n"
                    f"INR Volume: ₹{info['total_amt']:,.2f} ({info['count']} txn[s])\n"
                    f"Last Date: {info['latest_ts']}\n"
                    f"Ref / TxHash: {info['sample_txid']}"
                ),
                color='#a855f7',
                dashes=False,
            )
        else:
            direction_label = "Money Sent (Debit)" if flow == 'DEBIT' else ("Money Received (Credit)" if flow == 'CREDIT' else "Transfer")
            net.add_edge(
                u, v,
                value=min(10.0, max(1.5, info['total_amt'] / 5000.0)),
                title=(
                    f"{direction_label}\n"
                    f"Total Amount: ₹{info['total_amt']:,.2f} ({info['count']} txn[s])\n"
                    f"Last Date: {info['latest_ts']}\n"
                    f"Ref ID: {info['sample_txid']}"
                ),
                color='#f87171' if flow == 'DEBIT' else '#4ade80',
                dashes=False,
            )

    raw_html = net.generate_html()
    offline_safety_script = """
    <script>
    window.addEventListener('error', function(e) {
        if (e.target.src && e.target.src.includes('vis-network')) {
            document.body.innerHTML = '<div style="color:#ef4444;padding:20px;font-family:sans-serif;">' +
            '<h3>Offline Workstation Mode</h3>' +
            '<p>Interactive graph script requires internet or local vis-network bundle. See table below for full path breakdown.</p></div>';
        }
    }, true);
    </script>
    """
    return raw_html.replace('<head>', f'<head>{offline_safety_script}')


def audit_shared_vault_write(db_index_path: str, case_id: str, entity_type: str, count: int) -> None:
    """Audit shared intelligence database writes under DPDP secondary purpose compliance."""
    try:
        if not os.path.isabs(db_index_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_index_path = os.path.join(base_dir, db_index_path)
        conn = sqlite3.connect(db_index_path, timeout=30.0)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_audit (
                ts TEXT DEFAULT CURRENT_TIMESTAMP,
                case_id TEXT, entity_type TEXT, entity_count INTEGER
            );
        """)
        conn.execute(
            "INSERT INTO vault_audit (case_id, entity_type, entity_count) VALUES (?,?,?)",
            (case_id, entity_type, count),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        try:
            from fs_handler import _log_forensic_error
            _log_forensic_error("vault_audit", e)
        except Exception:
            pass


def cross_case_correlation(
    current_case: str,
    master_timeline: pd.DataFrame,
    vpa_df: pd.DataFrame,
    phone_df: pd.DataFrame,
    db_index_path: str = 'case_intelligence_index.db',
    persist_to_shared_vault: bool = True,
) -> pd.DataFrame:
    """Thread-safe and multi-process safe cross-case correlation using WAL mode and busy_timeout."""
    if not os.path.isabs(db_index_path):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_index_path = os.path.join(base_dir, db_index_path)

    empty_cols = [
        'Target_Entity', 'Entity_Type', 'Matched_Historical_Case',
        'Historical_Recorded_Date', 'Intelligence_Insight',
    ]
    matches: List[dict] = []
    conn = None
    norm_current = _norm_case(current_case)

    with _INDEX_DB_LOCK:
        try:
            conn = sqlite3.connect(db_index_path, timeout=30.0)
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA busy_timeout=30000;')
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS entity_index (
                entity_value TEXT,
                entity_type TEXT,
                case_id TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (entity_value, case_id)
            );
            """)

            curr_entities = []
            if not vpa_df.empty and 'UPI_VPA' in vpa_df.columns:
                curr_entities.extend((str(v), 'UPI ID (VPA)') for v in vpa_df['UPI_VPA'])
            if not phone_df.empty and 'Phone_Number' in phone_df.columns:
                curr_entities.extend(
                    (str(p), 'Mobile Number') for p in phone_df['Phone_Number']
                )

            for ent_val, ent_type in curr_entities:
                cursor.execute(
                    'SELECT case_id, first_seen FROM entity_index WHERE entity_value = ?',
                    (ent_val,),
                )
                for h in cursor.fetchall():
                    hist_case = h[0]
                    if _norm_case(hist_case) == norm_current:
                        continue
                    matches.append({
                        'Target_Entity': ent_val,
                        'Entity_Type': ent_type,
                        'Matched_Historical_Case': hist_case,
                        'Historical_Recorded_Date': h[1],
                        'Intelligence_Insight': (
                            'This UPI ID / Phone Number was previously seen in another case.'
                        ),
                    })

                if persist_to_shared_vault:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO entity_index (entity_value, entity_type, case_id)
                        VALUES (?, ?, ?)
                        """,
                        (ent_val, ent_type, current_case),
                    )

            if persist_to_shared_vault:
                conn.commit()
                if curr_entities:
                    audit_shared_vault_write(db_index_path, current_case, "UPI_VPA_AND_PHONE", len(curr_entities))
        except Exception:
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    if matches:
        return pd.DataFrame(matches).drop_duplicates()
    return pd.DataFrame(columns=empty_cols)