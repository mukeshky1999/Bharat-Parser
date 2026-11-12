"""
Universal Multi-Source Corroboration, Split-Table RCS/SMS Joiner & Cross-App Counterparty Healer.
Fixes:
- Eliminates the `'cred'` substring collision with `"credited"` so Bank of Baroda / HDFC / SBI
  credit SMS messages are never misattributed to CRED.
- Maps TRAI DLT Sender IDs (`BOBSMS`, `BOBTXN`, `HDFCBK`, `SBIUPI`, `ICICIB`, `AXISBK`, `KOTAKB`)
  directly to their respective bank apps.
- Cross-App Counterparty & UTR Healing: when any app (e.g. CRED, PhonePe, GPay) knows the VPA/Name
  for a transaction, automatically heals missing counterparties (`Unknown` / `UPI / Bank Transfer`)
  in all other apps (e.g. HDFC & PayZapp, bob World, Slice) for the same UTR or Amount+Time!
"""

from __future__ import annotations

import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from parsers.app_overrides import (
    ACCT_MASK_RE,
    is_trai_sms_header,
    is_valid_counterparty,
    is_valid_txid,
    normalize_timestamp_value,
    parse_indian_financial_text,
)
from parsers.heuristic_engine import (
    _are_dates_compatible,
    synthesize_and_deduplicate_records,
)

# Priority 1: TRAI DLT Sender Header Tokens -> Exact Bank / Payment App
SENDER_HEADER_ATTRIBUTION: List[Tuple[Tuple[str, ...], str]] = [
    (('bobsms', 'bobtxn', 'bobcrd', 'baroda'), 'bob World (BoB)'),
    (('hdfcbk', 'hdfcbn', 'payzap', 'hdfc'), 'HDFC & PayZapp'),
    (('sbiupi', 'sbipsg', 'sbmsms', 'sbinb', 'sbiinb', 'cbssbi', 'yono'), 'YONO SBI'),
    (('icicib', 'icicit', 'imobil'), 'iMobile (ICICI)'),
    (('axisbk', 'axismb', 'axisb'), 'Axis Mobile'),
    (('kotakb', 'kotakm', 'kbank'), 'Kotak 811'),
    (('pnbone', 'pnbsms', 'punb'), 'PNB One'),
    (('canbnk', 'canara'), 'Canara ai1'),
    (('uboiin', 'unionb', 'vyom'), 'Union Bank Vyom'),
    (('idfcfb', 'idfc'), 'IDFC FIRST Bank'),
    (('indusb', 'indus'), 'IndusMobile'),
    (('fedbnk', 'fbl'), 'FedMobile'),
    (('yesbnk', 'yesb'), 'YES BANK (IRIS)'),
    (('airbnk', 'airtel', 'airt'), 'Airtel Thanks'),
    (('jiofin', 'jiopay'), 'JioFinance'),
    (('paytmb', 'paytm'), 'Paytm'),
    (('slice', 'slicep', 'indwin'), 'Slice'),
]

# Priority 2: Word-Boundary / VPA Handle Attribution inside Message Text (No bare 'cred' substring!)
BODY_ATTRIBUTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(\bcom\.phonepe\b|\bphonepe\b|@ybl\b|@ibl\b|@axl\b)', re.I), 'PhonePe'),
    (re.compile(r'(\bnbu\.paisa\b|\bgoogle\s*pay\b|\bgpay\b|@okaxis\b|@okhdfcbank\b|@okicici\b|@oksbi\b|@okbizaxis\b)', re.I), 'Google Pay'),
    (re.compile(r'(\bone97\.paytm\b|\bpaytm\b|@paytm\b|@ptyes\b|@ptaxis\b|@ptsbi\b|@pthdfc\b)', re.I), 'Paytm'),
    (re.compile(r'(\bnpci\.upiapp\b|\bbhim\b|@upi\b)', re.I), 'BHIM UPI'),
    (re.compile(r'(\bcom\.dreamplug\b|\bcred\s+app\b|\bvia\s+cred\b|@yescred\b|@axisc\b|@axisb\b)', re.I), 'CRED'),
    (re.compile(r'(\bin\.amazon\b|\bamazon\s*pay\b|@apl\b|@yapl\b|@rapl\b)', re.I), 'Amazon Pay'),
    (re.compile(r'(\bwhatsapp\b|@waicici\b|@wahdfcbank\b|@wasbi\b|@waaxis\b)', re.I), 'WhatsApp'),
    (re.compile(r'(\bsuper\.money\b|\bsupermoney\b|@superyes\b)', re.I), 'Super.money'),
    (re.compile(r'(\bnaviapp\b|\bnavi\s+upi\b|@naviaxis\b)', re.I), 'Navi'),
    (re.compile(r'(\bjupiter\b|@jupiteraxis\b)', re.I), 'Jupiter'),
    (re.compile(r'(\bepifi\b|\bfi\s+money\b)', re.I), 'Fi Money'),
    (re.compile(r'(\bslicepay\b|\bslice\b|@sliceaxis\b|sliceit@)', re.I), 'Slice'),
    (re.compile(r'(\bmobikwik\b|@ikwik\b)', re.I), 'MobiKwik'),
    (re.compile(r'(\bfreecharge\b|@freecharge\b|@fcaxis\b)', re.I), 'Freecharge'),
    (re.compile(r'(\bmyairtelapp\b|\bairtel\s+thanks\b|@airtel\b|@mairtel\b|@rxairtel\b)', re.I), 'Airtel Thanks'),
    (re.compile(r'(\bjio\.finance\b|\bjiopay\b|\bjiofinance\b|@jio\b|@jiopay\b)', re.I), 'JioFinance'),
    (re.compile(r'(\bbank\s+of\s+baroda\b|\bbob\s+world\b|@barodampay\b|@barb\b)', re.I), 'bob World (BoB)'),
    (re.compile(r'(\bhdfc\s+bank\b|\bpayzapp\b|@hdfcbank\b)', re.I), 'HDFC & PayZapp'),
    (re.compile(r'(\bstate\s+bank\s+of\s+india\b|\byono\s+sbi\b|\bsbi\s+upi\b|@sbi\b)', re.I), 'YONO SBI'),
    (re.compile(r'(\bicici\s+bank\b|\bimobile\b|@icici\b)', re.I), 'iMobile (ICICI)'),
    (re.compile(r'(\baxis\s+bank\b|@axisbank\b)', re.I), 'Axis Mobile'),
    (re.compile(r'(\bkotak\s+mahindra\b|\bkotak\s+811\b|@kotak\b|@kkbk\b)', re.I), 'Kotak 811'),
    (re.compile(r'(\bpunjab\s+national\b|\bpnb\b|@pnb\b)', re.I), 'PNB One'),
    (re.compile(r'(\bcanara\s+bank\b|@cnrb\b)', re.I), 'Canara ai1'),
    (re.compile(r'(\bunion\s+bank\b|@uboi\b|@unionbank\b)', re.I), 'Union Bank Vyom'),
    (re.compile(r'(\bidfc\s+first\b|@idfcbank\b)', re.I), 'IDFC FIRST Bank'),
    (re.compile(r'(\bindusind\b|@indus\b)', re.I), 'IndusMobile'),
    (re.compile(r'(\bfederal\s+bank\b|@federal\b|@fbl\b)', re.I), 'FedMobile'),
    (re.compile(r'(\byes\s+bank\b|@yesbank\b|@yespay\b)', re.I), 'YES BANK (IRIS)'),
]


def _infer_app_from_sms(sender_str: str, body_str: str) -> Optional[str]:
    """Accurately attributes an SMS/Notification to its originating Bank or UPI app."""
    s_low = (sender_str or '').lower()
    # 1. Check sender header first (e.g. VM-BOBSMS-S -> bob World (BoB), AD-HDFCBK -> HDFC & PayZapp)
    for tokens, app_name in SENDER_HEADER_ATTRIBUTION:
        if any(t.strip() in s_low for t in tokens):
            return app_name

    # 2. Check word-boundary regexes on combined text
    combined = f"{sender_str} {body_str}"
    for pattern, app_name in BODY_ATTRIBUTION_PATTERNS:
        if pattern.search(combined):
            return app_name
    return None


def is_background_corroboration_file(clean_path: str) -> bool:
    p = clean_path.replace('\\', '/').lower()
    bg_indicators = (
        '/telephony/databases/',
        'mmssms.db',
        'bugle_db',
        '/library/sms/sms.db',
        'notification_log',
        'notifs.db',
        'knowledgec.db',
        '/usagestats/',
        'com.coloros.mms',
        'com.oplus.mms',
        'com.android.mms',
        'com.google.android.apps.messaging',
        'com.samsung.android.messaging',
        'com.miui.smsextra',
        'service_message',
        'smart_sms',
        'finance_sms',
        'com.microsoft.android.smsorganizer',
        'fcm_queued_messages',
    )
    if any(ind in p for ind in bg_indicators):
        if not any(pkg in p for pkg in ['phonepe', 'paisa', 'one97', 'npci', 'dreamplug', 'sbi', 'icici', 'hdfc', 'coindcx', 'wazirx']):
            return True
    return False


def _try_join_android_bugle_or_mms(conn: sqlite3.Connection, tables: List[str]) -> List[Dict[str, Any]]:
    joined_rows: List[Dict[str, Any]] = []
    tables_low = {t.lower(): t for t in tables}

    if 'parts' in tables_low and 'messages' in tables_low:
        queries = [
            """
            SELECT p.text AS body,
                   COALESCE(m.received_timestamp, m.sent_timestamp, p.timestamp) AS ts,
                   COALESCE(pt.normalized_destination, pt.display_destination, m.sender_id, '') AS sender
            FROM parts p
            LEFT JOIN messages m ON p.message_id = m._id
            LEFT JOIN participants pt ON m.sender_id = pt._id
            WHERE p.text IS NOT NULL AND length(p.text) >= 18
            LIMIT 30000
            """,
            """
            SELECT p.text AS body,
                   COALESCE(m.received_timestamp, m.sent_timestamp) AS ts,
                   CAST(m.sender_id AS TEXT) AS sender
            FROM parts p
            LEFT JOIN messages m ON p.message_id = m._id
            WHERE p.text IS NOT NULL AND length(p.text) >= 18
            LIMIT 30000
            """,
        ]
        for q in queries:
            try:
                df = pd.read_sql_query(q, conn)
                if not df.empty:
                    for _, r in df.iterrows():
                        joined_rows.append({
                            'body': str(r.get('body', '')),
                            'ts': normalize_timestamp_value(r.get('ts'), 'auto'),
                            'sender': str(r.get('sender', '') or ''),
                        })
                    break
            except Exception:
                continue

    if 'part' in tables_low and 'pdu' in tables_low:
        try:
            q_mms = """
            SELECT pt.text AS body, p.date AS ts, '' AS sender
            FROM part pt
            LEFT JOIN pdu p ON pt.mid = p._id
            WHERE pt.text IS NOT NULL AND length(pt.text) >= 18
            LIMIT 15000
            """
            df_mms = pd.read_sql_query(q_mms, conn)
            for _, r in df_mms.iterrows():
                joined_rows.append({
                    'body': str(r.get('body', '')),
                    'ts': normalize_timestamp_value(r.get('ts'), 'auto'),
                    'sender': str(r.get('sender', '') or ''),
                })
        except Exception:
            pass

    return joined_rows


def harvest_corroboration_signals(db_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    signals: List[Dict[str, Any]] = []
    account_hints: List[Dict[str, str]] = []

    if not os.path.exists(db_path):
        return signals, account_hints

    conn = None
    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = [r[0] for r in cur.fetchall() if not r[0].startswith('sqlite_')]

        def _process_text_record(body_str: str, ts_str: Optional[str], sender_str: str) -> None:
            if not body_str or len(body_str) < 18:
                return
            acct_m = ACCT_MASK_RE.search(body_str)
            if acct_m:
                account_hints.append({
                    'sender': sender_str,
                    'account_mask': acct_m.group(1),
                    'raw_text': body_str[:250],
                })
            parsed = parse_indian_financial_text(body_str, default_date=ts_str, sender=sender_str)
            if parsed:
                parsed['Inferred_App'] = _infer_app_from_sms(sender_str, body_str)
                parsed['Raw_Source_Context'] = f"{sender_str} {body_str}".lower()[:250]
                signals.append(parsed)

        joined_records = _try_join_android_bugle_or_mms(conn, tables)
        for jr in joined_records:
            _process_text_record(jr['body'], jr['ts'], jr['sender'])

        for table in tables:
            if table.lower() == 'parts' and joined_records:
                continue

            try:
                cur.execute(f'PRAGMA table_info("{table}");')
                cols = [r[1] for r in cur.fetchall()]
                col_map = {re.sub(r'[^a-zA-Z0-9]', '', c.lower()): c for c in cols}
            except Exception:
                continue

            body_col = next(
                (
                    col_map[k] for k in col_map
                    if k in (
                        'body', 'text', 'message', 'snippet', 'content', 'title',
                        'attributedbody', 'receiverdata', 'msg', 'payload', 'alert',
                        'notificationbody', 'gcmbody', 'fcmbody',
                    )
                ),
                None,
            )
            date_col = next(
                (col_map[k] for k in col_map if any(x in k for x in ('date', 'time', 'timestamp', 'posttime', 'sent', 'received', 'created'))),
                None,
            )
            sender_col = next(
                (col_map[k] for k in col_map if any(x in k for x in ('address', 'sender', 'pkg', 'package', 'handle', 'creator', 'title', 'from'))),
                None,
            )

            if not body_col:
                continue

            try:
                df = pd.read_sql_query(f'SELECT * FROM "{table}" LIMIT 25000', conn)
            except Exception:
                continue

            for _, row in df.iterrows():
                raw_body = row.get(body_col)
                if raw_body is None:
                    continue
                if isinstance(raw_body, (bytes, bytearray)):
                    body_str = raw_body.decode('utf-8', errors='ignore')
                else:
                    body_str = str(raw_body)

                sender_str = str(row.get(sender_col, '')) if sender_col and pd.notna(row.get(sender_col)) else ''
                ts_str = normalize_timestamp_value(row.get(date_col), 'auto') if date_col and pd.notna(row.get(date_col)) else None
                _process_text_record(body_str, ts_str, sender_str)
    except Exception:
        # E-2: Raw-byte fallback for non-SQLite stores (Protobuf/SEGB notification streams)
        try:
            with open(db_path, 'rb') as f:
                raw_bytes = f.read(16 * 1024 * 1024)
            for m in re.finditer(rb'[\x20-\x7E]{20,500}', raw_bytes):
                try:
                    s_text = m.group(0).decode('utf-8', errors='ignore')
                    if 'upi://' in s_text.lower() or any(k in s_text.lower() for k in ('credited', 'debited', 'transferred', 'vpa', 'paid rs')):
                        parsed = parse_indian_financial_text(s_text)
                        if parsed:
                            parsed['Inferred_App'] = _infer_app_from_sms('', s_text)
                            parsed['Raw_Source_Context'] = s_text[:250].lower()
                            signals.append(parsed)
                except Exception:
                    continue
        except Exception:
            pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return signals, account_hints


def _is_placeholder_counterparty(c_str: str) -> bool:
    if not c_str or c_str == 'Unknown':
        return True
    if is_trai_sms_header(c_str):
        return True
    low = c_str.lower()
    return any(
        low.startswith(p)
        for p in ('upi / bank transfer', 'upi counterparty', 'phonepe merchant', 'bank a/c ', 'upi transfer')
    )


def heal_counterparties_across_apps(
    app_artifacts: Dict[str, Dict[str, Any]],
    owner_identifiers: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Cross-App Counterparty Healer.

    * Exact reference match (same valid transaction / UTR ID in another app): the counterparty and
      DEBIT/CREDIT direction are copied. This is a fact of the record.
    * Name <-> VPA: a name-only or VPA-only counterparty is upgraded to `Name (vpa@bank)` only when
      that name (or VPA) maps to exactly one full form on the device.
    * Same amount on a compatible date but no shared reference ID is NOT evidence of the same payment
      (M-04). Nothing is overwritten; a unique candidate is recorded in `Possible_Link` as an
      unconfirmed lead with the rule that produced it.
    """
    from parsers.heuristic_engine import _merge_two_counterparties

    known_by_txid: Dict[str, Tuple[str, str]] = {}
    known_by_amt: Dict[float, List[Tuple[Optional[str], str, str]]] = {}
    global_name_to_full: Dict[str, str] = {}
    global_vpa_to_full: Dict[str, str] = {}
    ambiguous_names: Set[str] = set()
    possible_links: Dict[Tuple[str, float, str], str] = {}

    for app_name, cats in app_artifacts.items():
        tx_df = cats.get('transactions', pd.DataFrame())
        if not isinstance(tx_df, pd.DataFrame) or tx_df.empty:
            continue
        for _, r in tx_df.iterrows():
            cparty = str(r.get('Counterparty', 'Unknown')).strip()
            if _is_placeholder_counterparty(cparty):
                continue

            # Record any `Name (vpa@bank)` pair in global dictionary
            m_pair = re.match(r'^(?:Self / Own Account - )?([^()@]+?)\s*\(([a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+)\)$', cparty)
            if m_pair:
                n_clean = m_pair.group(1).strip()
                v_clean = m_pair.group(2).strip().lower()
                full_str = f"{n_clean} ({v_clean})"
                if global_name_to_full.get(n_clean.lower(), full_str) != full_str:
                    ambiguous_names.add(n_clean.lower())  # same name, different VPAs: do not guess
                global_name_to_full[n_clean.lower()] = full_str
                global_vpa_to_full[v_clean] = full_str

            txid = str(r.get('Transaction_ID', 'N/A')).strip()
            linked = str(r.get('Linked_Reference_IDs', '') or txid).strip()
            t_type = str(r.get('Type', 'TRANSFER')).strip()
            dt = str(r.get('Date', '')) if pd.notna(r.get('Date')) else None
            try:
                amt_raw = pd.to_numeric(r.get('Amount', 0.0), errors='coerce')
                amt = round(float(amt_raw) if pd.notna(amt_raw) else 0.0, 2)
            except Exception:
                amt = 0.0

            if is_valid_txid(txid):
                prev_c, prev_t = known_by_txid.get(txid, ('Unknown', 'TRANSFER'))
                known_by_txid[txid] = (_merge_two_counterparties(prev_c, cparty), t_type if t_type in ('DEBIT', 'CREDIT') else prev_t)
            for sub_id in linked.split(' | '):
                if is_valid_txid(sub_id):
                    prev_c, prev_t = known_by_txid.get(sub_id, ('Unknown', 'TRANSFER'))
                    known_by_txid[sub_id] = (_merge_two_counterparties(prev_c, cparty), t_type if t_type in ('DEBIT', 'CREDIT') else prev_t)
            if amt > 0:
                known_by_amt.setdefault(amt, []).append((dt, cparty, t_type))

    for app_name, cats in app_artifacts.items():
        tx_df = cats.get('transactions', pd.DataFrame())
        if not isinstance(tx_df, pd.DataFrame) or tx_df.empty:
            continue
        modified = False
        tx_df = tx_df.copy()
        for idx, r in tx_df.iterrows():
            cparty = str(r.get('Counterparty', 'Unknown')).strip()
            t_type = str(r.get('Type', 'TRANSFER')).strip()
            txid = str(r.get('Transaction_ID', 'N/A')).strip()
            try:
                amt_raw = pd.to_numeric(r.get('Amount', 0.0), errors='coerce')
                amt = round(float(amt_raw) if pd.notna(amt_raw) else 0.0, 2)
            except Exception:
                amt = 0.0
            dt = str(r.get('Date', '')) if pd.notna(r.get('Date')) else None

            healed_cpty = cparty
            healed_type = None

            if txid in known_by_txid:
                cand_c, cand_t = known_by_txid[txid]
                healed_cpty = _merge_two_counterparties(healed_cpty, cand_c)
                healed_type = cand_t
            if amt in known_by_amt and dt and (_is_placeholder_counterparty(cparty) or cparty == 'Unknown'):
                cands = {cand_cpty for cand_dt, cand_cpty, _t in known_by_amt[amt]
                         if cand_dt and _are_dates_compatible(dt, cand_dt)}
                if len(cands) == 1:
                    lead = next(iter(cands))
                    possible_links[(txid, amt, dt[:10])] = (
                        f"Possible counterparty: {lead} (unconfirmed: same amount {amt:.2f} and compatible date "
                        f"in another app, no shared reference ID)"
                    )

            # Also check global Name <-> VPA dictionary
            if '@' not in healed_cpty and healed_cpty.lower() in global_name_to_full \
                    and healed_cpty.lower() not in ambiguous_names:
                healed_cpty = global_name_to_full[healed_cpty.lower()]
            elif '@' in healed_cpty and '(' not in healed_cpty and healed_cpty.lower() in global_vpa_to_full:
                healed_cpty = global_vpa_to_full[healed_cpty.lower()]

            if healed_cpty != cparty:
                tx_df.at[idx, 'Counterparty'] = healed_cpty
                modified = True
            if healed_type in ('DEBIT', 'CREDIT') and t_type == 'TRANSFER':
                tx_df.at[idx, 'Type'] = healed_type
                modified = True

        if modified:
            cats['transactions'] = synthesize_and_deduplicate_records(
                tx_df, owner_identifiers=owner_identifiers
            )

        final_tx = cats.get('transactions', pd.DataFrame())
        if possible_links and not final_tx.empty:
            final_tx = final_tx.copy()

            def _lead_for(row) -> str:
                try:
                    amt_v = round(float(row.get('Amount')), 2)
                except (TypeError, ValueError):
                    return ''
                dt_v = str(row.get('Date', '')) if pd.notna(row.get('Date')) else ''
                return possible_links.get((str(row.get('Transaction_ID', 'N/A')).strip(), amt_v, dt_v[:10]), '')

            final_tx['Possible_Link'] = final_tx.apply(_lead_for, axis=1)
            cats['transactions'] = final_tx

        # Saved-contact rows derived from the (healed) payees; labelled as derived above.
        if not final_tx.empty:
            c_rows = []
            for _, tr in final_tx.iterrows():
                cp = str(tr.get('Counterparty', 'Unknown')).strip()
                if not _is_placeholder_counterparty(cp):
                    m_b = re.match(r'^([^()]+?)\s*\(([^()]+)\)$', cp)
                    # M-05: these are payees seen in transactions, not address-book entries. They are
                    # labelled as derived, and a name with no account/VPA is not invented an identifier.
                    derived = 'DERIVED: payee seen in transactions (not an address-book entry)'
                    if m_b:
                        c_rows.append({'Contact_Name': m_b.group(1).strip(), 'Identifier': m_b.group(2).strip(),
                                       'Forensic_Provenance': derived})
                    elif '@' in cp:
                        c_rows.append({'Contact_Name': cp.split('@')[0], 'Identifier': cp,
                                       'Forensic_Provenance': derived})
            if c_rows:
                new_cnt_df = pd.DataFrame(c_rows).drop_duplicates(subset=['Identifier'])
                curr_cnt = cats.get('contacts', pd.DataFrame())
                cats['contacts'] = (
                    pd.concat([curr_cnt, new_cnt_df], ignore_index=True).drop_duplicates(subset=['Identifier']).reset_index(drop=True)
                    if isinstance(curr_cnt, pd.DataFrame) and not curr_cnt.empty
                    else new_cnt_df.reset_index(drop=True)
                )

    return app_artifacts

def reconcile_and_enrich_artifacts(
    app_artifacts: Dict[str, Dict[str, Any]],
    profiles: Dict[str, Any],
    corroboration_signals: List[Dict[str, Any]],
    account_hints: List[Dict[str, str]],
    owner_identifiers: Optional[Set[str]] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    if not corroboration_signals and not account_hints:
        return heal_counterparties_across_apps(app_artifacts, owner_identifiers), profiles

    sig_df = pd.DataFrame(corroboration_signals) if corroboration_signals else pd.DataFrame()
    if not sig_df.empty:
        sig_df['Amount'] = pd.to_numeric(sig_df['Amount'], errors='coerce')

    consumed_signal_indices: set = set()

    # 1. Heal & Enrich Existing App Transactions
    for app_name, cats in app_artifacts.items():
        tx_df = cats.get('transactions', pd.DataFrame())
        if not isinstance(tx_df, pd.DataFrame) or tx_df.empty or sig_df.empty:
            continue

        tx_df = tx_df.copy()
        tx_df['Amount'] = pd.to_numeric(tx_df['Amount'], errors='coerce')

        for idx, row in tx_df.iterrows():
            amt = row.get('Amount')
            txid = str(row.get('Transaction_ID', '')).strip()
            cparty = str(row.get('Counterparty', '')).strip()
            r_date_str = str(row.get('Date', '')) if pd.notna(row.get('Date')) else None
            t_type = str(row.get('Type', 'TRANSFER')).strip()

            matched_sig = None

            if is_valid_txid(txid):
                exact_matches = sig_df[sig_df['Transaction_ID'].astype(str) == txid]
                if not exact_matches.empty:
                    matched_sig = exact_matches.iloc[0]
                    consumed_signal_indices.add(exact_matches.index[0])

            if matched_sig is None and pd.notna(amt) and amt > 0:
                amt_candidates = sig_df[(sig_df['Amount'] - amt).abs() < 0.05]
                for cand_idx, cand_row in amt_candidates.iterrows():
                    cand_date_str = str(cand_row.get('Date', '')) if pd.notna(cand_row.get('Date')) else None
                    if _are_dates_compatible(r_date_str, cand_date_str):
                        matched_sig = cand_row
                        consumed_signal_indices.add(cand_idx)
                        break

            if matched_sig is not None:
                if not r_date_str or r_date_str in ('None', 'nan', ''):
                    if pd.notna(matched_sig.get('Date')):
                        tx_df.at[idx, 'Date'] = matched_sig['Date']

                sig_txid = str(matched_sig.get('Transaction_ID', ''))
                if is_valid_txid(sig_txid):
                    if not is_valid_txid(txid) or txid.startswith(('CARVED_', 'SLACK_', 'PG', 'RAW_', 'WAL_', 'RK_')):
                        tx_df.at[idx, 'Transaction_ID'] = sig_txid
                    if 'Linked_Reference_IDs' in tx_df.columns:
                        curr_linked = str(tx_df.at[idx, 'Linked_Reference_IDs'] or '')
                        if sig_txid not in curr_linked:
                            tx_df.at[idx, 'Linked_Reference_IDs'] = f"{curr_linked} | {sig_txid}".strip(' |')

                sig_cpty = str(matched_sig.get('Counterparty', ''))
                if _is_placeholder_counterparty(cparty) and not _is_placeholder_counterparty(sig_cpty):
                    tx_df.at[idx, 'Counterparty'] = sig_cpty

                sig_type = str(matched_sig.get('Type', 'TRANSFER'))
                if t_type == 'TRANSFER' and sig_type in ('DEBIT', 'CREDIT'):
                    tx_df.at[idx, 'Type'] = sig_type

        cats['transactions'] = synthesize_and_deduplicate_records(
            tx_df, owner_identifiers=owner_identifiers
        )

    # 2. Attribute Unconsumed Verified Bank/UPI Signals to Installed Apps
    if not sig_df.empty:
        preferred_upi_apps = [
            'Google Pay', 'PhonePe', 'Paytm', 'BHIM UPI', 'Amazon Pay',
            'CRED', 'Super.money', 'Navi', 'Jupiter',
        ]
        installed_upi = [a for a in preferred_upi_apps if a in app_artifacts]
        fallback_app = installed_upi[0] if installed_upi else 'UPI / Bank Account Ledger'

        for s_idx, s_row in sig_df.iterrows():
            if s_idx in consumed_signal_indices:
                continue
            s_txid = s_row.get('Transaction_ID')
            s_cpty = s_row.get('Counterparty')
            if not is_valid_txid(s_txid) and not (is_valid_counterparty(s_cpty) and '@' in str(s_cpty)):
                continue

            target_app = s_row.get('Inferred_App')
            if target_app is None or not isinstance(target_app, str) or not target_app.strip():
                target_app = fallback_app

            if target_app not in app_artifacts:
                app_artifacts[target_app] = {
                    'transactions': pd.DataFrame(columns=[
                        'Date', 'Transaction_ID', 'Linked_Reference_IDs', 'Amount', 'Counterparty', 'Status', 'Type', 'Risk_Level'
                    ]),
                    'chats': pd.DataFrame(),
                    'contacts': pd.DataFrame(),
                    'notifications': pd.DataFrame(),
                }
            new_tx = pd.DataFrame([{
                'Date': s_row.get('Date'),
                'Transaction_ID': str(s_txid) if is_valid_txid(s_txid) else 'N/A',
                'Linked_Reference_IDs': str(s_txid) if is_valid_txid(s_txid) else 'N/A',
                'Amount': s_row.get('Amount'),
                'Counterparty': str(s_cpty) if is_valid_counterparty(s_cpty) else 'Unknown',
                'Status': s_row.get('Status', 'SUCCESS'),
                'Type': s_row.get('Type', 'TRANSFER'),
            }])
            curr_tx = app_artifacts[target_app].get('transactions', pd.DataFrame())
            app_artifacts[target_app]['transactions'] = synthesize_and_deduplicate_records(
                pd.concat([curr_tx, new_tx], ignore_index=True),
                owner_identifiers=owner_identifiers,
            )

    # 3. Run Cross-App Counterparty & UTR Healer across all app ledgers
    app_artifacts = heal_counterparties_across_apps(app_artifacts, owner_identifiers=owner_identifiers)

    # 4. Enrich Owner Profiles with Bank Account Masks
    if account_hints:
        primary_mask = re.sub(r'\D', '', account_hints[0]['account_mask'])[-4:]
        if primary_mask:
            for _, p_dict in profiles.items():
                if isinstance(p_dict, dict):
                    if not p_dict.get('Bank_Account_Info') or p_dict.get('Bank_Account_Info') == 'N/A':
                        p_dict['Bank_Account_Info'] = f"A/c *{primary_mask}"

    return app_artifacts, profiles