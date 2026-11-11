"""
Account Profiler & Unified Master Device Owner Dossier Engine.
Synthesizes every detail about the phone owner across all apps, shared_prefs XMLs,
iOS Plists, SQLite KYC/profile tables, Bank SMS greetings, VPA handles, and Bank Account masks
into ONE consolidated Master Owner Dossier.
"""

from __future__ import annotations

from collections import Counter
import json
import os
import plistlib
import re
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
import pandas as pd

from parsers.vpa_harvester import (
    IFSC_BANK_DIRECTORY,
    clean_and_validate_vpa,
    is_valid_indian_mobile,
    resolve_ifsc_bank,
    resolve_vpa_attribution,
)

PHONE_RE = re.compile(r'(?:\+?91[\-\s]?)?([6-9]\d{9})\b')
EMAIL_RE = re.compile(r'\b([a-zA-Z0-9._%+\-]{3,45}@(?:gmail|yahoo|outlook|hotmail|icloud|rediffmail|protonmail|live|zoho)\.[a-zA-Z]{2,6})\b', re.IGNORECASE)
IFSC_STR_RE = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')
MASKED_ACC_RE = re.compile(r'(?:A/c|Acct|Account|[Xx\*]{2,})\s*[:\-No.\s]*([Xx\*]*\d{3,6})\b', re.IGNORECASE)
FULL_ACC_NUM_RE = re.compile(r'^\d{9,18}$')

_INVALID_NAME_TOKENS = (
    'true', 'false', 'null', 'none', 'nan', 'unknown', 'unset', 'nil', 'empty',
    'user', 'default', 'string', 'java.', 'android.', 'com.', 'org.', 'http',
    'view', 'controller', 'activity', 'fragment', 'config', 'version', 'production', 'release',
    'googlepay', 'google pay', 'gpay', 'phonepe', 'paytm', 'whatsapp', 'amazon',
    'bhim', 'cred', 'coindcx', 'wazirx', 'coinswitch', 'binance', 'slice', 'jupiter',
    'airtel', 'jio', 'kotak', 'hdfc', 'icici', 'axis', 'sbi', 'yono', 'customer',
    'upi user', 'valued customer', 'account holder', 'dear customer', 'learn more',
)


def _validate_bank_account_info(val_str: str) -> Optional[str]:
    s = val_str.strip()
    if len(s) < 4 or len(s) > 65:
        return None
    s_low = s.lower()
    if any(bad in s_low for bad in (
        'view', 'controller', 'activity', 'fragment', 'listener', 'adapter',
        'layout', 'widget', 'java.', 'android.', 'com.', 'org.', 'true', 'false',
        'null', 'none', 'http', 'config', 'pref', 'boolean', 'enable', 'disable',
    )):
        return None

    ifsc_m = IFSC_STR_RE.search(s.upper())
    if ifsc_m and ifsc_m.group(1)[:4] in IFSC_BANK_DIRECTORY:
        code = ifsc_m.group(1)
        return f"{resolve_ifsc_bank(code)} (IFSC: {code})"

    mask_m = MASKED_ACC_RE.search(s)
    if mask_m:
        digits = re.sub(r'\D', '', mask_m.group(1))
        if len(digits) >= 3:
            return f"A/c *{digits[-4:]}"

    if FULL_ACC_NUM_RE.match(s) and len(s) not in (10, 13):
        return f"A/c *{s[-4:]}"

    if ' bank' in s_low and re.match(r'^[A-Za-z0-9\s.&()\-]{6,50}$', s):
        return s

    return None


def _inspect_key_val(key: str, val: Any, profile_data: Dict[str, Any]) -> None:
    if val is None or isinstance(val, (bool, dict, list)):
        return
    val_str = str(val).strip()
    if not val_str or val_str.lower() in ('null', 'none', 'nan', 'true', 'false', ''):
        return

    k_lower = str(key).lower()

    if (val_str.startswith('{') and val_str.endswith('}')) or (val_str.startswith('[') and val_str.endswith(']')):
        try:
            nested = json.loads(val_str)
            _walk_structure(nested, profile_data, parent_key=k_lower)
            return
        except Exception:
            pass

    # 1. Account Holder Name
    if any(
        x in k_lower
        for x in ['user_name', 'username', 'profile_name', 'account_name', 'full_name', 'customer_name', 'display_name', 'holder_name', 'push_name', 'kyc_name']
    ) and not profile_data.get('Account_Name'):
        if (
            3 <= len(val_str) <= 50
            and not any(c.isdigit() for c in val_str)
            and '@' not in val_str
            and not any(tok in val_str.lower() for tok in _INVALID_NAME_TOKENS)
            and re.match(r'^[A-Za-z][A-Za-z\s.]{2,48}$', val_str)
        ):
            profile_data['Account_Name'] = val_str

    # 2. Owner Email Address
    if (
        any(x in k_lower for x in ['email', 'mail', 'gmail', 'google_account', 'login_id'])
        or '@' in val_str
    ) and not profile_data.get('Owner_Email'):
        em_m = EMAIL_RE.search(val_str)
        if em_m:
            profile_data['Owner_Email'] = em_m.group(1).lower()

    # 3. Primary VPA (Strictly validated against NPCI handles)
    if (
        any(x in k_lower for x in ['vpa', 'upi_id', 'handle', 'virtual_address', 'primary_vpa'])
        or '@' in val_str
    ) and not profile_data.get('Primary_VPA'):
        for token in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', val_str):
            valid_vpa = clean_and_validate_vpa(token)
            if valid_vpa:
                profile_data['Primary_VPA'] = valid_vpa
                vpa_phone_m = re.match(r'^([6-9]\d{9})\b', valid_vpa.split('@')[0])
                if vpa_phone_m and is_valid_indian_mobile(vpa_phone_m.group(1)):
                    profile_data['Registered_Phone'] = vpa_phone_m.group(1)
                break

    # 4. Registered Phone Number
    if any(
        x in k_lower
        for x in ['mobile', 'phone', 'msisdn', 'contact_number', 'registered_number', 'user_mobile', 'sim_number', 'registration_jid']
    ) and not profile_data.get('Registered_Phone'):
        match = PHONE_RE.search(val_str)
        if match and is_valid_indian_mobile(match.group(1)):
            profile_data['Registered_Phone'] = match.group(1)

    # 5. Linked Bank Account / IFSC
    if any(
        x in k_lower
        for x in ['bank', 'account_no', 'masked_acc', 'account_num', 'ifsc', 'issuer_name']
    ) and not profile_data.get('Bank_Account_Info'):
        valid_bank = _validate_bank_account_info(val_str)
        if valid_bank:
            profile_data['Bank_Account_Info'] = valid_bank


def _walk_structure(obj: Any, profile_data: Dict[str, Any], parent_key: str = '') -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk_structure(v, profile_data, parent_key=str(k))
            elif isinstance(v, (bytes, bytearray)):
                try:
                    sub = plistlib.loads(v)
                    _walk_structure(sub, profile_data, parent_key=str(k))
                except Exception:
                    try:
                        _inspect_key_val(str(k), v.decode('utf-8', errors='ignore'), profile_data)
                    except Exception:
                        pass
            else:
                _inspect_key_val(str(k), v, profile_data)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _walk_structure(item, profile_data, parent_key=parent_key)
            elif isinstance(item, str):
                _inspect_key_val(parent_key, item, profile_data)


def extract_account_profile(file_path: str) -> Dict[str, Any]:
    profile_data: Dict[str, Any] = {}
    if not os.path.exists(file_path):
        return profile_data

    lower_path = file_path.lower()

    if lower_path.endswith('.plist'):
        try:
            with open(file_path, 'rb') as f:
                data = plistlib.load(f)
            _walk_structure(data, profile_data)
        except Exception:
            pass

    elif lower_path.endswith('.xml'):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for elem in root.iter():
                name_attr = elem.attrib.get('name', '')
                val = elem.text if elem.text is not None else elem.attrib.get('value', '')
                if val:
                    _inspect_key_val(name_attr, val, profile_data)
        except Exception:
            try:
                with open(file_path, 'rb') as f:
                    raw_text = f.read().decode('utf-8', errors='ignore')
                for token in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', raw_text):
                    valid_vpa = clean_and_validate_vpa(token)
                    if valid_vpa:
                        profile_data.setdefault('Primary_VPA', valid_vpa)
                        vpa_phone_m = re.match(r'^([6-9]\d{9})\b', valid_vpa.split('@')[0])
                        if vpa_phone_m and is_valid_indian_mobile(vpa_phone_m.group(1)):
                            profile_data['Registered_Phone'] = vpa_phone_m.group(1)
                        break
                em_m = EMAIL_RE.search(raw_text)
                if em_m:
                    profile_data.setdefault('Owner_Email', em_m.group(1).lower())
            except Exception:
                pass

    return profile_data


def build_unified_owner_dossier(
    profiles: Dict[str, Any],
    app_artifacts: Dict[str, Dict[str, Any]],
    vpa_df: pd.DataFrame,
    ifsc_df: pd.DataFrame,
    account_hints: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Synthesizes a single, comprehensive Master Device Owner Dossier combining all discovered
    attributes across every installed app, SQLite table, VPA directory, IFSC directory, and SMS hint.
    """
    phone_votes: Counter = Counter()
    names_found: List[str] = []
    emails_found: List[str] = []
    owner_vpas: List[str] = []
    bank_accounts: List[str] = []
    key_handles: List[str] = []
    per_app_rows: List[Dict[str, str]] = []

    for app_name, p_data in profiles.items():
        if app_name.startswith('_') or not isinstance(p_data, dict):
            continue

        ph = str(p_data.get('Registered_Phone', '') or '').strip()
        nm = str(p_data.get('Account_Name', '') or '').strip()
        vp = str(p_data.get('Primary_VPA', '') or '').strip()
        bk = str(p_data.get('Bank_Account_Info', '') or '').strip()
        em = str(p_data.get('Owner_Email', '') or '').strip()
        keys = p_data.get('Decrypted_Key_Handles', [])

        if is_valid_indian_mobile(ph):
            phone_votes[ph] += 2
        if vp and '@' in vp and vp not in ('Not Found', 'Unknown'):
            owner_vpas.append(vp)
            vpa_ph_m = re.match(r'^([6-9]\d{9})\b', vp.split('@')[0])
            if vpa_ph_m and is_valid_indian_mobile(vpa_ph_m.group(1)):
                # Phone embedded inside an owner VPA gets +5 weight
                phone_votes[vpa_ph_m.group(1)] += 5
        if nm and nm not in ('Not Found', 'Unknown', 'UNSET'):
            names_found.append(f"{nm} ({app_name})")
        if em and '@' in em:
            emails_found.append(f"{em} ({app_name})")
        if bk and bk not in ('Not Found', 'Unknown', 'N/A', '0'):
            bank_accounts.append(f"{bk} [{app_name}]")
        if isinstance(keys, list):
            for k in keys[:4]:
                key_handles.append(f"{app_name}: {k}")

        if any(x and x not in ('Not Found', 'Unknown', 'N/A', '0') for x in (ph, nm, vp, bk, em)):
            per_app_rows.append({
                'Application': app_name,
                'Registered_Mobile': ph or '—',
                'Account_Holder_Name': nm or '—',
                'Owner_UPI_ID': vp or '—',
                'Linked_Bank_Account': bk or '—',
                'Registered_Email': em or '—',
            })

    # Determine Primary Consensus Mobile Number
    primary_mobile = phone_votes.most_common(1)[0][0] if phone_votes else 'Not Found'
    secondary_mobiles = [p for p, _ in phone_votes.most_common() if p != primary_mobile]

    # Mine additional Owner VPAs from `vpa_df` that contain the owner's Primary Mobile Number
    if primary_mobile != 'Not Found' and isinstance(vpa_df, pd.DataFrame) and not vpa_df.empty:
        for _, v_row in vpa_df.iterrows():
            cand_vpa = str(v_row.get('UPI_VPA', '')).strip()
            if cand_vpa.startswith(primary_mobile) and cand_vpa not in owner_vpas:
                owner_vpas.append(cand_vpa)

    # Mine Bank Account Masks & Sender Bank Names from SMS `account_hints`
    if account_hints:
        sender_bank_map = {
            'HDFC': 'HDFC Bank',
            'BOBSMS': 'Bank of Baroda',
            'BOBTXN': 'Bank of Baroda',
            'SBI': 'State Bank of India (SBI)',
            'ICICI': 'ICICI Bank',
            'AXIS': 'Axis Bank',
            'KOTAK': 'Kotak Mahindra Bank',
            'PNB': 'Punjab National Bank',
            'CANBNK': 'Canara Bank',
            'IDFC': 'IDFC FIRST Bank',
            'INDUS': 'IndusInd Bank',
            'YES': 'Yes Bank',
            'PAYTM': 'Paytm Payments Bank',
            'AIRTEL': 'Airtel Payments Bank',
            'JIO': 'Jio Payments Bank',
        }
        for hint in account_hints:
            mask_raw = str(hint.get('account_mask', '')).strip()
            digits = re.sub(r'\D', '', mask_raw)
            if len(digits) >= 3:
                norm_mask = f"A/c *{digits[-4:]}"
                sender_up = str(hint.get('sender', '')).upper()
                bank_label = next((b_name for k_tok, b_name in sender_bank_map.items() if k_tok in sender_up), None)
                entry = f"{bank_label} ({norm_mask})" if bank_label else norm_mask
                bank_accounts.append(entry)

            # Check if SMS greeting has "Dear <Name>,"
            raw_txt = str(hint.get('raw_text', ''))
            dear_m = re.search(r'\b(?:Dear|Hi|Hello)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})\s*[,!]', raw_txt)
            if dear_m:
                cand_nm = dear_m.group(1).strip()
                if cand_nm.lower() not in _INVALID_NAME_TOKENS and len(cand_nm) >= 3:
                    names_found.append(f"{cand_nm} (Bank SMS)")

    # Include top discovered Bank IFSC codes in Linked Bank Accounts
    if isinstance(ifsc_df, pd.DataFrame) and not ifsc_df.empty:
        for _, i_row in ifsc_df.head(5).iterrows():
            code = str(i_row.get('IFSC_Code', '')).strip()
            b_name = str(i_row.get('Bank_Name', '')).strip()
            if code:
                bank_accounts.append(f"{b_name} (IFSC: {code})")

    # Deduplicate while preserving order
    unique_vpas = list(dict.fromkeys(owner_vpas))
    vpa_details = []
    for v in unique_vpas:
        psp, sp_bank = resolve_vpa_attribution(v)
        vpa_details.append(f"{v} ({psp} / {sp_bank})")

    unique_names = list(dict.fromkeys(names_found))
    unique_emails = list(dict.fromkeys(emails_found))
    unique_banks = list(dict.fromkeys(bank_accounts))

    # Build Active Financial Apps Footprint Summary
    active_apps_summary = []
    circle_delegated_users = []
    for app_name, cats in app_artifacts.items():
        tx_cnt = len(cats.get('transactions', pd.DataFrame()))
        ch_cnt = len(cats.get('chats', pd.DataFrame()))
        if tx_cnt > 0 or ch_cnt > 0 or app_name in [r['Application'] for r in per_app_rows]:
            active_apps_summary.append(f"{app_name} ({tx_cnt} txns, {ch_cnt} msgs)")
        tx = cats.get('transactions', pd.DataFrame())
        if isinstance(tx, pd.DataFrame) and not tx.empty and 'Delegation_Flag' in tx.columns:
            del_rows = tx[tx['Delegation_Flag'] == True]
            for _, dr in del_rows.iterrows():
                circle_delegated_users.append(f"{dr.get('Counterparty', 'Delegated User')} ({app_name})")

    return {
        'Primary_Mobile': primary_mobile,
        'Secondary_Mobiles': ', '.join(secondary_mobiles) if secondary_mobiles else 'None',
        'All_Mobiles_List': ([primary_mobile] if primary_mobile != 'Not Found' else []) + secondary_mobiles,
        'Account_Holder_Names': ' | '.join(unique_names) if unique_names else 'Not Found in Plaintext Prefs',
        'Owner_Emails': ' | '.join(unique_emails) if unique_emails else 'Not Found',
        'Owner_VPAs_Raw': unique_vpas,
        'Owner_VPAs_Detailed': ' | '.join(vpa_details) if vpa_details else 'Not Found',
        'Linked_Bank_Accounts': ' | '.join(unique_banks[:10]) if unique_banks else 'Not Found',
        'Active_Financial_Apps': ', '.join(active_apps_summary) if active_apps_summary else 'None',
        'Security_Key_Handles': ', '.join(list(dict.fromkeys(key_handles))[:10]) if key_handles else 'None',
        'UPI_Circle_Delegations': ' | '.join(list(dict.fromkeys(circle_delegated_users))) if circle_delegated_users else 'None',
        'Per_App_Breakdown_DF': pd.DataFrame(per_app_rows) if per_app_rows else pd.DataFrame(
            columns=['Application', 'Registered_Mobile', 'Account_Holder_Name', 'Owner_UPI_ID', 'Linked_Bank_Account', 'Registered_Email']
        ),
    }