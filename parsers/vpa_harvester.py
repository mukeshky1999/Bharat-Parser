"""
Raw Byte Entity Harvester, Strict NPCI UPI Handle Validator & Indian Bank IFSC Harvester.
Eliminates binary column-bleed (e.g. `user@yblzxxxxxx8119` -> `user@ybl`), WhatsApp `@broadcast` IDs,
Java `.toString()` object hashes, and leading-hyphen fragments (`-2@ybl`).
"""

import logging
import os
import re
from collections import Counter
from typing import Dict, Optional, Tuple
import pandas as pd

PHONE_REGEX = re.compile(rb'(?<![0-9.])(?:\+?91[\-\s]?|0)?([6-9]\d{9})(?![0-9])')

_EMAIL_PROVIDER_HANDLES = {
    'gmail', 'googlemail', 'yahoo', 'ymail', 'outlook', 'hotmail', 'live',
    'icloud', 'me', 'apple', 'rediffmail', 'protonmail', 'zoho', 'aol', 'msn',
}

logger = logging.getLogger(__name__)


_HARVEST_CHUNK_BYTES = 16 * 1024 * 1024  # read size; a test lowers it to exercise the chunk boundary


def is_valid_indian_mobile(phone_10: str) -> bool:
    """
    Validates a 10-digit Indian mobile number and rejects binary timers/floats
    like '6520700000', '8162800000', '6048000000', and '6666666667'.
    """
    if not phone_10 or len(phone_10) != 10 or not phone_10.isdigit():
        return False
    if phone_10[0] not in '6789':
        return False
    # Reject millisecond timers / round numbers ending in 4 or more zeros (e.g. 6520700000, 8162800000)
    if phone_10.endswith('0000'):
        return False
    # Reject numbers with 5+ identical consecutive digits (e.g. 6666666667, 9999999999, 8000001234)
    if re.search(r'(\d)\1{4,}', phone_10):
        return False
    # Reject numbers with fewer than 3 distinct digits
    if len(set(phone_10)) < 3:
        return False
    return True

# Raw candidate matcher: prefix must start and end with alphanumeric [a-zA-Z0-9]
RAW_VPA_CANDIDATE_RE = re.compile(
    rb'(?<![a-zA-Z0-9.\-_])([a-zA-Z0-9][a-zA-Z0-9.\-_]{1,62}[a-zA-Z0-9])@([a-zA-Z]{2,32})'
)

_BLOCKED_PREFIX_SUBSTRINGS = (
    'java.', 'android.', 'androidx.', 'kotlin.', 'com.', 'org.', 'net.',
    'io.', 'status', 'broadcast', 'localhost', 'schema', 'support', 'noreply',
    'no-reply', 'help', 'info', 'feedback', 'crash', 'developer', ' sentinel',
)

# 40+ RBI Indian Bank IFSC 4-Letter Prefix Directory
IFSC_BANK_DIRECTORY: Dict[str, str] = {
    'SBIN': 'State Bank of India (SBI)',
    'HDFC': 'HDFC Bank',
    'ICIC': 'ICICI Bank',
    'UTIB': 'Axis Bank',
    'KKBK': 'Kotak Mahindra Bank',
    'BARB': 'Bank of Baroda',
    'PUNB': 'Punjab National Bank (PNB)',
    'CNRB': 'Canara Bank',
    'UBIN': 'Union Bank of India',
    'IDFC': 'IDFC FIRST Bank',
    'INDB': 'IndusInd Bank',
    'FDRL': 'Federal Bank',
    'YESB': 'Yes Bank',
    'IDIB': 'Indian Bank',
    'BKID': 'Bank of India (BOI)',
    'CBIN': 'Central Bank of India',
    'UCBA': 'UCO Bank',
    'IOBA': 'Indian Overseas Bank',
    'MAHB': 'Bank of Maharashtra',
    'PSIB': 'Punjab & Sind Bank',
    'RATN': 'RBL Bank',
    'KARB': 'Karnataka Bank',
    'KVBL': 'Karur Vysya Bank',
    'SIBL': 'South Indian Bank',
    'TMBL': 'Tamilnad Mercantile Bank',
    'CIUB': 'City Union Bank',
    'JAKA': 'Jammu & Kashmir Bank',
    'BDBL': 'Bandhan Bank',
    'DCBL': 'DCB Bank',
    'CSBK': 'CSB Bank',
    'DLXB': 'Dhanlaxmi Bank',
    'NSPB': 'NSDL Payments Bank',
    'AIRP': 'Airtel Payments Bank',
    'JIOP': 'Jio Payments Bank',
    'PYTM': 'Paytm Payments Bank',
    'FINO': 'Fino Payments Bank',
    'IPOS': 'India Post Payments Bank (IPPB)',
    'AUBL': 'AU Small Finance Bank',
    'ESFB': 'Equitas Small Finance Bank',
    'UJVN': 'Ujjivan Small Finance Bank',
    'JSFB': 'Jana Small Finance Bank',
    'SURY': 'Suryoday Small Finance Bank',
    'USFB': 'Utkarsh Small Finance Bank',
    'ESAF': 'ESAF Small Finance Bank',
}

IFSC_REGEX = re.compile(
    rb'\b(?:' + b'|'.join(k.encode('ascii') for k in IFSC_BANK_DIRECTORY) + rb')0[A-Z0-9]{6}\b'
)

# Comprehensive NPCI UPI Handle (@suffix) -> (Payment App / PSP, Issuing / Sponsor Bank)
UPI_HANDLE_DIRECTORY: Dict[str, Tuple[str, str]] = {
    'ybl': ('PhonePe', 'Yes Bank'),
    'ibl': ('PhonePe', 'ICICI Bank'),
    'axl': ('PhonePe', 'Axis Bank'),
    'okhdfcbank': ('Google Pay', 'HDFC Bank'),
    'okicici': ('Google Pay', 'ICICI Bank'),
    'okaxis': ('Google Pay', 'Axis Bank'),
    'oksbi': ('Google Pay', 'State Bank of India (SBI)'),
    'okbizaxis': ('Google Pay Business', 'Axis Bank'),
    'paytm': ('Paytm', 'Paytm / Partner Banks'),
    'ptyes': ('Paytm', 'Yes Bank'),
    'ptaxis': ('Paytm', 'Axis Bank'),
    'ptsbi': ('Paytm', 'State Bank of India (SBI)'),
    'pthdfc': ('Paytm', 'HDFC Bank'),
    'pty': ('Paytm', 'Paytm Partner Bank'),
    'upi': ('BHIM UPI', 'NPCI / Linked Bank'),
    'bhim': ('BHIM UPI', 'NPCI'),
    'apl': ('Amazon Pay', 'Axis Bank'),
    'yapl': ('Amazon Pay', 'Yes Bank'),
    'rapl': ('Amazon Pay', 'RBL Bank'),
    'ikwik': ('MobiKwik', 'HDFC / Partner Bank'),
    'freecharge': ('Freecharge', 'Axis Bank'),
    'fcaxis': ('Freecharge', 'Axis Bank'),
    'waicici': ('WhatsApp Pay', 'ICICI Bank'),
    'wahdfcbank': ('WhatsApp Pay', 'HDFC Bank'),
    'wasbi': ('WhatsApp Pay', 'State Bank of India (SBI)'),
    'waaxis': ('WhatsApp Pay', 'Axis Bank'),
    'superyes': ('Super.money (Flipkart)', 'Yes Bank'),
    'naviaxis': ('Navi UPI', 'Axis Bank'),
    'jupiteraxis': ('Jupiter Money', 'Axis Bank'),
    'fbl': ('Fi Money / FedMobile', 'Federal Bank'),
    'sliceaxis': ('Slice', 'Axis Bank'),
    'fam': ('FamPay', 'IDFC FIRST / Partner Bank'),
    'airtel': ('Airtel Thanks', 'Airtel Payments Bank'),
    'mairtel': ('Airtel Thanks', 'Airtel Payments Bank'),
    'rxairtel': ('Razorpay / Airtel', 'Airtel Payments Bank'),
    'jio': ('JioFinance / MyJio', 'Jio Payments Bank'),
    'jiopay': ('JioFinance', 'Jio Payments Bank'),
    'tapicici': ('Tata Neu', 'ICICI Bank'),
    'abfspay': ('Bajaj Finserv', 'Axis / Partner Bank'),
    'sbi': ('YONO SBI', 'State Bank of India (SBI)'),
    'sbipay': ('BHIM SBI Pay', 'State Bank of India (SBI)'),
    'icici': ('iMobile Pay', 'ICICI Bank'),
    'hdfcbank': ('HDFC MobileBanking / PayZapp', 'HDFC Bank'),
    'pz': ('PayZapp', 'HDFC Bank'),
    'axisbank': ('Axis Mobile', 'Axis Bank'),
    'axisb': ('CRED / Axis', 'Axis Bank'),
    'yescred': ('CRED', 'Yes Bank'),
    'axisc': ('CRED', 'Axis Bank'),
    'kotak': ('Kotak 811', 'Kotak Mahindra Bank'),
    'kkbk': ('Kotak 811', 'Kotak Mahindra Bank'),
    'barodampay': ('bob World', 'Bank of Baroda'),
    'barb': ('bob World', 'Bank of Baroda'),
    'pnb': ('PNB One', 'Punjab National Bank'),
    'cnrb': ('Canara ai1', 'Canara Bank'),
    'uboi': ('Union Bank Vyom', 'Union Bank of India'),
    'unionbank': ('Union Bank Vyom', 'Union Bank of India'),
    'idfcbank': ('IDFC FIRST Mobile', 'IDFC FIRST Bank'),
    'indus': ('IndusMobile', 'IndusInd Bank'),
    'federal': ('FedMobile', 'Federal Bank'),
    'yesbank': ('IRIS by YES BANK', 'Yes Bank'),
    'yespay': ('YES PAY', 'Yes Bank'),
    'yesg': ('Groww UPI', 'Yes Bank'),
    'postbank': ('IPPB Mobile / DakPay', 'India Post Payments Bank'),
    'indianbank': ('IndOASIS', 'Indian Bank'),
    'cbin': ('Cent Mobile', 'Central Bank of India'),
    'boi': ('BOI Mobile', 'Bank of India'),
    'uco': ('UCO mBanking', 'UCO Bank'),
    'rbl': ('RBL MoBank', 'RBL Bank'),
    'citibank': ('Citibank UPI', 'Citibank / Axis'),
    'citi': ('Citibank UPI', 'Citibank / Axis'),
    'hsbc': ('HSBC UPI', 'HSBC Bank'),
    'dbs': ('DBS digibank', 'DBS Bank'),
    'scb': ('Standard Chartered UPI', 'Standard Chartered'),
    'equitas': ('Equitas Mobile', 'Equitas Small Finance Bank'),
    'aubank': ('AU 0101', 'AU Small Finance Bank'),
    'bandhan': ('mBandhan', 'Bandhan Bank'),
    'kvb': ('KVB DLite', 'Karur Vysya Bank'),
    'kbl': ('KBL Mobile', 'Karnataka Bank'),
    'sib': ('SIB Mirror+', 'South Indian Bank'),
    'fino': ('FinoPay', 'Fino Payments Bank'),
    'nsdl': ('NSDL Jiffy', 'NSDL Payments Bank'),
}

# Unambiguous primary handles that frequently suffer adjacent SQLite binary column bleed
_BLEED_SAFE_HANDLES = (
    'okhdfcbank', 'okicici', 'okaxis', 'oksbi', 'okbizaxis',
    'wahdfcbank', 'waicici', 'waaxis', 'wasbi',
    'superyes', 'naviaxis', 'jupiteraxis', 'sliceaxis',
    'barodampay', 'freecharge', 'hdfcbank', 'axisbank',
    'paytm', 'ptyes', 'ptaxis', 'ptsbi', 'pthdfc',
    'ybl', 'ibl', 'axl',
)


def clean_and_validate_vpa(raw_vpa: str) -> Optional[str]:
    """
    Validates a candidate VPA string against known NPCI handles and strips
    trailing SQLite binary column bleed (e.g. `9027407510-2@yblzxxxxxx8119` -> `9027407510-2@ybl`).
    Returns the canonical VPA string or None if invalid.
    """
    if not raw_vpa or '@' not in raw_vpa:
        return None
    s = str(raw_vpa).strip().lower()
    parts = s.split('@')
    if len(parts) != 2:
        return None
    prefix, suffix = parts[0].strip(), parts[1].strip()
    if suffix in _EMAIL_PROVIDER_HANDLES or any(suffix.startswith(ep + '.') for ep in _EMAIL_PROVIDER_HANDLES):
        return None

    # Prefix must be 3..64 chars, start & end with alphanumeric, and not contain code/class tokens
    if len(prefix) < 3 or len(prefix) > 64:
        return None
    if not (prefix[0].isalnum() and prefix[-1].isalnum()):
        return None
    if any(b in prefix for b in _BLOCKED_PREFIX_SUBSTRINGS):
        return None
    if prefix.isdigit() and len(prefix) < 10:
        return None

    # Exact handle match
    if suffix in UPI_HANDLE_DIRECTORY:
        return f"{prefix}@{suffix}"

    # Check if suffix is a known handle with adjacent SQLite binary column bleed (e.g. `yblwaccount`, `yblzxxxxxx8119`)
    for h in _BLEED_SAFE_HANDLES:
        if suffix.startswith(h) and len(suffix) > len(h):
            return f"{prefix}@{h}"

    return None


def resolve_vpa_attribution(vpa: str) -> Tuple[str, str]:
    """Returns (PSP_App, Sponsor_Bank) for a given UPI VPA."""
    if not vpa or '@' not in vpa:
        return ('Unknown App', 'Unknown Bank')
    suffix = vpa.split('@', 1)[-1].lower().strip()
    if suffix in UPI_HANDLE_DIRECTORY:
        return UPI_HANDLE_DIRECTORY[suffix]
    return ('UPI / Banking App', f'@{suffix} Handle')


def resolve_ifsc_bank(ifsc: str) -> str:
    """Returns the full RBI Bank Name for an 11-character IFSC code."""
    if not ifsc or len(ifsc) < 4:
        return 'Indian Bank'
    return IFSC_BANK_DIRECTORY.get(ifsc[:4].upper(), 'Scheduled Indian Bank')


def harvest_ifsc_from_file(file_path: str) -> pd.DataFrame:
    """Scans a file in 16MB streaming chunks for valid 11-character Indian Bank IFSC codes."""
    ifsc_counter: Counter = Counter()
    if not os.path.exists(file_path):
        return pd.DataFrame(columns=['IFSC_Code', 'Bank_Name', 'Occurrences'])
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(16 * 1024 * 1024):
                for ifsc in IFSC_REGEX.findall(chunk):
                    try:
                        ifsc_str = ifsc.decode('ascii').upper()
                        ifsc_counter[ifsc_str] += 1
                    except Exception:
                        continue
    except Exception as exc:  # a read failure must not look like 'nothing found'
        logger.warning('harvest incomplete for %s: %s', file_path, exc)

    rows = [
        {'IFSC_Code': code, 'Bank_Name': resolve_ifsc_bank(code), 'Occurrences': cnt}
        for code, cnt in ifsc_counter.most_common()
    ]
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['IFSC_Code', 'Bank_Name', 'Occurrences'])


def harvest_entities_from_file(file_path: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Carves strictly validated NPCI UPI VPAs and 10-digit Indian mobile numbers
    in 16MB streaming chunks from SQLite, WAL files, and caches.
    """
    vpa_counter: Counter = Counter()
    phone_counter: Counter = Counter()

    if not os.path.exists(file_path):
        return (
            pd.DataFrame(columns=['UPI_VPA', 'PSP_App', 'Sponsor_Bank', 'Occurrences']),
            pd.DataFrame(columns=['Phone_Number', 'Occurrences']),
        )

    try:
        CHUNK = _HARVEST_CHUNK_BYTES
        OVERLAP = 64
        prev_tail = b''
        with open(file_path, 'rb') as f:
            while True:
                raw = f.read(CHUNK)
                if not raw:
                    break
                chunk = prev_tail + raw
                for m in RAW_VPA_CANDIDATE_RE.finditer(chunk):
                    if len(prev_tail) > 0 and m.start() < len(prev_tail):
                        if m.end() <= len(prev_tail):
                            continue
                    end_pos = m.end()
                    if end_pos < len(chunk) and chunk[end_pos:end_pos + 1] == b'.':
                        continue
                    try:
                        cand_str = f"{m.group(1).decode('ascii')}@{m.group(2).decode('ascii')}"
                    except UnicodeDecodeError:
                        continue
                    valid_vpa = clean_and_validate_vpa(cand_str)
                    if valid_vpa:
                        vpa_counter[valid_vpa] += 1

                # Phone numbers are matched on the chunk with the previous tail in front, so a number split across
                # the 16 MB boundary is found (Q-2b); a match lying wholly inside the tail was counted last time.
                for pm in PHONE_REGEX.finditer(chunk):
                    if pm.end() <= len(prev_tail):
                        continue
                    try:
                        std_phone = pm.group(1).decode('ascii')
                        if is_valid_indian_mobile(std_phone):
                            phone_counter[std_phone] += 1
                    except UnicodeDecodeError:
                        continue

                prev_tail = chunk[-OVERLAP:] if len(chunk) >= OVERLAP else chunk
    except Exception as exc:  # a read failure must not look like 'nothing found'
        logger.warning('harvest incomplete for %s: %s', file_path, exc)

    vpa_rows = []
    for vpa_val, count in vpa_counter.most_common():
        psp, bank = resolve_vpa_attribution(vpa_val)
        vpa_rows.append({
            'UPI_VPA': vpa_val,
            'PSP_App': psp,
            'Sponsor_Bank': bank,
            'Occurrences': count,
        })

    vpa_df = (
        pd.DataFrame(vpa_rows)
        if vpa_rows
        else pd.DataFrame(columns=['UPI_VPA', 'PSP_App', 'Sponsor_Bank', 'Occurrences'])
    )
    phone_df = pd.DataFrame(
        phone_counter.most_common(), columns=['Phone_Number', 'Occurrences']
    )
    return vpa_df, phone_df
