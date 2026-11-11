"""
App-Specific Schema Overrides, Indian Bank SMS Counterparty Parser & Promo/Header Blocker.
Fixes:
- Blocks TRAI DLT SMS Sender Headers (`VM-BOBSMS-S`, `VD-BOBTXN`, `JX-BOBSMS`, `AD-HDFCBK`) from ever
  appearing as a Counterparty.
- Blocks telecom recharge catalog & CTA button strings (`Learn More`, `Unlimited calls`, `2 GB data`).
- Extracts counterparties from HDFC, SBI, BoB, ICICI, Axis, and Kotak SMS formats (`from A/c *2820 to <Name>`,
  `Dr. from ... Cr. to <Name>`, `trf to <Name>`, `linked to VPA <VPA>`).
- Never uses the phone owner's own debited/credited account mask (`Bank A/c *2820`) as the Counterparty.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import zlib
import pandas as pd

from parsers.vpa_harvester import clean_and_validate_vpa

_COCOA_OFFSET_SECONDS = 978307200

AMOUNT_KEYS = [
    'amount', 'txnamount', 'transactionamount', 'totalamount', 'amt',
    'paidamount', 'receivedamount', 'debitamount', 'creditamount', 'billamount',
    'transferamount', 'netamount', 'inramount', 'paymentamount', 'principalamount',
    'amountinpaise', 'amountminor', 'payeramount', 'payeeamount', 'settlementamount',
]

DATE_KEYS = [
    'timestamp', 'time', 'date', 'createdat', 'created_at', 'txntime', 'txndate',
    'transactiontime', 'transactiondate', 'bookingdate', 'initiationtime',
    'completedat', 'updatedat', 'creationtime', 'paymenttime', 'messagetimestamp',
]

PAYER_KEYS = [
    'payervpa', 'sendervpa', 'fromvpa', 'remittervpa', 'payername', 'sendername',
    'remitter', 'payer', 'sender', 'from', 'debitedfrom',
]

PAYEE_KEYS = [
    'payeevpa', 'receivervpa', 'recipientvpa', 'tovpa', 'beneficiaryvpa',
    'payeename', 'receivername', 'recipientname', 'beneficiaryname', 'merchantname',
    'billername', 'operatorname', 'providername', 'storename', 'creditorname',
    'accountholdername', 'payee', 'receiver', 'recipient', 'beneficiary', 'merchant',
]

CPTY_KEYS = [
    'counterparty', 'counterpartyvpa', 'counterpartyname', 'payeevpa', 'payeename',
    'merchantname', 'billername', 'operatorname', 'providername', 'storename',
    'vpa', 'receivername', 'beneficiaryname', 'payervpa', 'payername', 'sendername',
    'heading', 'subheading', 'narration', 'peername', 'recipient', 'payee',
    'receiver', 'merchant', 'remitter', 'beneficiary', 'title', 'subtitle',
]

TXID_KEYS = [
    'transactionid', 'txnid', 'transaction_id', 'txn_id', 'banktxnid', 'utr',
    'referenceid', 'orderid', 'order_id', 'serialno', 'paymentid', 'upi_txn_id',
    'custrefno', 'bankrefno', 'npcitxnid', 'refno', 'workflowid',
]

STATUS_KEYS = [
    'status', 'txnstatus', 'state', 'paymentstatus', 'orderstatus', 'result',
    'transactionstatus', 'paystatus',
]

TYPE_KEYS = [
    'transactiontype', 'txntype', 'paymenttype', 'entrytype', 'flowtype',
    'direction', 'drcr', 'flow', 'type',
]

_VALID_DIRECTION_TOKENS = {
    'DEBIT', 'CREDIT', 'DR', 'CR', 'SENT', 'RECEIVED', 'PAID',
    'WITHDRAW', 'WITHDRAWAL', 'DEPOSIT', 'REFUND', 'OUT', 'IN',
    'P2M', 'RECHARGE', 'BILL',
}

INDIAN_CURRENCY_RE = re.compile(
    r'(?:INR|Rs\.?|₹)\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)\b',
    re.IGNORECASE,
)
UTR_12_RE = re.compile(
    r'(?:UTR|Ref(?:\s*No\.?)?|UPI(?:\s*Ref)?|Txn(?:\s*ID)?|IMPS(?:\s*Ref)?)\s*[:\-No.\s]*([0-9]{12})\b',
    re.IGNORECASE,
)
UPI_SLASH_UTR_RE = re.compile(
    r'\b(?:UPI|IMPS|NEFT)/(?:DR|CR|P2A|P2P|P2M)?/?([0-9]{12})(?:/([A-Za-z0-9\s.\-_]{2,35}))?',
    re.IGNORECASE,
)
UPI_NAME_AFTER_UTR_RE = re.compile(r'\b[0-9]{12}[/\-]([A-Za-z][A-Za-z0-9\s.\-_]{2,30})(?:[/\-]|$)')
PHONEPE_TID_RE = re.compile(r'\b(T(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\d{6,16})\b')
NPCI_35_ID_RE = re.compile(
    r'\b((?:YBL|IBL|AXL|OKH|OKI|OKA|OKS|PTM|PYT|UPI|SBI|ICI|HDF|AXIS|KKB|BARB|PUNB|CNRB|UBIN|IDFC|INDB|FDRL|CIC)[a-zA-Z0-9]{18,32})\b'
)
VPA_EMBED_RE = re.compile(r'\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32})\b')
ACCT_MASK_RE = re.compile(
    r'(?:A/c|Acct|Account)\s*(?:no\.?|number)?\s*[:\-]?\s*([Xx\*]{1,8}\d{3,6}|\d{2,4}[Xx\*]{2,6}\d{2,4})\b',
    re.IGNORECASE,
)

# TRAI DLT Commercial SMS Header Pattern (e.g. VM-BOBSMS-S, VD-BOBTXN, JX-BOBSMS, AD-HDFCBK, AX-ICICIB)
TRAI_SMS_HEADER_RE = re.compile(
    r'^(?:[A-Z]{2}[\-\s]?[A-Z0-9]{3,10}(?:[\-\s][A-ZPTGS])?|[A-Z]{2}[0-9]{4,8}|(?:VM|VD|VK|VG|VX|AD|AX|BP|JD|JK|JM|JX|QP|TM|TX|CP|BZ)[\-][A-Za-z0-9\-]+)$',
    re.IGNORECASE,
)

# Strict Promotional, Recharge Catalog, Loan, Bill-Due & Marketing Spam Blocker
PROMO_SPAM_RE = re.compile(
    r'\b('
    r'learn\s+more|know\s+more|unlimited\s+calls|\d+\s*gb\s+data|data\s+pack|per\s+day\s+data|'
    r'pack\s+validity|plan\s+validity|recharge\s+now|buy\s+now|view\s+plans?|truly\s+unlimited|'
    r'loan|pre-approved|preapproved|eligible|apply\s+now|avail\s+now|up\s*to\s+rs|upto\s+rs|'
    r'cashback\s+up|win\s+up|get\s+flat|offer\s+valid|voucher|scratch\s+card|spin\s+and\s+win|'
    r'credit\s+limit|increase\s+limit|credit\s+score|experian|cibil|emi\s+starts|'
    r'otp\s+is|verification\s+code|one\s+time\s+password|do\s+not\s+share|'
    r'bill\s+is\s+due|payment\s+due|overdue|minimum\s+due|statement\s+is\s+ready|'
    r'congratulations|hurry|limited\s+period|click\s+here|tap\s+here|http://|https://'
    r')\b',
    re.IGNORECASE,
)

# UI Localization / Non-Counterparty / Telecom Plan / SMS Header Garbage Filter
INVALID_CPTY_RE = re.compile(
    r'(%d|%s|\{\d+\}|new\s+messages|notification|get\s+your|loan\s+up|click\s+to|tap\s+to|'
    r'learn\s+more|know\s+more|unlimited\s+calls|\b\d+\s*gb\b|data\s+pack|validity|per\s+day|'
    r'buy\s+now|recharge\s+now|claim\s+now|explore|upgrade|apply\s+now|refer\s+and\s+earn|'
    r'local\s+device|unknown\s+contact|java\.lang\.|viewcontroller|bobsms|bobtxn|hdfcbk|sbiupi|'
    r'bank\s+a/c\s+[\*x]|'
    r'^0+$|^null$|^none$|^nan$|^unknown$|^n/a$|^true$|^false$|^counterparty$|^upi\s+transfer$)',
    re.IGNORECASE,
)


def is_trai_sms_header(val: Any) -> bool:
    """Returns True if the string is a TRAI DLT SMS sender header like VM-BOBSMS-S or VD-BOBTXN."""
    if not val or pd.isna(val):
        return False
    s = str(val).strip()
    if '(' in s:
        s = s.split('(')[0].strip()
    if TRAI_SMS_HEADER_RE.match(s):
        return True
    if any(tok in s.upper() for tok in ('-BOBSMS', '-BOBTXN', 'BOBSMS', 'BOBTXN', '-HDFCBK', '-ICICIB', '-SBIUPI', '-AXISBK', '-KOTAKB', '-PAYTMB')):
        return True
    return False


# Known VPA Prefix -> Clean Merchant/Brand Name
_VPA_MERCHANT_BRANDS: Dict[str, str] = {
    'blinkit': 'Blinkit',
    'swiggystores': 'Swiggy Instamart',
    'swiggy': 'Swiggy',
    'zomato': 'Zomato',
    'zeptomarketplac': 'Zepto',
    'zepto': 'Zepto',
    'flipkart': 'Flipkart',
    'amazon': 'Amazon',
    'bigbasket': 'BigBasket',
    'jio': 'Jio Recharge / Services',
    'airtel': 'Airtel Services',
    'irctc': 'IRCTC Railways',
    'uber': 'Uber',
    'ola': 'Ola Cabs',
    'rapido': 'Rapido',
    'roppentransport': 'Rapido (Roppen Transport)',
    'nesfbsliceit': 'Slice (North East SFB)',
    'bookmyshow': 'BookMyShow',
    'makemytrip': 'MakeMyTrip',
    'redbus': 'redBus',
    'myntra': 'Myntra',
    'meesho': 'Meesho',
    'nykaa': 'Nykaa',
    'tataneu': 'Tata Neu',
    ' electricity': 'Electricity Bill',
    'bescom': 'BESCOM Electricity',
    'tsspdcl': 'TSSPDCL Electricity',
    'apsfl': 'APSFL Broadband',
    'actcorp': 'ACT Fibernet',
}


def is_valid_counterparty(val: Any) -> bool:
    """Returns True only if the string represents a genuine VPA, 10-digit phone, or person/merchant name."""
    if val is None or pd.isna(val):
        return False
    s = str(val).strip()
    # Strip any trailing " On DD" SMS date artifact before validating
    s = re.sub(r'\s+\b(?:on|at|dt|dated)\s+\d{1,4}.*$', '', s, flags=re.IGNORECASE).strip()
    if len(s) < 2 or len(s) > 95:
        return False
    if is_trai_sms_header(s):
        return False
    if INVALID_CPTY_RE.search(s):
        return False
    # Block app names or single letters like "PhonePe", "GooglePay", "Paytm", "N"
    if s.lower() in ('phonepe', 'google pay', 'googlepay', 'gpay', 'paytm', 'bhim', 'cred', 'whatsapp', 'true', 'false', '0.0', '0'):
        return False
    # Block pure numbers UNLESS it is a valid 10-digit Indian mobile number (blocks 19-digit Paytm IDs like 1302521724619685890)
    digits_only = s.lstrip('+').replace('-', '').replace(' ', '')
    if digits_only.isdigit():
        if re.match(r'^(?:91)?[6-9]\d{9}$', digits_only):
            return True
        return False
    # Block float strings like "0.0" or "123.45"
    if re.match(r'^-?\d+\.\d+$', s):
        return False
    return True


def combine_name_and_vpa(name_val: Optional[str], vpa_val: Optional[str]) -> str:
    """
    Combines a human/merchant display name and a UPI VPA into the unified format:
    `Name (vpa@bank)` (or `Store QR (Q...@ybl)` / `Brand (vpa@bank)`).
    """
    clean_vpa = None
    if vpa_val and '@' in str(vpa_val):
        raw_v = str(vpa_val).strip()
        m = re.search(r'[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}', raw_v)
        if m:
            clean_vpa = clean_and_validate_vpa(m.group(0)) or m.group(0).lower()

    clean_name = None
    if name_val and is_valid_counterparty(name_val):
        cand_n = re.sub(r'\s+\b(?:on|at|dt|dated)\s+\d{1,4}.*$', '', str(name_val).strip(), flags=re.IGNORECASE).strip()
        if '@' not in cand_n and is_valid_counterparty(cand_n):
            clean_name = cand_n

    if clean_name and clean_vpa:
        if clean_vpa.lower() in clean_name.lower():
            return clean_name
        return f"{clean_name} ({clean_vpa})"

    if clean_vpa:
        if re.match(r'^q\d{6,12}@ybl$', clean_vpa, re.IGNORECASE):
            return f"Merchant Store QR ({clean_vpa})"
        prefix_low = clean_vpa.split('@')[0].lower()
        for brand_key, brand_title in _VPA_MERCHANT_BRANDS.items():
            if brand_key in prefix_low:
                return f"{brand_title} ({clean_vpa})"
        return clean_vpa

    if clean_name:
        return clean_name

    return 'Unknown'


def format_counterparty_display(cparty: str) -> str:
    """Formats counterparty strings consistently, stripping SMS date suffixes and adding VPA brand labels."""
    if not cparty or cparty == 'Unknown':
        return 'Unknown'
    s = re.sub(r'\s+\b(?:on|at|dt|dated)\s+\d{1,4}.*$', '', str(cparty).strip(), flags=re.IGNORECASE).strip()
    if not is_valid_counterparty(s):
        return 'Unknown'
    if s.startswith('Self / Own Account'):
        return s
    # If already in `Name (vpa@bank)` format, keep it clean
    if '(' in s and '@' in s and s.endswith(')'):
        return s
    if '@' in s and '(' not in s:
        return combine_name_and_vpa(None, s)
    return s


def _clean_extracted_sms_name(raw_name: str) -> Optional[str]:
    """Cleans a candidate counterparty name extracted from an SMS message (strips trailing 'On 01/31/30')."""
    if not raw_name:
        return None
    s = re.sub(r'\s+', ' ', raw_name).strip(' .,:;-/()[]')
    s = re.split(
        r'\b(?:on\s+\d|on\s*$|at\s+\d|via\s+|ref\s*[:.\-]?|utr\s*[:.\-]?|upi\s*[:.\-]?|avl\s+bal|bal\s*[:.\-]|not\s+you|if\s+not)\b',
        s,
        flags=re.IGNORECASE,
    )[0].strip(' .,:;-/()[]')
    s = re.sub(r'\s+\b(?:on|at|dt|dated)\s*\d*$', '', s, flags=re.IGNORECASE).strip(' .,:;-/()[]')
    if not s or len(s) < 2 or len(s) > 55:
        return None
    if re.match(
        r'^(?:a/c|acct|account|your|bank|hdfc|icici|sbi|axis|kotak|bob|phonepe|paytm|gpay|google\s*pay|upi|imps|neft|rtgs|vpa|no|number)\b',
        s,
        re.IGNORECASE,
    ):
        return None
    if is_trai_sms_header(s) or not is_valid_counterparty(s):
        return None
    return s


def is_valid_txid(val: Any) -> bool:
    """Returns True only if the string is a genuine transaction ID/UTR (not N/A, None, or 0)."""
    if val is None or pd.isna(val):
        return False
    s = str(val).strip()
    if len(s) < 6 or len(s) > 64:
        return False
    if s.lower() in ('n/a', 'none', 'null', 'nan', 'unknown', 'sms_notif_record', '0', 'false', 'true'):
        return False
    if not any(c.isdigit() for c in s):
        return False
    return True


def matches_owner_identity(candidate: Any, owner_identifiers: Optional[Set[str]]) -> bool:
    """Checks whether a VPA or phone string belongs to the device owner."""
    if not candidate or not owner_identifiers:
        return False
    c_low = str(candidate).strip().lower()
    if not c_low or c_low in ('unknown', 'none', 'n/a'):
        return False
    c_base = c_low.split('@')[0].split('-')[0]
    for own in owner_identifiers:
        o_low = str(own).strip().lower()
        if not o_low or len(o_low) < 4:
            continue
        o_base = o_low.split('@')[0].split('-')[0]
        if c_low == o_low or (len(o_base) >= 8 and (o_base == c_base or o_base in c_low)):
            return True
    return False


def extract_date_from_phonepe_tid(txid: Any) -> Optional[str]:
    """Extracts 'YYYY-MM-DD HH:MM:SS' from PhonePe Transaction IDs starting with 'T' + YYMMDDHHMMSS."""
    if not txid or not isinstance(txid, str):
        return None
    m = PHONEPE_TID_RE.search(txid.strip())
    if not m:
        return None
    yy, mm, dd, hh, mi, ss = (int(m.group(i)) for i in range(2, 8))
    year = 2000 + yy
    if 2016 <= year <= 2035 and 1 <= mm <= 12 and 1 <= dd <= 31 and 0 <= hh <= 23 and 0 <= mi <= 59 and 0 <= ss <= 59:
        return f"{year:04d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}:{ss:02d}"
    return None


def parse_indian_financial_text(text: str, default_date: Optional[str] = None, sender: str = '') -> Optional[Dict[str, Any]]:
    """
    Strictly extracts completed UPI / Bank transactions from SMS or Push Notifications.
    Handles HDFC, SBI, BoB (`Dr.`/`Cr.`), ICICI, Axis, Kotak, and Slice templates.
    Never uses TRAI SMS headers (`VM-BOBSMS-S`) or the owner's own A/c mask (`*2820`) as the Counterparty.
    """
    if not text or len(text) < 18 or len(text) > 1500:
        return None

    if PROMO_SPAM_RE.search(text):
        return None

    text_lower = text.lower()
    # Support standard settlement verbs AND Bank of Baroda / PSU Bank `Dr.` / `Cr.` / `trf` shorthand
    has_verb = bool(
        re.search(
            r'\b(debited|credited|paid|sent|received|transferred|withdrawn|trf\s+to|dr\.?\s+from|cr\.?\s+to|amt\s+sent)\b',
            text_lower,
        )
    )
    if not has_verb:
        return None

    amt_match = INDIAN_CURRENCY_RE.search(text)
    if not amt_match:
        return None

    try:
        amt_val = float(amt_match.group(1).replace(',', ''))
    except ValueError:
        return None

    if amt_val <= 0 or amt_val > 1_000_000:
        return None

    slash_m = UPI_SLASH_UTR_RE.search(text)
    utr_match = UTR_12_RE.search(text)
    txid = None
    slash_name = None

    if slash_m:
        txid = slash_m.group(1)
        if slash_m.group(2):
            slash_name = slash_m.group(2).strip()
    elif utr_match:
        txid = utr_match.group(1)
    else:
        pp_m = PHONEPE_TID_RE.search(text)
        npci_m = NPCI_35_ID_RE.search(text)
        if pp_m:
            txid = pp_m.group(1)
        elif npci_m:
            txid = npci_m.group(1)
        else:
            raw_12 = re.search(r'\b([0-9]{12})\b', text)
            if raw_12 and any(k in text_lower for k in ('upi', 'imps', 'ref', 'utr', 'a/c', 'acct')):
                txid = raw_12.group(1)

    # 1. Extract embedded NPCI VPA (highest priority)
    counterparty = None
    for v_cand in VPA_EMBED_RE.findall(text):
        valid_v = clean_and_validate_vpa(v_cand)
        if valid_v:
            counterparty = valid_v
            break

    acct_m = ACCT_MASK_RE.search(text)
    acct_mask = acct_m.group(1) if acct_m else None

    if not txid and not (counterparty and acct_mask):
        return None

    # 2. Check Slash-Delimited Name (e.g. `UPI/DR/558513310751/RAMESH KUMAR/...`)
    if not counterparty and slash_name:
        cand = _clean_extracted_sms_name(slash_name)
        if cand and cand.upper() not in ('UPI', 'DR', 'CR', 'IMPS', 'NEFT', 'P2P', 'P2M', 'P2A'):
            counterparty = cand

    if not counterparty:
        after_utr_m = UPI_NAME_AFTER_UTR_RE.search(text)
        if after_utr_m:
            cand = _clean_extracted_sms_name(after_utr_m.group(1))
            if cand and cand.upper() not in ('UPI', 'DR', 'CR', 'IMPS', 'NEFT', 'P2P', 'P2M', 'P2A'):
                counterparty = cand

    # 3. Check Bank-Specific Multi-Pattern Templates (HDFC, BoB, SBI, ICICI, Axis, Kotak)
    if not counterparty:
        sms_cpty_patterns = [
            # BoB: "Dr. from A/C XX6676 and Cr. to <NAME/VPA>"
            r'\bcr\.?\s+to\s+([A-Za-z0-9.\-@_\s]{3,35})',
            # SBI: "debited by 500.0 on date ... trf to <NAME> Refno"
            r'\btrf\s+to\s+([A-Za-z0-9.\-@_\s]{3,35})',
            # HDFC / ICICI: "Sent Rs.17000 from HDFC Bank A/c *2820 to <NAME> on ..."
            r'(?:a/c|acct|account)\s+[\*xX0-9]{3,12}\s+(?:on\s+[0-9/\-]+\s+)?to\s+([A-Za-z0-9.\-@_\s]{3,35})',
            # Credit SMS: "credited to A/c xx2820 ... from/by <NAME>"
            r'\bcredited\s+to\s+(?:your\s+)?(?:[A-Za-z]+\s+)?(?:a/c|acct|account)\s+[\*xX0-9]{3,12}\s+(?:on\s+[0-9/\-]+\s+)?(?:by|from)\s+(?:a/c\s+linked\s+to\s+(?:vpa\s+)?)?([A-Za-z0-9.\-@_\s]{3,35})',
            # Standard prepositions
            r'\b(?:paid\s+to|sent\s+to|received\s+from|credited\s+by|debited\s+towards|transferred\s+to|to\s+vpa|from\s+vpa|by\s+vpa|towards)\s+([A-Za-z0-9.\-@_\s]{3,35})',
        ]
        for pat in sms_cpty_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                cand = _clean_extracted_sms_name(m.group(1))
                if cand:
                    counterparty = cand
                    break

    # 4. Accurate Polarity Detection (including BoB `Dr.` / `Cr.` and `Amt Sent`)
    if re.search(r'\b(debited|sent|paid|withdrawn|upi/dr|dr\.?\s+from|trf\s+to|amt\s+sent)\b', text_lower):
        tx_type = 'DEBIT'
    elif re.search(r'\b(credited|received|deposited|upi/cr|cr\.?\s+to\s+your|cr\.?\s+in)\b', text_lower):
        tx_type = 'CREDIT'
    else:
        tx_type = 'TRANSFER'

    # Never use TRAI SMS headers (`VM-BOBSMS-S`) or the owner's own A/c mask (`*2820`) as the Counterparty!
    if not is_valid_counterparty(counterparty):
        counterparty = 'Unknown'

    return {
        'Date': default_date,
        'Transaction_ID': txid or 'N/A',
        'Amount': amt_val,
        'Counterparty': format_counterparty_display(counterparty)[:80],
        'Status': 'SUCCESS',
        'Type': tx_type,
        'Owner_Acct_Mask': acct_mask,
    }


SCHEMA_OVERRIDES: Dict[str, Dict[str, Any]] = {
    'phonepe': {
        'preferred_tables': [
            'ZTRANSACTIONENTITY', 'TRANSACTION_HISTORY', 'transaction_history',
            'ZTRANSACTION', 'transactions', 'P2P_TRANSACTIONS', 'workflow_table',
        ],
        'amount_cols': ['ZAMOUNT', 'AMOUNT', 'amount', 'z_amount', 'txnamount', 'amount_in_paise'],
        'date_cols': ['ZCREATEDAT', 'ZDATE', 'DATE', 'timestamp', 'created_at'],
        'counterparty_cols': ['ZPAYEENAME', 'ZCOUNTERPARTY', 'counterparty', 'payee', 'ZPAYEEVPA', 'payee_vpa', 'payer_vpa'],
        'txid_cols': ['ZTRANSACTIONID', 'ZTRANSACTIONREFERENCEID', 'transaction_id', 'txn_id', 'utr'],
        'status_cols': ['ZSTATUS', 'STATUS', 'status', 'state'],
        'blob_cols': ['ZDATA', 'ZDETAILS', 'data', 'payload', 'value'],
        'timestamp_epoch': 'auto',
        'amount_divisor': 100.0,
        'json_amount_divisor': 100.0,
        'json_path_amount': 'amount',
        'json_path_date': 'timestamp',
        'json_path_cpty': 'counterparty',
        'json_path_txid': 'transactionId',
    },
    'google pay': {
        'preferred_tables': [
            'transactions', 'txn_history', 'upi_transactions',
            'tez_transactions', 'feed_items', 'sync_entities', 'ZTRANSACTION',
        ],
        'amount_cols': ['amount', 'total_amount', 'txn_amount', 'amount_minor', 'amount_micros', 'ZAMOUNT'],
        'date_cols': ['timestamp', 'created_at', 'txn_time', 'time_created', 'ZTIMESTAMP'],
        'counterparty_cols': ['counterparty', 'payee_vpa', 'receiver_vpa', 'counterparty_id'],
        'txid_cols': ['transaction_id', 'txn_id', 'upi_txn_id'],
        'status_cols': ['status', 'txn_status', 'state'],
        'blob_cols': ['payload', 'blob', 'item', 'feed_payload', 'sync_payload'],
        'timestamp_epoch': 'unix_ms',
        'amount_divisor': 100.0,
        'json_amount_divisor': 100.0,
        'json_path_amount': 'amount',
        'json_path_date': 'timestamp',
        'json_path_cpty': 'counterparty',
        'json_path_txid': 'transaction_id',
    },
    'paytm': {
        'preferred_tables': [
            'payments', 'paytm_payments', 'transactions',
            'passbook_entries', 'order_history', 'ZTRANSACTION',
        ],
        'amount_cols': ['txn_amount', 'amount', 'amt', 'paid_amount'],
        'date_cols': ['txn_date', 'created_at', 'timestamp', 'txn_time'],
        'counterparty_cols': ['payee_vpa', 'counterparty', 'heading', 'narration', 'merchant_name'],
        'txid_cols': ['txn_id', 'order_id', 'transaction_id', 'utr'],
        'status_cols': ['txn_status', 'status', 'order_status'],
        'blob_cols': ['payload', 'data', 'value'],
        'timestamp_epoch': 'auto',
        'amount_divisor': 1.0,
        'json_amount_divisor': 1.0,
    },
    'whatsapp': {
        'preferred_tables': [
            'pay_transaction', 'pay_transactions', 'message_payment', 'ZWAPAYMENTTRANSACTION',
        ],
        'amount_cols': ['amount_1000', 'ZAMOUNT1000', 'amount'],
        'date_cols': ['timestamp', 'init_timestamp', 'received_timestamp', 'ZTIMESTAMP', 'ZMESSAGEDATE'],
        'counterparty_cols': ['remote_jid', 'key_remote_jid', 'sender_jid', 'receiver_jid', 'ZFROMJID'],
        'txid_cols': ['bank_transaction_id', 'upi_transaction_id', 'ZTRANSACTIONID', 'key_id'],
        'status_cols': ['status', 'ZSTATUS'],
        'blob_cols': ['future_data', 'metadata', 'service_data', 'data'],
        'timestamp_epoch': 'auto',
        'amount_divisor': 1000.0,
        'json_amount_divisor': 1.0,
    },
}


def get_app_override(app_label: str) -> Optional[Dict[str, Any]]:
    if not app_label:
        return None
    normalized = str(app_label).strip().lower()
    for key, override in SCHEMA_OVERRIDES.items():
        if key in normalized or normalized in key:
            return override

    try:
        from parsers.plugin_loader import BUILTIN_MANIFESTS
        for m in BUILTIN_MANIFESTS:
            if m['app_name'].lower() == normalized or normalized in [a.lower() for a in m.get('aliases', [])]:
                return {
                    'preferred_tables': m.get('preferred_tables', []),
                    'amount_cols': m.get('amount_cols', []),
                    'date_cols': m.get('date_cols', []),
                    'counterparty_cols': m.get('counterparty_cols', []),
                    'txid_cols': m.get('txid_cols', []),
                    'status_cols': m.get('status_cols', []),
                    'blob_cols': m.get('blob_cols', []),
                    'timestamp_epoch': m.get('timestamp_epoch', 'auto'),
                    'amount_divisor': m.get('amount_divisor', 1.0),
                    'json_amount_divisor': m.get('json_amount_divisor', 1.0),
                }
    except Exception:
        pass
    return None


def find_in_json(obj: Any, target_keys: List[str]) -> Any:
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_lower = str(k).lower().replace('_', '').replace('-', '')
            for tk in target_keys:
                if k_lower == tk or k_lower.endswith(tk):
                    if v is not None and v != '' and not isinstance(v, (dict, list)):
                        return v
                    if isinstance(v, dict) and tk in AMOUNT_KEYS:
                        for sub_k in ('value', 'amount', 'paise', 'minor', 'total', 'units'):
                            if sub_k in v and v[sub_k] is not None and not isinstance(v[sub_k], (dict, list)):
                                return v[sub_k]
                    elif isinstance(v, dict) and (tk in PAYEE_KEYS or tk in PAYER_KEYS or tk in CPTY_KEYS):
                        for sub_k in ('vpa', 'name', 'merchantName', 'billerName', 'displayName', 'id'):
                            if sub_k in v and v[sub_k] is not None and not isinstance(v[sub_k], (dict, list)):
                                return v[sub_k]
        for _, v in obj.items():
            if isinstance(v, (dict, list)):
                res = find_in_json(v, target_keys)
                if res is not None:
                    return res
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                res = find_in_json(item, target_keys)
                if res is not None:
                    return res
    return None


def find_direction_in_json(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_lower = str(k).lower().replace('_', '').replace('-', '')
            if any(k_lower == tk or k_lower.endswith(tk) for tk in TYPE_KEYS):
                if isinstance(v, str):
                    v_up = v.strip().upper()
                    if any(tok in v_up for tok in _VALID_DIRECTION_TOKENS):
                        return v_up
        for _, v in obj.items():
            if isinstance(v, (dict, list)):
                res = find_direction_in_json(v)
                if res is not None:
                    return res
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                res = find_direction_in_json(item)
                if res is not None:
                    return res
    return None


def resolve_payer_payee_counterparty(
    payer_val: Any,
    payee_val: Any,
    owner_identifiers: Optional[Set[str]] = None,
    explicit_direction: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    payer = str(payer_val).strip() if is_valid_counterparty(payer_val) else None
    payee = str(payee_val).strip() if is_valid_counterparty(payee_val) else None

    payer_is_owner = matches_owner_identity(payer, owner_identifiers)
    payee_is_owner = matches_owner_identity(payee, owner_identifiers)

    if payer and payee:
        if payer_is_owner and not payee_is_owner:
            return format_counterparty_display(payee), 'DEBIT'
        if payee_is_owner and not payer_is_owner:
            return format_counterparty_display(payer), 'CREDIT'
        if payer_is_owner and payee_is_owner:
            return f"Self Transfer ({payee})", 'DEBIT'

    dir_up = str(explicit_direction or '').upper()
    if any(k in dir_up for k in ('DEBIT', 'SENT', 'PAID', 'OUT', 'DR', 'P2M', 'BILL', 'RECHARGE')):
        if payee and not payee_is_owner:
            return format_counterparty_display(payee), 'DEBIT'
        if payer and not payer_is_owner:
            return format_counterparty_display(payer), 'DEBIT'
    elif any(k in dir_up for k in ('CREDIT', 'RECEIVED', 'IN', 'CR')):
        if payer and not payer_is_owner:
            return format_counterparty_display(payer), 'CREDIT'
        if payee and not payee_is_owner:
            return format_counterparty_display(payee), 'CREDIT'

    if payee and not payee_is_owner:
        return format_counterparty_display(payee), explicit_direction
    if payer and not payer_is_owner:
        return format_counterparty_display(payer), explicit_direction
    if payee_is_owner and payee:
        return f"Self / Own Account ({payee})", explicit_direction
    if payer_is_owner and payer:
        return f"Self / Own Account ({payer})", explicit_direction
    return None, explicit_direction


def normalize_timestamp_value(
    value: Any, epoch: str = 'auto'
) -> Optional[str]:
    if value is None or pd.isna(value):
        return None
    try:
        if isinstance(value, str):
            value = value.strip()
            if not value or value.lower() in ('none', 'nan', 'null', 'n/a', '0'):
                return None
            if re.match(r'^-?\d+(\.\d+)?$', value):
                numeric = float(value)
            else:
                parsed = pd.to_datetime(value, errors='coerce')
                if pd.isna(parsed) or parsed.year < 2015 or parsed.year > 2035:
                    return None
                return parsed.strftime('%Y-%m-%d %H:%M:%S')
        else:
            numeric = float(value)
    except (TypeError, ValueError):
        return None

    if numeric <= 0:
        return None

    magnitude = abs(numeric)
    if epoch == 'unix_ns' or magnitude > 1e16:
        if 4e17 <= magnitude <= 1.2e18:
            seconds = (numeric / 1e9) + _COCOA_OFFSET_SECONDS
        else:
            seconds = numeric / 1e9
    elif epoch == 'unix_us' or 1e14 < magnitude <= 1e16:
        seconds = numeric / 1e6
    elif epoch == 'unix_ms' or 1e11 < magnitude <= 1e14:
        seconds = numeric / 1e3
    elif epoch == 'cocoa':
        seconds = numeric + _COCOA_OFFSET_SECONDS
    elif epoch == 'unix_s':
        seconds = numeric
    else:
        if 4e8 < magnitude < 1.1e9:
            seconds = numeric + _COCOA_OFFSET_SECONDS
        else:
            seconds = numeric

    if not (1420070400 <= seconds <= 2051222400):
        return None

    try:
        ts = pd.to_datetime(seconds, unit='s', errors='coerce', utc=False)
        return None if pd.isna(ts) else ts.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def try_decompress_blob(raw: Any) -> Optional[bytes]:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 2:
        return None
    data = bytes(raw)
    for wbits in (zlib.MAX_WBITS, 16 + zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            continue
    return None


def extract_from_blob(
    raw_blob: Any,
    app_label: str = '',
    json_paths: Optional[Dict[str, str]] = None,
    owner_identifiers: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        'Amount': None,
        'Date': None,
        'Counterparty': None,
        'Transaction_ID': None,
        'Status': None,
        'Type': None,
    }
    if raw_blob is None:
        return out

    if isinstance(raw_blob, str):
        s_trim = raw_blob.strip()
        if len(s_trim) >= 16 and not ('{' in s_trim or '[' in s_trim) and re.match(r'^[A-Za-z0-9+/=\-_]+$', s_trim):
            try:
                decoded_b64 = base64.b64decode(s_trim + '===')
                if len(decoded_b64) >= 4:
                    decompressed = try_decompress_blob(decoded_b64)
                    payload_bytes = decompressed if decompressed is not None else decoded_b64
                else:
                    payload_bytes = s_trim.encode('utf-8', errors='replace')
            except Exception:
                payload_bytes = s_trim.encode('utf-8', errors='replace')
        else:
            payload_bytes = s_trim.encode('utf-8', errors='replace')
    elif isinstance(raw_blob, (bytes, bytearray)):
        if len(raw_blob) == 0:
            return out
        decompressed = try_decompress_blob(raw_blob)
        payload_bytes = decompressed if decompressed is not None else bytes(raw_blob)
    else:
        return out

    try:
        text = payload_bytes.decode('utf-8', errors='replace').strip()
        if '{' in text or '[' in text:
            start_idx = text.find('{') if '{' in text else text.find('[')
            payload = json.loads(text[start_idx:])
            if json_paths and isinstance(payload, dict):
                def _dig(obj: Any, dotted: str) -> Any:
                    if not dotted:
                        return None
                    for part in dotted.split('.'):
                        if isinstance(obj, dict):
                            obj = obj.get(part)
                        else:
                            return None
                    return obj

                cand_amt = _dig(payload, json_paths.get('amount', ''))
                if isinstance(cand_amt, dict):
                    cand_amt = cand_amt.get('value') or cand_amt.get('amount')
                out['Amount'] = cand_amt
                out['Date'] = _dig(payload, json_paths.get('date', ''))
                out['Counterparty'] = _dig(payload, json_paths.get('counterparty', ''))
                out['Transaction_ID'] = _dig(payload, json_paths.get('transaction_id', ''))

            if out['Amount'] is None:
                out['Amount'] = find_in_json(payload, AMOUNT_KEYS)
            if out['Date'] is None:
                out['Date'] = find_in_json(payload, DATE_KEYS)
            if out['Transaction_ID'] is None:
                out['Transaction_ID'] = find_in_json(payload, TXID_KEYS)
            if out['Status'] is None:
                out['Status'] = find_in_json(payload, STATUS_KEYS)
            if out['Type'] is None:
                out['Type'] = find_direction_in_json(payload)

            payer_vpa_cand = find_in_json(payload, ['payervpa', 'sendervpa', 'fromvpa', 'remittervpa'])
            payer_name_cand = find_in_json(payload, ['payername', 'sendername', 'remitter', 'payer', 'sender'])
            payee_vpa_cand = find_in_json(payload, ['payeevpa', 'receivervpa', 'recipientvpa', 'tovpa', 'beneficiaryvpa'])
            payee_name_cand = find_in_json(payload, ['payeename', 'receivername', 'recipientname', 'beneficiaryname', 'merchantname', 'billername', 'storename', 'payee'])

            payer_combined = combine_name_and_vpa(payer_name_cand, payer_vpa_cand)
            payee_combined = combine_name_and_vpa(payee_name_cand, payee_vpa_cand)

            resolved_cpty, resolved_dir = resolve_payer_payee_counterparty(
                payer_combined if payer_combined != 'Unknown' else None,
                payee_combined if payee_combined != 'Unknown' else None,
                owner_identifiers=owner_identifiers,
                explicit_direction=out['Type'],
            )
            if resolved_cpty:
                out['Counterparty'] = resolved_cpty
            if resolved_dir:
                out['Type'] = resolved_dir

            if not is_valid_counterparty(out['Counterparty']) or matches_owner_identity(out['Counterparty'], owner_identifiers):
                fallback_cpty = find_in_json(payload, CPTY_KEYS)
                if is_valid_counterparty(fallback_cpty) and not matches_owner_identity(fallback_cpty, owner_identifiers):
                    out['Counterparty'] = format_counterparty_display(str(fallback_cpty))
                elif matches_owner_identity(out['Counterparty'], owner_identifiers):
                    out['Counterparty'] = f"Self / Own Account ({out['Counterparty']})"
                else:
                    out['Counterparty'] = None

            if not is_valid_txid(out['Transaction_ID']):
                out['Transaction_ID'] = None
            if any(v is not None for v in out.values()):
                return out
    except Exception:
        pass

    try:
        from parsers.protobuf_decoder import decode_protobuf_stream, extract_financials_from_protobuf
        pb = decode_protobuf_stream(payload_bytes, max_depth=3)
        if pb:
            fin = extract_financials_from_protobuf(pb)
            out['Amount'] = fin.get('Amount')
            out['Date'] = fin.get('Date')
            c_pb = fin.get('Counterparty')
            if is_valid_counterparty(c_pb):
                out['Counterparty'] = (
                    f"Self / Own Account ({c_pb})"
                    if matches_owner_identity(c_pb, owner_identifiers)
                    else format_counterparty_display(str(c_pb))
                )
            out['Transaction_ID'] = fin.get('Transaction_ID') if is_valid_txid(fin.get('Transaction_ID')) else None
    except Exception:
        pass

    return out