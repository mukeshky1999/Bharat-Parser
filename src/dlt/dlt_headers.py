"""
Sub-Engine 3.4B: TRAI DLT Header Anatomy, Circle Decoder & SMSC Spoof Detector.
Parses Indian Telecom Regulatory Authority of India (TRAI) DLT headers,
resolves financial entities, checks promotional flags, and detects fake SMS injections.
Adheres strictly to AGENTS.md Forensic Invariants and Section 4 of Module 3.4 Spec.
"""

from typing import Dict, Optional, Set

from src.dlt.models import DLTHeaderInfo


class DLTHeaderParser:
    """Decodes Indian TRAI DLT sender headers and evaluates carrier delivery authenticity."""

    OPERATOR_MAP: Dict[str, str] = {
        "A": "Bharti Airtel",
        "J": "Reliance Jio Infocomm",
        "V": "Vodafone Idea (Vi)",
        "B": "BSNL",
        "M": "MTNL",
        "Q": "Tata Teleservices",
        "T": "Tata Tele / Quadrant",
    }

    CIRCLE_MAP: Dict[str, str] = {
        "A": "Andhra Pradesh & Telangana",
        "B": "Bihar & Jharkhand",
        "C": "Chennai",
        "D": "Delhi NCR",
        "E": "Kerala",
        "G": "Gujarat",
        "H": "Haryana",
        "J": "Jammu & Kashmir",
        "K": "Kolkata",
        "L": "Himachal Pradesh",
        "M": "Mumbai",
        "N": "North East",
        "O": "Odisha",
        "P": "Punjab",
        "R": "Rajasthan",
        "S": "Assam",
        "T": "Tamil Nadu",
        "U": "Uttar Pradesh (East)",
        "W": "Uttar Pradesh (West) & Uttarakhand",
        "X": "Karnataka",
        "Y": "Madhya Pradesh & Chhattisgarh",
        "Z": "West Bengal",
    }

    DLT_ENTITY_DIRECTORY: Dict[str, str] = {
        # Public Sector Banks
        "SBIINB": "State Bank of India (SBI)",
        "SBIPSG": "State Bank of India (SBI)",
        "SBMSMS": "State Bank of India (SBI)",
        "CBSSBI": "State Bank of India (SBI)",
        "SBIUPI": "State Bank of India (SBI)",
        "SBICRD": "SBI Card",
        "YONOSB": "State Bank of India (YONO)",
        "BOBTXN": "Bank of Baroda",
        "BOBSMS": "Bank of Baroda",
        "BOBCRD": "Bank of Baroda",
        "BARODA": "Bank of Baroda",
        "PNBSMS": "Punjab National Bank (PNB)",
        "PNBCRD": "Punjab National Bank (PNB)",
        "PNBOTP": "Punjab National Bank (PNB)",
        "PNBUPI": "Punjab National Bank (PNB)",
        "CANBNK": "Canara Bank",
        "CANARA": "Canara Bank",
        "CNRBMS": "Canara Bank",
        "UNIONB": "Union Bank of India",
        "UBISMS": "Union Bank of India",
        "UBINBK": "Union Bank of India",
        "INDBNK": "Indian Bank",
        "INDIAN": "Indian Bank",
        "BOIIND": "Bank of India (BOI)",
        "BOISMS": "Bank of India (BOI)",
        "BKOFIN": "Bank of India (BOI)",
        "CENTBK": "Central Bank of India",
        "CBIOTP": "Central Bank of India",
        "UCOBNK": "UCO Bank",
        "IOBCHN": "Indian Overseas Bank",
        "IOBBNK": "Indian Overseas Bank",
        "MAHABK": "Bank of Maharashtra",
        "BOMBNK": "Bank of Maharashtra",
        "PSBANK": "Punjab & Sind Bank",
        # Private Sector Banks
        "HDFCBK": "HDFC Bank",
        "HDFCBN": "HDFC Bank",
        "HDFCCC": "HDFC Bank Credit Card",
        "PAYZAP": "HDFC PayZapp",
        "ICICIB": "ICICI Bank",
        "ICICBK": "ICICI Bank",
        "ICICIC": "ICICI Bank Credit Card",
        "AXISBK": "Axis Bank",
        "AXISMR": "Axis Bank",
        "AXISCC": "Axis Bank Credit Card",
        "KOTAKB": "Kotak Mahindra Bank",
        "KOTAKM": "Kotak Mahindra Bank",
        "KTKBNK": "Kotak Mahindra Bank",
        "INDUSB": "IndusInd Bank",
        "INDUSL": "IndusInd Bank",
        "IDFCFB": "IDFC FIRST Bank",
        "IDFCBK": "IDFC FIRST Bank",
        "YESBNK": "Yes Bank",
        "YESBKL": "Yes Bank",
        "FEDBNK": "Federal Bank",
        "FDRLBK": "Federal Bank",
        "RBLBNK": "RBL Bank",
        "RBLCRD": "RBL Bank Credit Card",
        "AUBANK": "AU Small Finance Bank",
        "AUSMFB": "AU Small Finance Bank",
        "EQUITA": "Equitas Small Finance Bank",
        "UJJIVN": "Ujjivan Small Finance Bank",
        "BANDHN": "Bandhan Bank",
        "JKBANK": "J&K Bank",
        "KVBANK": "Karur Vysya Bank",
        "SIBSMS": "South Indian Bank",
        # Payments Banks & UPI Platforms
        "AIRBNK": "Airtel Payments Bank",
        "AIRTEL": "Airtel Payments Bank",
        "AIRPAY": "Airtel Payments Bank",
        "IPPBSM": "India Post Payments Bank (IPPB)",
        "IPPBNK": "India Post Payments Bank (IPPB)",
        "DOPBNK": "India Post / POSB",
        "JIOPAY": "Jio Payments Bank",
        "JIOBNK": "Jio Payments Bank",
        "FINOBK": "Fino Payments Bank",
        "NSDLPB": "NSDL Payments Bank",
        "PAYTMB": "Paytm Payments Bank",
        "PYTMSB": "Paytm",
        "PHONPE": "PhonePe",
        "NPCIUP": "NPCI / BHIM",
        "BHIMUP": "NPCI / BHIM",
        "SLICEP": "Slice",
        "FAMPAY": "FamPay",
        "CREDAP": "CRED",
        # Crypto Exchanges
        "COINDC": "CoinDCX",
        "DCXOTP": "CoinDCX",
        "WAZIRX": "WazirX",
        "COINSW": "CoinSwitch Kuber",
        "CSKUBR": "CoinSwitch Kuber",
        "MUDREX": "Mudrex",
        "ZEBPAY": "ZebPay",
        "GIOTTU": "Giottus",
        "BINANC": "Binance",
        # Demat & Law Enforcement
        "NSDLDP": "NSDL Demat",
        "NSDLCA": "NSDL Demat",
        "CDSLDP": "CDSL Demat",
        "CDSLTX": "CDSL Demat",
        "ZERODH": "Zerodha",
        "GROWWP": "Groww",
        "ANGELB": "AngelOne",
        "CYBERC": "1930 NCRP Cybercrime Portal",
        "NCRPIN": "1930 NCRP Cybercrime Portal",
        "MHAIND": "1930 NCRP Cybercrime Portal",
        "UIDAIG": "UIDAI Aadhaar",
        "ADHAAR": "UIDAI Aadhaar",
        "ITDEPT": "Income Tax Dept",
    }

    LEGITIMATE_SMS_PACKAGES: Set[str] = {
        "com.android.phone",
        "com.google.android.apps.messaging",
        "com.samsung.android.messaging",
        "com.android.mms",
        "com.android.providers.telephony",
        "com.oneplus.mms",
        "com.xiaomi.mms",
        "com.oppo.mms",
        "com.vivo.mms",
    }

    def parse_header(self, raw_sender: Optional[str]) -> DLTHeaderInfo:
        """
        Parses DLT header conforming to TRAI format: <Operator><Circle>-<Entity_ID>[-<Category>]
        Examples: 'AD-SBIINB-S', 'VM-HDFCBK-P', 'JX-ICICIB-T', 'AD-CYBERC-G'
        """
        if not raw_sender:
            return DLTHeaderInfo(raw_sender="")

        sender = raw_sender.strip().upper()
        parts = sender.split("-")

        op_char: Optional[str] = None
        circle_char: Optional[str] = None
        op_name: Optional[str] = None
        circle_name: Optional[str] = None
        op_circle_str: Optional[str] = None
        entity_code: Optional[str] = None
        category_suffix: Optional[str] = None
        is_promo = False

        # Parse Prefix (Operator + Circle)
        if len(parts) >= 2 and len(parts[0]) == 2:
            op_char = parts[0][0]
            circle_char = parts[0][1]
            op_name = self.OPERATOR_MAP.get(op_char, "Unknown Operator")
            circle_name = self.CIRCLE_MAP.get(circle_char, "Unknown Circle")
            op_circle_str = f"{op_name} — {circle_name}"

            entity_code = parts[1]

            if len(parts) >= 3:
                category_suffix = parts[2]
                if category_suffix == "P":
                    is_promo = True
            elif sender.endswith("-P"):
                is_promo = True
                category_suffix = "P"

        else:
            # Fallback parsing for legacy headers without hyphens
            entity_code = sender
            if sender.endswith("-P"):
                is_promo = True
                category_suffix = "P"
                entity_code = sender[:-2]

        # Resolve institution
        inst_name = "Unknown Financial Institution"
        if entity_code:
            clean_code = entity_code.replace("-", "").strip()
            if clean_code in self.DLT_ENTITY_DIRECTORY:
                inst_name = self.DLT_ENTITY_DIRECTORY[clean_code]
            else:
                for k, v in self.DLT_ENTITY_DIRECTORY.items():
                    if k in clean_code:
                        inst_name = v
                        break

        return DLTHeaderInfo(
            raw_sender=raw_sender,
            operator_char=op_char,
            operator_name=op_name,
            circle_char=circle_char,
            circle_name=circle_name,
            entity_code=entity_code,
            category_suffix=category_suffix,
            resolved_institution=inst_name,
            operator_and_circle=op_circle_str,
            is_promotional_dlt=is_promo,
        )

    def detect_smsc_spoof(
        self,
        service_center: Optional[str],
        creator: Optional[str],
        msg_type: int = 1,
    ) -> bool:
        """
        Section 4.3: Inspects service_center and creator package to detect locally injected fake SMS.
        Returns True if SMS is suspected to be spoofed/injected locally.
        """
        # Only evaluate received inbox SMS messages
        if msg_type != 1:
            return False

        has_valid_smsc = False
        if service_center:
            clean_sc = service_center.strip().replace(" ", "").replace("-", "")
            if clean_sc.startswith("+91") or (clean_sc.startswith("91") and len(clean_sc) == 12) or len(clean_sc) == 10:
                has_valid_smsc = True

        if not has_valid_smsc:
            clean_creator = (creator or "").strip().lower()
            if clean_creator and clean_creator not in self.LEGITIMATE_SMS_PACKAGES:
                return True
            if not clean_creator:
                return True

        return False
