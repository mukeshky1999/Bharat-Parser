"""
Sub-Engine 7.3C: NPCI upi://pay & BharatQR EMVCo TLV Merchant Unpacker.
Parses UPI query strings, unpacks EMVCo Tag-Length-Value trees, validates CRC-16 CCITT,
and classifies barcodes into the 10 canonical forensic payload categories.
Adheres strictly to AGENTS.md Forensic Invariants and Section 5 of Module 7.3 Specification.
"""

import re
import urllib.parse
from typing import Any, Dict, Tuple

from src.qr_and_receipts.models import PayloadCategory


class UPIAndBharatQRUnpacker:
    """Unpacker for NPCI UPI query strings and EMVCo BharatQR Merchant TLV streams."""

    def compute_crc16_ccitt(self, data_str: str) -> str:
        """Computes standard EMVCo CRC-16/CCITT checksum (polynomial 0x1021, init 0xFFFF)."""
        crc = 0xFFFF
        for byte in data_str.encode("ascii"):
            crc ^= (byte << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return f"{crc:04X}"

    def parse_upi_uri(self, uri: str) -> Dict[str, Any]:
        """Parses upi://pay or upi://mandate URI query parameters."""
        parsed = urllib.parse.urlparse(uri)
        query_str = parsed.query or (uri.split("?", 1)[1] if "?" in uri else "")
        qs = urllib.parse.parse_qs(query_str)

        result: Dict[str, Any] = {}
        for key, values in qs.items():
            if values:
                val = values[0]
                result[key] = val

        # Normalize common keys
        if "am" in result:
            try:
                result["am_float"] = float(result["am"])
            except ValueError:
                result["am_float"] = None

        return result

    def parse_bharatqr_emvco(self, emvco_str: str) -> Dict[str, Any]:
        """Parses EMVCo Merchant-Presented QR TLV stream and validates CRC-16 CCITT."""
        data: Dict[str, Any] = {
            "tags": {},
            "crc_valid": False,
            "merchant_vpa": None,
            "mcc": None,
            "merchant_name": None,
            "city": None,
            "postal_code": None,
            "currency": None,
        }

        str_len = len(emvco_str)
        crc_idx = emvco_str.rfind("6304")

        # Validate CRC-16 if Tag 63 is present
        if crc_idx != -1 and crc_idx + 8 <= str_len:
            check_data = emvco_str[: crc_idx + 4]
            claimed_crc = emvco_str[crc_idx + 4 : crc_idx + 8].upper()
            computed_crc = self.compute_crc16_ccitt(check_data)
            data["crc_valid"] = (claimed_crc == computed_crc)
            data["computed_crc"] = computed_crc
            data["claimed_crc"] = claimed_crc

        idx = 0
        while idx + 4 <= str_len:
            tag = emvco_str[idx : idx + 2]
            try:
                length = int(emvco_str[idx + 2 : idx + 4])
            except ValueError:
                break
            val_start = idx + 4
            val_end = val_start + length

            # Resilient lookahead alignment for Tag 26/27/28 if followed by standard Tag 52 MCC
            if tag in {"26", "27", "28"}:
                m52 = re.search(r"5204\d{4}", emvco_str[val_start : val_end + 16])
                if m52:
                    actual_end = val_start + m52.start()
                    if actual_end != val_end:
                        val_end = actual_end

            if val_end > str_len:
                val_end = str_len
            val = emvco_str[val_start:val_end]
            data["tags"][tag] = val
            idx = val_end

            # Unpack specific standard tags
            if tag in {"26", "27", "28"}:
                # NPCI Merchant Account Information sub-TLV
                sub_idx = 0
                while sub_idx + 4 <= len(val):
                    sub_tag = val[sub_idx : sub_idx + 2]
                    try:
                        sub_len = int(val[sub_idx + 2 : sub_idx + 4])
                    except ValueError:
                        break
                    s_start = sub_idx + 4
                    s_end = min(s_start + sub_len, len(val))
                    sub_val = val[s_start:s_end]
                    if sub_tag == "01":
                        data["merchant_vpa"] = sub_val
                    elif sub_tag == "00":
                        data["aid"] = sub_val
                    sub_idx = s_end

            elif tag == "52":
                data["mcc"] = val
            elif tag == "53":
                data["currency"] = val
            elif tag == "58":
                data["country"] = val
            elif tag == "59":
                data["merchant_name"] = val
            elif tag == "60":
                data["city"] = val
            elif tag == "61":
                data["postal_code"] = val

        return data

    def classify_and_unpack(self, payload_str: str) -> Tuple[str, Dict[str, Any]]:
        """Classifies raw decoded string into 10 canonical forensic payload categories and unpacks attributes."""
        s = payload_str.strip()

        # 1. UIDAI Aadhaar Secure QR
        if (s.isdigit() and len(s) >= 500) or s.startswith("<PrintLetterBarcodeData") or s.startswith("<QPDB"):
            return PayloadCategory.UIDAI_AADHAAR_SECURE_QR.value, {
                "length": len(s),
                "is_xml": s.startswith("<"),
            }

        # 2. NPCI UPI Payment QR
        if s.lower().startswith("upi://pay?") or s.lower().startswith("upi://mandate?") or s.lower().startswith("bhim://"):
            parsed_data = self.parse_upi_uri(s)
            return PayloadCategory.NPCI_UPI_PAYMENT_QR.value, parsed_data

        # 3. EMVCo BharatQR Merchant
        if s.startswith("000201") or s.startswith("000202"):
            parsed_emv = self.parse_bharatqr_emvco(s)
            return PayloadCategory.EMVCO_BHARATQR_MERCHANT.value, parsed_emv

        # 4. GSMA eSIM Activation QR
        if s.startswith("LPA:1$"):
            parts = s.split("$")
            smdp = parts[1] if len(parts) > 1 else ""
            matching_id = parts[2] if len(parts) > 2 else ""
            oid = parts[3] if len(parts) > 3 else ""
            flag = parts[4] if len(parts) > 4 else ""
            return PayloadCategory.GSMA_ESIM_ACTIVATION_QR.value, {
                "smdp_server": smdp,
                "matching_id": matching_id,
                "oid": oid,
                "confirmation_flag": flag,
            }

        # 5. Wi-Fi Credentials Share QR
        if s.startswith("WIFI:"):
            ssid_m = re.search(r"S:([^;]+);", s)
            auth_m = re.search(r"T:([^;]+);", s)
            pwd_m = re.search(r"P:([^;]+);", s)
            hidden_m = re.search(r"H:([^;]+);", s)
            return PayloadCategory.WIFI_CREDENTIALS_SHARE_QR.value, {
                "ssid": ssid_m.group(1) if ssid_m else "",
                "auth_type": auth_m.group(1) if auth_m else "",
                "password": pwd_m.group(1) if pwd_m else "",
                "hidden": hidden_m.group(1) if hidden_m else "false",
            }

        # 6. Crypto Wallet URI or Address
        crypto_prefixes = ("bitcoin:", "ethereum:", "tron:", "solana:", "monero:")
        if s.lower().startswith(crypto_prefixes) or re.match(r"^(0x[0-9a-fA-F]{40}|T[A-Za-z0-9]{33}|bc1[a-zA-Z0-9]{25,60})$", s):
            return PayloadCategory.CRYPTO_WALLET_URI_OR_ADDRESS.value, {
                "uri_or_address": s,
            }

        # 7. WalletConnect Pairing QR
        if s.startswith("wc:"):
            return PayloadCategory.WALLETCONNECT_PAIRING_QR.value, {
                "walletconnect_uri": s,
            }

        # 8. Messenger Companion or OPSEC Invite QR
        companion_prefixes = ("tg://login", "sgnl://linkdevice", "https://simplex.chat/contact")
        if s.startswith(companion_prefixes) or re.match(r"^05[0-9a-fA-F]{64}$", s) or re.match(r"^[12]@[A-Za-z0-9+/=,]+", s):
            return PayloadCategory.MESSENGER_COMPANION_OR_OPSEC_INVITE_QR.value, {
                "companion_uri": s,
            }

        # 9. IATA Boarding Pass BCBP or IRCTC
        if s.startswith("M1") or s.startswith("M2"):
            return PayloadCategory.IATA_BOARDING_PASS_BCBP_OR_IRCTC_QR.value, {
                "bcbp_raw": s,
            }

        # 10. DigiLocker or Govt JWT QR
        gov_domains = ("digilocker.gov.in", "parivahan.gov.in", "incometax.gov.in", "cowin.gov.in")
        if any(g in s.lower() for g in gov_domains):
            return PayloadCategory.DIGILOCKER_OR_GOVT_JWT_QR.value, {
                "gov_url": s,
            }

        # Default fallback
        return "UNKNOWN_BARCODE_PAYLOAD", {"raw_text": s}
