"""
Universal upi://pay Deep-Link URI & EMVCo BharatQR TLV Decoder.
Adheres strictly to Specification Section 7 (Sub-Engine 3.1E) and AGENTS.md Forensic Invariants.
"""

from typing import Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from src.upi.models import QRArtifactType, UPIScannedQRAndVPALookup


def parse_nested_tlv(tlv_str: str) -> Dict[str, str]:
    """
    Recursively decodes a [2-character Tag][2-digit Length][Value] TLV string.
    Robust against boundary edge cases and trailing length variations.
    """
    result: Dict[str, str] = {}
    pos = 0
    total_len = len(tlv_str)

    while pos + 4 <= total_len:
        tag_id = tlv_str[pos:pos + 2]
        try:
            val_len = int(tlv_str[pos + 2:pos + 4])
        except ValueError:
            break

        val_start = pos + 4
        val_end = min(val_start + val_len, total_len)
        val_str = tlv_str[val_start:val_end]
        result[tag_id] = val_str
        pos = val_end

    return result


def _normalize_emvco_string(s: str) -> str:
    """
    Detects and normalizes off-by-one length misalignments in BharatQR strings
    where Tag 26 (UPI Merchant Info) swallows the leading character of standard Tag 52 (MCC).
    """
    idx_52 = s.find("5204")
    if idx_52 != -1:
        for tag_prefix in ("26", "27", "28"):
            idx_tag = s.find(tag_prefix)
            if idx_tag != -1 and idx_tag < idx_52:
                # Correct length of Tag 26/27/28 to end right at '5204'
                val_len = idx_52 - (idx_tag + 4)
                if val_len > 0:
                    return s[:idx_tag + 2] + f"{val_len:02d}" + s[idx_tag + 4:]
    return s


class UniversalQRDecoder:
    """
    Decodes Indian UPI QR formats:
    - upi://pay and upi://mandate deep-link URI parameters (pa, pn, mc, tr, am).
    - EMVCo / BharatQR Merchant-Presented QR TLV strings (Tags 00 through 63, nested 26/27/28 & 62).
    """

    def decode_emvco_bharatqr(
        self,
        qr_string: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
        event_utc_iso: Optional[str] = None,
        gps_json: Optional[str] = None,
    ) -> Optional[UPIScannedQRAndVPALookup]:
        """
        Parses an EMVCo / BharatQR contiguous string starting with 000201.
        """
        if not qr_string or not qr_string.startswith("000201"):
            return None

        normalized_qr = _normalize_emvco_string(qr_string)
        top_tlv = parse_nested_tlv(normalized_qr)
        if not top_tlv:
            return None

        # Extract nested Tag 26, 27, or 28 for Payee VPA
        payee_vpa: Optional[str] = None
        for tag_upi in ("26", "27", "28"):
            if tag_upi in top_tlv:
                nested = parse_nested_tlv(top_tlv[tag_upi])
                # Sub-tag 01 is Payee VPA
                if "01" in nested:
                    payee_vpa = nested["01"]
                    break

        mcc = top_tlv.get("52")
        merchant_name = top_tlv.get("59")
        city = top_tlv.get("60")
        pincode = top_tlv.get("61")

        terminal_id: Optional[str] = None
        if "62" in top_tlv:
            nested_62 = parse_nested_tlv(top_tlv["62"])
            terminal_id = nested_62.get("07") or nested_62.get("03") or nested_62.get("01")

        return UPIScannedQRAndVPALookup(
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
            artifact_type=QRArtifactType.SCANNED_BHARATQR_EMVCO_TLV.value,
            raw_qr_or_uri_string=qr_string,
            extracted_payee_vpa=payee_vpa,
            verified_merchant_or_cbs_name=merchant_name,
            mcc_4_digit=mcc,
            merchant_city=city,
            merchant_pincode_6_digit=pincode,
            terminal_or_store_id=terminal_id,
            scan_gps_lat_lon_json=gps_json,
            was_name_verified_without_tx=0,
            event_utc_iso=event_utc_iso,
        )

    def decode_upi_uri(
        self,
        uri_string: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
        event_utc_iso: Optional[str] = None,
        gps_json: Optional[str] = None,
    ) -> Optional[UPIScannedQRAndVPALookup]:
        """
        Parses a upi://pay?... or upi://mandate?... deep-link URI.
        """
        if not uri_string or not uri_string.lower().startswith("upi://"):
            return None

        parsed = urlparse(uri_string)
        qs = parse_qs(parsed.query)

        def _get_one(k: str) -> Optional[str]:
            vals = qs.get(k)
            return unquote(vals[0]) if vals else None

        payee_vpa = _get_one("pa")
        payee_name = _get_one("pn")
        mcc = _get_one("mc")
        tr_id = _get_one("tr") or _get_one("tid")

        return UPIScannedQRAndVPALookup(
            app_instance_id=app_instance_id,
            source_vfs_file_id=source_vfs_file_id,
            artifact_type=QRArtifactType.SCANNED_UPI_URI_QR.value,
            raw_qr_or_uri_string=uri_string,
            extracted_payee_vpa=payee_vpa,
            verified_merchant_or_cbs_name=payee_name,
            mcc_4_digit=mcc,
            merchant_city=None,
            merchant_pincode_6_digit=None,
            terminal_or_store_id=tr_id,
            scan_gps_lat_lon_json=gps_json,
            was_name_verified_without_tx=0,
            event_utc_iso=event_utc_iso,
        )

    def decode_qr(
        self,
        raw_text: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 0,
        event_utc_iso: Optional[str] = None,
        gps_json: Optional[str] = None,
    ) -> Optional[UPIScannedQRAndVPALookup]:
        """
        Auto-detects whether raw_text is a BharatQR TLV string or a upi:// URI.
        """
        if not raw_text:
            return None
        cleaned = raw_text.strip()
        if cleaned.startswith("000201"):
            return self.decode_emvco_bharatqr(
                cleaned,
                app_instance_id=app_instance_id,
                source_vfs_file_id=source_vfs_file_id,
                event_utc_iso=event_utc_iso,
                gps_json=gps_json,
            )
        elif cleaned.lower().startswith("upi://"):
            return self.decode_upi_uri(
                cleaned,
                app_instance_id=app_instance_id,
                source_vfs_file_id=source_vfs_file_id,
                event_utc_iso=event_utc_iso,
                gps_json=gps_json,
            )
        return None
