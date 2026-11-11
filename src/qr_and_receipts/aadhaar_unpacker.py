"""
Sub-Engine 7.3B: UIDAI Aadhaar Secure QR Code Mathematical Unpacker.
Performs BigInt Base-10 -> Big-Endian byte decoding -> Gzip DEFLATE inflation ->
0xFF-delimited demographic parsing, embedded .jp2 JPEG-2000 biometric facial photo carving,
iterative SHA-256 mobile/email unmasking, and physical card photoshopped forgery detection.
Adheres strictly to AGENTS.md Forensic Invariants and Section 4 of Module 7.3 Specification.
"""

import gzip
import hashlib
import re
import xml.etree.ElementTree as ET
import zlib
from typing import List, Optional

from src.qr_and_receipts.models import (
    AadhaarTamperStatus,
    AadhaarUnpackedRecord,
)


class AadhaarSecureQRUnpacker:
    """Mathematical decoder and authenticity auditor for UIDAI Aadhaar Secure QR codes."""

    def unpack_secure_qr(
        self,
        qr_numeric_string: str,
        candidate_mobiles: Optional[List[str]] = None,
        candidate_emails: Optional[List[str]] = None,
        source_vfs_file_id: int = 0,
        barcode_uid: int = 0,
    ) -> AadhaarUnpackedRecord:
        """Unpacks either modern BigInt+Gzip Aadhaar Secure QR or legacy XML barcode."""
        raw_text = qr_numeric_string.strip()

        # Check for legacy XML Aadhaar barcode (<PrintLetterBarcodeData or <QPDB)
        if raw_text.startswith("<PrintLetterBarcodeData") or raw_text.startswith("<?xml") or raw_text.startswith("<QPDB"):
            return self._unpack_legacy_xml_barcode(raw_text, source_vfs_file_id, barcode_uid)

        # Modern UIDAI Secure QR (Base-10 integer string)
        return self._unpack_bigint_gzip_secure_qr(
            raw_text,
            candidate_mobiles=candidate_mobiles or [],
            candidate_emails=candidate_emails or [],
            source_vfs_file_id=source_vfs_file_id,
            barcode_uid=barcode_uid,
        )

    def _unpack_bigint_gzip_secure_qr(
        self,
        qr_numeric_string: str,
        candidate_mobiles: List[str],
        candidate_emails: List[str],
        source_vfs_file_id: int,
        barcode_uid: int,
    ) -> AadhaarUnpackedRecord:
        """Decodes BigInt -> Big-Endian bytes -> Gzip decompression -> demographic fields + JP2 photo."""
        n_big = int(qr_numeric_string)
        num_bytes = (n_big.bit_length() + 7) // 8
        compressed_bytes = n_big.to_bytes(num_bytes, byteorder="big")

        # Locate Gzip DEFLATE magic header 1F 8B 08 if preceded by padding
        decompressed_bytes = None
        magic_idx = compressed_bytes.find(b"\x1f\x8b\x08")
        if magic_idx != -1:
            try:
                decompressed_bytes = zlib.decompress(compressed_bytes[magic_idx:], 16 + zlib.MAX_WBITS)
            except Exception:
                decompressed_bytes = None

        if decompressed_bytes is None:
            try:
                decompressed_bytes = gzip.decompress(compressed_bytes)
            except Exception:
                decompressed_bytes = zlib.decompress(compressed_bytes, 16 + zlib.MAX_WBITS)

        total_len = len(decompressed_bytes)

        # Find 0xFF delimiters to extract demographic fields
        ff_positions = []
        for i, byte in enumerate(decompressed_bytes):
            if byte == 0xFF:
                ff_positions.append(i)

        # Inspect first token for Version shift ("V2", "V3", "V4", "V5")
        first_token = decompressed_bytes[: ff_positions[0]].decode("utf-8", "ignore").strip()
        version_prefix = "V1"
        k = 0
        if first_token.upper() in {"V2", "V3", "V4", "V5"}:
            version_prefix = first_token.upper()
            k = 1

        fields: List[str] = []
        start = 0
        for pos in ff_positions:
            val = decompressed_bytes[start:pos].decode("utf-8", "ignore").strip()
            fields.append(val)
            start = pos + 1
            if len(fields) >= k + 16:
                break

        photo_start_offset = start

        # Extract structured demographic attributes
        email_mobile_indicator = fields[k + 0] if len(fields) > k + 0 else "0"
        reference_id = fields[k + 1] if len(fields) > k + 1 else ""
        full_name = fields[k + 2] if len(fields) > k + 2 else ""
        dob = fields[k + 3] if len(fields) > k + 3 else ""
        gender = fields[k + 4] if len(fields) > k + 4 else ""
        care_of = fields[k + 5] if len(fields) > k + 5 else None
        district = fields[k + 6] if len(fields) > k + 6 else ""
        landmark = fields[k + 7] if len(fields) > k + 7 else ""
        house_building = fields[k + 8] if len(fields) > k + 8 else ""
        location_locality = fields[k + 9] if len(fields) > k + 9 else ""
        pincode = fields[k + 10] if len(fields) > k + 10 else ""
        post_office = fields[k + 11] if len(fields) > k + 11 else ""
        state = fields[k + 12] if len(fields) > k + 12 else ""
        street = fields[k + 13] if len(fields) > k + 13 else ""
        sub_district = fields[k + 14] if len(fields) > k + 14 else ""
        vtc = fields[k + 15] if len(fields) > k + 15 else ""

        # Slicing trailing binary tail from total_len backwards
        sig_bytes = decompressed_bytes[total_len - 256 : total_len]
        rsa_2048_sig_hex = sig_bytes.hex().lower()

        mob_hash_bytes: Optional[bytes] = None
        email_hash_bytes: Optional[bytes] = None
        photo_end_offset = total_len - 256

        if email_mobile_indicator == "3":
            mob_hash_bytes = decompressed_bytes[total_len - 256 - 32 : total_len - 256]
            email_hash_bytes = decompressed_bytes[total_len - 256 - 64 : total_len - 256 - 32]
            photo_end_offset = total_len - 256 - 64
        elif email_mobile_indicator == "2":
            mob_hash_bytes = decompressed_bytes[total_len - 256 - 32 : total_len - 256]
            photo_end_offset = total_len - 256 - 32
        elif email_mobile_indicator == "1":
            email_hash_bytes = decompressed_bytes[total_len - 256 - 32 : total_len - 256]
            photo_end_offset = total_len - 256 - 32

        jp2_bytes = decompressed_bytes[photo_start_offset:photo_end_offset]

        # Aadhaar last 4 digits and generation timestamp from reference_id
        last_4_digits = reference_id[:4] if len(reference_id) >= 4 else ""
        gen_timestamp_raw = reference_id[4:] if len(reference_id) > 4 else None
        formatted_gen_ts = None
        if gen_timestamp_raw and len(gen_timestamp_raw) >= 14:
            # YYYYMMDDHHMMSS
            formatted_gen_ts = (
                f"{gen_timestamp_raw[0:4]}-{gen_timestamp_raw[4:6]}-{gen_timestamp_raw[6:8]} "
                f"{gen_timestamp_raw[8:10]}:{gen_timestamp_raw[10:12]}:{gen_timestamp_raw[12:14]}"
            )

        # Assemble full address
        addr_parts = [
            p
            for p in [
                house_building,
                street,
                location_locality,
                landmark,
                vtc,
                sub_district,
                district,
                post_office,
                state,
            ]
            if p
        ]
        address_str = ", ".join(addr_parts)
        if pincode:
            address_str = f"{address_str} - {pincode}" if address_str else pincode

        dob_and_gender = f"{dob} ({gender})" if gender else dob

        # Iterative SHA-256 mobile unmasking
        unmasked_mobile = None
        if mob_hash_bytes:
            for cand_mob in candidate_mobiles:
                if self.verify_mobile_iterative_hash(mob_hash_bytes, reference_id, cand_mob):
                    unmasked_mobile = cand_mob
                    break

        # Iterative SHA-256 email unmasking
        unmasked_email = None
        if email_hash_bytes:
            for cand_email in candidate_emails:
                if self.verify_email_iterative_hash(email_hash_bytes, reference_id, cand_email):
                    unmasked_email = cand_email
                    break

        return AadhaarUnpackedRecord(
            barcode_uid=barcode_uid,
            source_vfs_file_id=source_vfs_file_id,
            qr_format_version="SECURE_QR_V2_V3_BIGINT_GZIP",
            aadhaar_last_4_digits=last_4_digits,
            qr_generation_timestamp_str=formatted_gen_ts,
            signed_full_name=full_name,
            signed_dob_and_gender=dob_and_gender,
            signed_care_of_guardian=care_of,
            signed_full_address_and_pin=address_str,
            extracted_jp2_photo_staging_id=None,
            unmasked_registered_mobile=unmasked_mobile,
            unmasked_registered_email=unmasked_email,
            rsa_2048_signature_hex=rsa_2048_sig_hex,
            visual_vs_qr_tamper_status=AadhaarTamperStatus.AUTHENTIC_MATCH.value,
            extracted_jp2_bytes=jp2_bytes,
            mobile_sha256_hash_hex=mob_hash_bytes.hex().lower() if mob_hash_bytes else None,
            email_sha256_hash_hex=email_hash_bytes.hex().lower() if email_hash_bytes else None,
        )

    def verify_mobile_iterative_hash(
        self,
        mobile_sha256_hash: bytes,
        reference_id: str,
        candidate_mobile: str,
    ) -> bool:
        """Computes UIDAI iterative SHA-256 digest on candidate mobile number."""
        if not reference_id or len(reference_id) < 4:
            return False

        # 4th character of reference_id (last digit of Aadhaar)
        d4_char = reference_id[3]
        d4 = int(d4_char) if d4_char.isdigit() else 1
        n_iter = 1 if d4 == 0 else d4

        # Clean candidate 10-digit mobile number
        mob_clean = re.sub(r"\D", "", candidate_mobile)
        if len(mob_clean) > 10:
            mob_clean = mob_clean[-10:]

        h = mob_clean
        for _ in range(n_iter):
            h = hashlib.sha256(h.encode("ascii")).hexdigest()

        return bytes.fromhex(h) == mobile_sha256_hash

    def verify_email_iterative_hash(
        self,
        email_sha256_hash: bytes,
        reference_id: str,
        candidate_email: str,
    ) -> bool:
        """Computes UIDAI iterative SHA-256 digest on candidate email address."""
        if not reference_id or len(reference_id) < 4:
            return False

        d4_char = reference_id[3]
        d4 = int(d4_char) if d4_char.isdigit() else 1
        n_iter = 1 if d4 == 0 else d4

        h = candidate_email.strip().lower()
        for _ in range(n_iter):
            h = hashlib.sha256(h.encode("ascii")).hexdigest()

        return bytes.fromhex(h) == email_sha256_hash

    def detect_aadhaar_card_tamper(
        self,
        unpacked: AadhaarUnpackedRecord,
        printed_name: str,
        printed_dob: str,
        printed_last_4: str,
    ) -> str:
        """Compares signed demographic payload from QR against printed text on physical card face."""
        # 1. Compare Last 4 Digits
        clean_printed_last_4 = re.sub(r"\D", "", printed_last_4)[-4:]
        if clean_printed_last_4 and unpacked.aadhaar_last_4_digits:
            if clean_printed_last_4 != unpacked.aadhaar_last_4_digits:
                return AadhaarTamperStatus.PHOTOSHOPPED_AADHAAR_CARD_DETECTED.value

        # 2. Compare Full Name (Token overlap / normalization)
        def _norm_name(s: str) -> List[str]:
            return [w for w in re.sub(r"[^A-Za-z0-9]", " ", s).upper().split() if w]

        qr_tokens = set(_norm_name(unpacked.signed_full_name))
        printed_tokens = set(_norm_name(printed_name))
        if qr_tokens and printed_tokens:
            common = qr_tokens.intersection(printed_tokens)
            if len(common) == 0:
                return AadhaarTamperStatus.PHOTOSHOPPED_AADHAAR_CARD_DETECTED.value

        # 3. Compare Date of Birth
        def _norm_dob(s: str) -> str:
            return re.sub(r"\D", "", s)

        qr_dob_digits = _norm_dob(unpacked.signed_dob_and_gender)
        printed_dob_digits = _norm_dob(printed_dob)
        if qr_dob_digits and printed_dob_digits:
            if qr_dob_digits[:8] != printed_dob_digits[:8]:
                return AadhaarTamperStatus.PHOTOSHOPPED_AADHAAR_CARD_DETECTED.value

        return AadhaarTamperStatus.AUTHENTIC_MATCH.value

    def _unpack_legacy_xml_barcode(
        self,
        xml_text: str,
        source_vfs_file_id: int,
        barcode_uid: int,
    ) -> AadhaarUnpackedRecord:
        """Parses legacy pre-2018 XML Aadhaar QR code."""
        root = ET.fromstring(xml_text)
        uid = root.attrib.get("uid", "")
        name = root.attrib.get("name", "")
        gender = root.attrib.get("gender", "")
        yob = root.attrib.get("yob", "")
        dob = root.attrib.get("dob", yob)
        co = root.attrib.get("co", "")
        house = root.attrib.get("house", "")
        street = root.attrib.get("street", "")
        lm = root.attrib.get("lm", "")
        loc = root.attrib.get("loc", "")
        vtc = root.attrib.get("vtc", "")
        po = root.attrib.get("po", "")
        dist = root.attrib.get("dist", "")
        state = root.attrib.get("state", "")
        pc = root.attrib.get("pc", "")

        last_4 = uid[-4:] if len(uid) >= 4 else ""
        addr_parts = [p for p in [house, street, loc, lm, vtc, dist, po, state] if p]
        full_addr = ", ".join(addr_parts)
        if pc:
            full_addr = f"{full_addr} - {pc}" if full_addr else pc

        return AadhaarUnpackedRecord(
            barcode_uid=barcode_uid,
            source_vfs_file_id=source_vfs_file_id,
            qr_format_version="LEGACY_XML_BARCODE",
            aadhaar_last_4_digits=last_4,
            qr_generation_timestamp_str=None,
            signed_full_name=name,
            signed_dob_and_gender=f"{dob} ({gender})" if gender else dob,
            signed_care_of_guardian=co or None,
            signed_full_address_and_pin=full_addr,
            extracted_jp2_photo_staging_id=None,
            unmasked_registered_mobile=None,
            unmasked_registered_email=None,
            rsa_2048_signature_hex=None,
            visual_vs_qr_tamper_status=AadhaarTamperStatus.AUTHENTIC_MATCH.value,
            extracted_jp2_bytes=None,
            mobile_sha256_hash_hex=None,
            email_sha256_hash_hex=None,
        )
