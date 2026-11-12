"""Explicit, test-only input for legal-report endpoints (the product no longer ships sample data)."""
import os

from parsers.api_server import Sec230MediaInput


def ncrp_candidates(victim_account: str):
    return [
        {"account_no": victim_account, "ifsc": "HDFC0000001", "vpa": "victim@okhdfcbank",
         "is_complainant_victim": True, "volume_inr": 250000.0},
        {"account_no": "987654321012", "ifsc": "SBIN0001234", "vpa": "mule1@oksbi",
         "is_complainant_victim": False, "volume_inr": 235000.0},
        {"account_no": "BESCOM_UTILITY_ESCROW", "ifsc": "SBIN0000002", "vpa": "bescom.billdesk@icici",
         "is_complainant_victim": False, "volume_inr": 1500.0},
        {"account_no": "112233445566", "ifsc": "ICIC0005678", "vpa": "mule2@icici",
         "is_complainant_victim": False, "volume_inr": 220000.0},
    ]


def sec230_items(workspace: str):
    """One disclosable image and one POCSO-tagged stream, written as real files."""
    ok = os.path.join(workspace, "payment_receipt_01.jpg")
    bad = os.path.join(workspace, "withheld_sensitive_stream_02.mp4")
    with open(ok, "wb") as f:
        f.write(b"SAFE_PAYMENT_RECEIPT_IMAGE_PAYLOAD_EVIDENCE")
    with open(bad, "wb") as f:
        f.write(b"SENSITIVE_POCSO_PROTECTED_STREAM_DO_NOT_DISCLOSE")
    return [
        Sec230MediaInput(path=ok, redaction_tag="DISCLOSABLE"),
        Sec230MediaInput(path=bad, redaction_tag="CSAM_POCSO"),
    ]
