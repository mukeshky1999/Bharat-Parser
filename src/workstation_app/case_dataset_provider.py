"""
Forensic Case Dataset Provider & Seeder for Bharat Analyzer Workstation.
Provides pre-populated, verified case intelligence for FIR Crime No. 104/2026,
binding analytical outputs from Phases 1 through 9 into unified UI payloads.
"""

from dataclasses import dataclass
import struct
import time
from typing import Any, Optional

from src.chat_reconstructor_and_redline.myers_redline_engine import MyersRedlineEngine
from src.financial_graph_and_storyboard.sankey_canvas import SankeyCanvasRenderer
from src.geospatial_media_and_tamper.hybrid_map_geocoder import (
    HybridReverseGeocoder,
    INDIAN_GAZETTEER_HUBS,
)
from src.workstation_shell_and_hex.hex_provenance_inspector import (
    DataInterpreterDecoder,
    HexProvenanceInspector,
)


class CaseDatasetProvider:
    """Generates rich, authentic forensic data fixtures for the live Workstation UI."""

    CASE_METADATA = {
        "case_fir_number": "FIR Crime No. 104/2026 — Cyber Crime PS, Bengaluru",
        "investigating_agency": "CID Cyber Crime Division / Karnataka Police",
        "primary_suspect": "Vikramaditya Sharma @ Vikram Hawala",
        "seized_devices": [
            {
                "device_label": "Device 01 (Primary Handset)",
                "model": "Samsung Galaxy S24 Ultra (SM-S928B/DS)",
                "os_version": "Android 14 (OneUI 6.1, Kernel 6.1.43, Knox 3.10)",
                "imei1": "864291060192837",
                "imei2": "864291060192838",
                "sim1_iccid": "89918720194829104928",
                "sim2_iccid": "89918720194829104929",
                "extraction_type": "Physical FFS Live Acquisition (VeraKey / Cellebrite Ingest)",
            },
            {
                "device_label": "Device 02 (Secondary Mule Burner)",
                "model": "Apple iPhone 15 Pro (A3102)",
                "os_version": "iOS 17.5.1 (Build 21F90)",
                "imei1": "354928104829104",
                "sim1_iccid": "89910120194829108841",
                "extraction_type": "Full File System (GrayKey / FFS Image)",
            },
        ],
        "dual_sha256": {
            "product_a_container": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "product_b_staging": "8f94a123b784e1b89ef67341ad1245e90214a7e9124a9841fca82341ba928172",
            "merkle_root_hash": "2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d199f281307a63293c",
            "merkle_root_tree": "2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d199f281307a63293c",
            "verification_status": "DUAL_SHA256_INTEGRITY_VERIFIED",
        },
        "hardware_profile": {
            "device_model": "Samsung Galaxy S24 Ultra (SM-S928B/DS)",
            "os_build": "Android 14 (OneUI 6.1, Kernel 6.1.43, Knox 3.10)",
            "imei_1": "864291060192837",
            "imei_2": "864291060192838",
            "sim_1_iccid": "89918720194829104928 (Jio 5G)",
            "extraction_method": "Full File System (VeraKey / Physical Ingest)",
        },
        "kpi_metrics": {
            "total_vfs_nodes": 142810,
            "parsed_vfs_nodes": 31402,
            "system_known_nodes": 111390,
            "decryption_pending_nodes": 14,
            "unk_unrecognized_nodes": 4,
            "total_laundered_inr": 14285000.0,
            "flagged_mule_inr": 4285000.0,
            "unified_messages_count": 84920,
            "edited_or_revoked_count": 312,
            "gps_fixes_count": 4819,
            "active_tamper_alerts": 3,
        },
        "crime_alerts": [
            {
                "alert_id": "ALERT-01",
                "severity": "CRITICAL",
                "badge": "RUPEE-TO-USDT 4-HOP LAUNDERING CHAIN",
                "summary": "₹95,000 debit from victim HDFC debited via PhonePe UTR 631014892011 settled into Binance P2P Order #205918472910 within 31 seconds.",
                "jump_workspace": "ws-finance",
                "primary_indicator": "UTR 631014892011 / Binance UID 91827361",
            },
            {
                "alert_id": "ALERT-02",
                "severity": "HIGH",
                "badge": "ANDROID ACCESSIBILITY TROJAN INGESTION",
                "summary": "Sideloaded APK 'com.mparivahan.update.overlay' abused Accessibility API to exfiltrate 6-digit OTP SMS without user interaction.",
                "jump_workspace": "ws-command",
                "primary_indicator": "Package: com.mparivahan.update.overlay",
            },
            {
                "alert_id": "ALERT-03",
                "severity": "CRITICAL",
                "badge": "RECOVERED BIP-39 12-WORD MNEMONIC SEED",
                "summary": "Exhumed 12-word cryptocurrency mnemonic seed from Samsung Gallery uncropped /Mutations/ photo buffer.",
                "jump_workspace": "ws-map-media",
                "primary_indicator": "12-Word Seed: 'abandon ability able about above absent absorb abstract absurd abuse access accident'",
            },
        ],
    }

    TIMELINE_EVENTS = [
        {
            "event_id": "EVT-1001",
            "timestamp_iso": "2026-10-24T14:32:01.000000+05:30",
            "timestamp_utc": "2026-10-24T09:02:01.000000Z",
            "app_domain": "Google Messages (com.google.android.apps.messaging)",
            "artifact_type": "DLT Financial SMS (OTP Arrival)",
            "summary": "HDFC Bank OTP SMS arrived: 'OTP for Rs 95,000 to VPA rsharma@sbi is 849102. Do not share.'",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/user/0/com.google.android.apps.messaging/databases/bugle_db",
            "sqlite_page": 42,
            "cell_offset": 814,
            "wal_frame": None,
            "raw_hex_preview": "53514C49544520464F524D415420330010000101004020200000000100000004",
        },
        {
            "event_id": "EVT-1002",
            "timestamp_iso": "2026-10-24T14:32:03.210000+05:30",
            "timestamp_utc": "2026-10-24T09:02:03.210000Z",
            "app_domain": "Accessibility Service (com.mparivahan.update.overlay)",
            "artifact_type": "Trojan Window Scraper Event",
            "summary": "Trojan scraped incoming SMS window content and dispatched payload to C2 server 194.26.29.112:8443",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/system/appops/discrete/10192_appops.xml",
            "sqlite_page": 0,
            "cell_offset": 1204,
            "wal_frame": None,
            "raw_hex_preview": "3C6F702069643D2232332220706B673D22636F6D2E6D70617269766168616E22",
        },
        {
            "event_id": "EVT-1003",
            "timestamp_iso": "2026-10-24T14:32:09.500000+05:30",
            "timestamp_utc": "2026-10-24T09:02:09.500000Z",
            "app_domain": "PhonePe (com.phonepe.app)",
            "artifact_type": "UPI Financial Transaction",
            "summary": "UPI Debit ₹95,000 | UTR: 631014892011 | Debit A/C: HDFC ...9210 -> Credit VPA: rsharma@sbi",
            "state_5d": "WAL_OR_JOURNAL",
            "confidence": "HISTORICAL_COMMITTED_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/user/0/com.phonepe.app/databases/phonepe.db-wal",
            "sqlite_page": 118,
            "cell_offset": 240,
            "wal_frame": 182,
            "raw_hex_preview": "00000076000000B60124A910E829104800000001000000006310148920110000",
        },
        {
            "event_id": "EVT-1004",
            "timestamp_iso": "2026-10-24T14:32:19.820000+05:30",
            "timestamp_utc": "2026-10-24T09:02:19.820000Z",
            "app_domain": "Binance (com.binance.dev)",
            "artifact_type": "P2P Escrow Order Release",
            "summary": "P2P Order #205918472910 marked COMPLETED. 1,080.00 USDT released to TronLink Pro wallet.",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/user/0/com.binance.dev/files/mmkv/com.binance.dev.default",
            "sqlite_page": 0,
            "cell_offset": 4096,
            "wal_frame": None,
            "raw_hex_preview": "0A223230353931383437323931301206534554544C451A08313038302E303020",
        },
        {
            "event_id": "EVT-1005",
            "timestamp_iso": "2026-10-24T14:32:31.140000+05:30",
            "timestamp_utc": "2026-10-24T09:02:31.140000Z",
            "app_domain": "Telegram X (org.thunderdog.challegram)",
            "artifact_type": "Encrypted Chat Receipt Exfiltration",
            "summary": "Secret Chat exfiltrated payment screenshot with OCR UTR '631014892011' to @HawalaBoss_HQ",
            "state_5d": "FREELIST_OR_UNALLOCATED",
            "confidence": "RESIDUAL_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/user/0/org.thunderdog.challegram/databases/cache4.db",
            "sqlite_page": 204,
            "cell_offset": 512,
            "wal_frame": None,
            "raw_hex_preview": "40486177616C61426F73735F485120536574746C656420555452203633313031",
        },
        {
            "event_id": "EVT-1006",
            "timestamp_iso": "2026-10-24T14:33:05.000000+05:30",
            "timestamp_utc": "2026-10-24T09:03:05.000000Z",
            "app_domain": "WhatsApp Business (Clone 999)",
            "artifact_type": "Edited Messaging Record",
            "summary": "Message edited: 'Bhai 50,000 bhej do' -> 'Bhai 1,50,000 bhej do Hawala account me'",
            "state_5d": "WAL_OR_JOURNAL",
            "confidence": "RECONSTRUCTED_RECORD",
            "clock_integrity": "NTP_VERIFIED",
            "vfs_path": "/data/user/999/com.whatsapp.w4b/databases/msgstore.db-wal",
            "sqlite_page": 514,
            "cell_offset": 128,
            "wal_frame": 94,
            "raw_hex_preview": "010000004268616920312C35302C303030206268656A20646F20486177616C61",
        },
    ]

    CHAT_THREADS: dict[str, Any] = {}

    ACTION_BURST_STORYBOARD = {
        "time_window": "2026-10-24 14:32:00 IST to 14:32:45 IST (45 Seconds Burst)",
        "swimlanes": [
            {
                "swimlane_id": "SWIM-1",
                "label": "OS Foreground & Accessibility",
                "color": "#38bdf8",
                "events": [
                    {"time_offset_s": 0.0, "title": "Phone Awake / Portrait Tilt", "detail": "Orientation: Portrait Hand-Held (22°)"},
                    {"time_offset_s": 2.2, "title": "Trojan Overlay Triggered", "detail": "com.mparivahan.update.overlay active"},
                    {"time_offset_s": 8.0, "title": "PhonePe Background Focus", "detail": "Intent: ACTION_VIEW upi://pay"},
                ],
            },
            {
                "swimlane_id": "SWIM-2",
                "label": "TRAI DLT Financial SMS",
                "color": "#f59e0b",
                "events": [
                    {"time_offset_s": 1.0, "title": "Incoming DLT SMS (HDFC)", "detail": "Header: VK-HDFCBK | OTP: 849102"},
                ],
            },
            {
                "swimlane_id": "SWIM-3",
                "label": "UPI / Core Banking Ledger",
                "color": "#10b981",
                "events": [
                    {"time_offset_s": 9.5, "title": "UPI Debit ₹95,000", "detail": "UTR: 631014892011 | Settled to rsharma@sbi"},
                ],
            },
            {
                "swimlane_id": "SWIM-4",
                "label": "CEX P2P Escrow",
                "color": "#ec4899",
                "events": [
                    {"time_offset_s": 19.8, "title": "Binance P2P Released", "detail": "Order #205918472910 | 1,080.00 USDT"},
                ],
            },
            {
                "swimlane_id": "SWIM-5",
                "label": "High-OpSec Chat Exfiltration",
                "color": "#a855f7",
                "events": [
                    {"time_offset_s": 31.1, "title": "Telegram Secret Chat Exfiltration", "detail": "Payment screenshot dispatched"},
                ],
            },
        ],
    }

    GEOSPATIAL_FIXES = [
        {
            "fix_id": "GEO-01",
            "lat": 25.317600,
            "lon": 82.973900,
            "tier": "TIER_1_GNSS",
            "accuracy_meters": 4.5,
            "timestamp": "2026-10-24 14:15:00 IST",
            "label": "Suspect Safehouse (Varanasi Ghats)",
            "city": "Varanasi",
            "state": "Uttar Pradesh",
        },
        {
            "fix_id": "GEO-02",
            "lat": 12.971600,
            "lon": 77.594600,
            "tier": "TIER_2_WIFI_BSSID",
            "accuracy_meters": 25.0,
            "timestamp": "2026-10-24 10:20:00 IST",
            "label": "Mule Coordination Office (MG Road, Bengaluru)",
            "city": "Bengaluru",
            "state": "Karnataka",
        },
        {
            "fix_id": "GEO-03",
            "lat": 19.076000,
            "lon": 72.877700,
            "tier": "TIER_3_CELLULAR_SECTOR",
            "accuracy_meters": 450.0,
            "azimuth_deg": 120.0,
            "timestamp": "2026-10-23 18:40:00 IST",
            "label": "4G eNodeB Sector Wedge (Bandra Kurla Complex, Mumbai)",
            "city": "Mumbai",
            "state": "Maharashtra",
        },
        {
            "fix_id": "GEO-04",
            "lat": 28.613900,
            "lon": 77.209000,
            "tier": "TIER_4_HYPERLOCAL_DELIVERY",
            "accuracy_meters": 12.0,
            "timestamp": "2026-10-22 13:10:00 IST",
            "label": "Blinkit Grocery Delivery Drop Point (New Delhi)",
            "city": "New Delhi",
            "state": "Delhi",
        },
    ]

    VISUAL_TAMPER_EXHIBITS = {
        "uncrop_curtain": {
            "exhibit_id": "TAMPER-01",
            "title": "Samsung Gallery /Mutations/ Uncrop Proof",
            "cropped_display": "Cropped Bank Receipt Screenshot",
            "uncropped_revealed": "Uncropped Original Desk Photo revealing handwritten 12-Word BIP-39 Crypto Seed Note!",
            "hidden_secret": "abandon ability able about above absent absorb abstract absurd abuse access accident",
        },
        "uidai_qr_verifier": {
            "exhibit_id": "TAMPER-02",
            "title": "Aadhaar Card QR vs Display Face Mismatch",
            "qr_payload_status": "[Aadhaar Redacted - Verhoeff Verified]",
            "qr_rsa_signature": "RSA-2048 Cryptographically Valid",
            "face_tamper_detected": True,
            "tamper_diagnostic": "Card surface photo (male aged ~25) does NOT match official UIDAI embedded .jp2 facial biometric (male aged ~52). Forged card detected.",
        },
        "forged_receipt_scorecard": {
            "exhibit_id": "TAMPER-03",
            "title": "5-Point Forged UPI Receipt Diagnostic",
            "claimed_utr": "699912345678",
            "checks": [
                {"name": "EXIF Creation Tool", "result": "FAILED", "detail": "Created with Adobe Photoshop 25.4 on Windows"},
                {"name": "Viewport Pixel Dimension", "result": "FAILED", "detail": "Non-standard 1080x2400 aspect ratio mismatch"},
                {"name": "Julian-Day (YDDD) Math", "result": "FAILED", "detail": "UTR indicates Day 999 (Invalid: > 366)"},
                {"name": "4-Way Phase 3 Ledger Match", "result": "FAILED", "detail": "Zero matching NPCI or banking logs found"},
                {"name": "ELA Box Font Alignment", "result": "FAILED", "detail": "Error Level Analysis shows spliced text bounding box"},
            ],
            "conclusion": "FABRICATED PAYMENT SCREENSHOT (100% Forgery Probability)",
        },
    }

    KEY_BROKER_VAULTS = [
        {
            "vault_id": "VAULT-01",
            "file_name": "msgstore.db.crypt15",
            "file_path": "/WhatsApp/Databases/msgstore.db.crypt15",
            "cipher": "AES-256-GCM / WhatsApp crypt15",
            "shannon_entropy": 7.98,
            "status": "DECRYPTION_PENDING_KEY_BROKER",
            "candidate_keys": [
                {"key": "Vikram@786", "source": "Recovered Apple Note / Slip", "is_correct": True},
                {"key": "9820194821", "source": "Suspect Primary Mobile", "is_correct": False},
            ],
        },
        {
            "vault_id": "VAULT-02",
            "file_name": "SBI_Statement_Oct2026.pdf",
            "file_path": "/Download/SBI_Statement_Oct2026.pdf",
            "cipher": "Adobe Acrobat Standard 40-bit RC4 / 128-bit AES",
            "shannon_entropy": 7.82,
            "status": "DECRYPTION_PENDING_KEY_BROKER",
            "candidate_keys": [
                {"key": "VIKR0408", "source": "Name4 + DDMM Permutation", "is_correct": True},
                {"key": "123456", "source": "Common PIN", "is_correct": False},
            ],
        },
        {
            "vault_id": "VAULT-03",
            "file_name": "signal.db",
            "file_path": "/data/user/0/org.thoughtcrime.securesms/databases/signal.db",
            "cipher": "SQLCipher v4 (PBKDF2-HMAC-SHA512)",
            "shannon_entropy": 7.99,
            "status": "DECRYPTION_PENDING_KEY_BROKER",
            "candidate_keys": [
                {"key": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403", "source": "Android Keystore Backup", "is_correct": True},
            ],
        },
    ]

    FREEZE_1930_ROWS = [
        {
            "row_id": "FRZ-01",
            "account_no": "9876543210",
            "ifsc": "HDFC0001234",
            "holder_name": "Smt. Sunita Rao (COMPLAINANT / VICTIM)",
            "vpa": "sunita.rao@hdfcbank",
            "role": "LOCKED_VICTIM_ACCOUNT",
            "freeze_locked": True,
            "badge": "[VICTIM / COMPLAINANT - DO NOT FREEZE]",
            "selected_for_freeze": False,
            "amount_disputed_inr": 250000.0,
        },
        {
            "row_id": "FRZ-02",
            "account_no": "301928401928",
            "ifsc": "SBIN0001234",
            "holder_name": "Mule Coordinator Layer 1",
            "vpa": "rsharma@sbi",
            "role": "SUSPECT_MULE_BENEFICIARY",
            "freeze_locked": False,
            "badge": "[TARGET MULE - FREEZE DIRECTIVE]",
            "selected_for_freeze": True,
            "amount_disputed_inr": 95000.0,
        },
        {
            "row_id": "FRZ-03",
            "account_no": "50100293847192",
            "ifsc": "ICIC0005678",
            "holder_name": "Amit Kumar OTC (Mule Layer 2)",
            "vpa": "amit.kumar@icici",
            "role": "SUSPECT_MULE_BENEFICIARY",
            "freeze_locked": False,
            "badge": "[TARGET MULE - FREEZE DIRECTIVE]",
            "selected_for_freeze": True,
            "amount_disputed_inr": 85000.0,
        },
        {
            "row_id": "FRZ-04",
            "account_no": "Binance UID: 91827361",
            "ifsc": "N/A (Crypto Escrow)",
            "holder_name": "P2P Trader Vikram_OTC",
            "vpa": "TRC20: TYk9q8WwJ3x4rZ5m1n8L2pQ9s7V64xLp",
            "role": "SUSPECT_CRYPTO_ESCROW",
            "freeze_locked": False,
            "badge": "[FIU-IND / INTERPOL LERP FREEZE]",
            "selected_for_freeze": True,
            "amount_disputed_inr": 1580.0,
        },
    ]

    FINANCIAL_LEDGER_TRANSACTIONS = [
        {
            "tx_id": "TX-101",
            "utr": "631014892011",
            "timestamp_ist": "2026-10-24 14:32:19 IST",
            "timestamp_utc": "2026-10-24T09:02:19.000000Z",
            "debited_entity": "Smt. Sunita Rao (HDFC 9876543210)",
            "credited_entity": "Mule Account (301928401928)",
            "amount_inr": 95000.0,
            "layer": "Layer 1: Victim Debit -> Layer 2: Mule Tier-1",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        {
            "tx_id": "TX-102",
            "utr": "631014892012",
            "timestamp_ist": "2026-10-24 14:32:38 IST",
            "timestamp_utc": "2026-10-24T09:02:38.000000Z",
            "debited_entity": "Mule Account (301928401928)",
            "credited_entity": "Amit Kumar OTC (ICICI 50100293847192)",
            "amount_inr": 85000.0,
            "layer": "Layer 2: Mule Tier-1 -> Layer 3: Mule Tier-2",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "sha256": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
        },
        {
            "tx_id": "TX-103",
            "utr": "P2P-205918472910",
            "timestamp_ist": "2026-10-24 14:32:45 IST",
            "timestamp_utc": "2026-10-24T09:02:45.000000Z",
            "debited_entity": "Amit Kumar OTC (ICICI 50100293847192)",
            "credited_entity": "Binance P2P Escrow (Trader UID 91827361)",
            "amount_inr": 85000.0,
            "layer": "Layer 3: Mule Tier-2 -> Layer 4: Crypto P2P (1,080 USDT)",
            "state_5d": "LIVE_RECORD",
            "confidence": "ORIGINAL_RECORD",
            "sha256": "8f94a123b784e1b89ef67341ad1245e90214a7e9124a9841fca82341ba928172",
        },
        {
            "tx_id": "TX-104",
            "utr": "TRC20-9182736412",
            "timestamp_ist": "2026-10-24 14:33:45 IST",
            "timestamp_utc": "2026-10-24T09:03:45.000000Z",
            "debited_entity": "Binance Hot Wallet",
            "credited_entity": "TronLink USDT (TYk9q8WwJ3x4rZ5m1n8L2pQ9s7V64xLp)",
            "amount_inr": 85000.0,
            "layer": "Layer 4: Crypto P2P -> Layer 5: Self-Custody TRC-20",
            "state_5d": "LIVE_RECORD",
            "confidence": "HISTORICAL_COMMITTED_RECORD",
            "sha256": "9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
        },
        {
            "tx_id": "TX-105",
            "utr": "XMR-SWAP-00129",
            "timestamp_ist": "2026-10-24 14:35:10 IST",
            "timestamp_utc": "2026-10-24T09:05:10.000000Z",
            "debited_entity": "TronLink USDT Stash",
            "credited_entity": "FixedFloat / Monero Anonymous Pool (XMR)",
            "amount_inr": 85000.0,
            "layer": "Layer 5: TRC-20 -> FixedFloat Monero (XMR Obfuscation)",
            "state_5d": "RESIDUAL_RECORD",
            "confidence": "PARTIAL_RECORD",
            "sha256": "2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d199f281307a63293c",
        },
    ]

    FORENSIC_GROUPS_REGISTRY = [
        {"code": "G01", "name": "INGESTION & OWNERSHIP", "status": "LIVE NODES", "tier": "badge-live", "desc": "Physical Extraction / FFS Container Hierarchy", "count": 142810},
        {"code": "G02", "name": "UPI & WALLETS", "status": "14 RECORDS", "tier": "badge-live", "desc": "PhonePe, Google Pay, Paytm, Navi Ledgers", "count": 14},
        {"code": "G03", "name": "DOMESTIC BANKING", "status": "8 RECORDS", "tier": "badge-live", "desc": "YONO SBI, iMobile, HDFC, BoB Core Stores", "count": 8},
        {"code": "G04", "name": "FINANCIAL SMS & DLT", "status": "32 PARSED", "tier": "badge-orig", "desc": "DLT Header Binding & OTP Corroboration", "count": 32},
        {"code": "G05", "name": "CRYPTO WALLETS", "status": "2 DETECTED", "tier": "badge-live", "desc": "TronLink TRC-20 & MetaMask EVM Vaults", "count": 2},
        {"code": "G06", "name": "EXCHANGES & SEEDS", "status": "1 RECOVERED", "tier": "badge-orig", "desc": "CoinDCX UID & BIP-39 Seed Hunter", "count": 1},
        {"code": "G07", "name": "MAINSTREAM CHATS", "status": "5 RECONSTRUCTED", "tier": "badge-live", "desc": "WhatsApp Dual Clone & Telegram", "count": 5},
        {"code": "G08", "name": "HIGH-OPSEC CHATS", "status": "3 CARVED", "tier": "badge-wal", "desc": "Session 66-hex & SimpleX Agent DB", "count": 3},
        {"code": "G09", "name": "VOIP & COVERT", "status": "2 DETECTED", "tier": "badge-orig", "desc": "Botim & In-Game Chat Residuals", "count": 2},
        {"code": "G10", "name": "CALL LOGS & CONTACTS", "status": "114 COMMITTED", "tier": "badge-live", "desc": "Telecom Call Records & Truecaller", "count": 114},
        {"code": "G11", "name": "WEBVIEW SANDBOXES", "status": "4 EXTRACTED", "tier": "badge-orig", "desc": "App WebViews & IndexedDB Stores", "count": 4},
        {"code": "G12", "name": "OS GEOLOCATION", "status": "4 FIX TIERS", "tier": "badge-live", "desc": "GPS, Wi-Fi BSSID & Cell Towers", "count": 4},
        {"code": "G13", "name": "HYPERLOCAL & RIDES", "status": "3 PROFILES", "tier": "badge-orig", "desc": "Uber, Swiggy Instamart & Zomato", "count": 3},
        {"code": "G14", "name": "WIFI / BT / NETSTATS", "status": "18 BSSIDS", "tier": "badge-orig", "desc": "Known Wi-Fi & Bluetooth Pairings", "count": 18},
        {"code": "G15", "name": "BEHAVIORAL TELEMETRY", "status": "84 STREAMS", "tier": "badge-live", "desc": "Apple Biome & Android AppOps APEX", "count": 84},
        {"code": "G16", "name": "KEYCHAIN & TAMPER", "status": "3 UNWRAPPED", "tier": "badge-wal", "desc": "SQLCipher & Android Keystore Keys", "count": 3},
        {"code": "G17", "name": "MEDIA & C2PA RESIDUALS", "status": "1 FORGERY", "tier": "badge-freelist", "desc": "Forged Receipts & C2PA JUMBF Box", "count": 1},
        {"code": "G18", "name": "APKS & OCR INDEX", "status": "FTS5 INDEXED", "tier": "badge-orig", "desc": "Bilingual Devanagari OCR & APKs", "count": 18},
    ]

    def get_full_workspace_bootstrap(self) -> dict[str, Any]:
        """Provides consolidated initial state for all 7 workspaces."""
        # Render dynamic Myers Redline for the edited message
        myers_engine = MyersRedlineEngine()
        redline_res = myers_engine.compute_redline(
            "Bhai 50,000 rupaye bhej do urgently, sham tak return kar dunga.",
            "Bhai 1,50,000 rupaye bhej do Hawala account me, kal sham tak settle kar dunga.",
        )
        if self.CHAT_THREADS.get("messages") and len(self.CHAT_THREADS["messages"]) > 2:
            self.CHAT_THREADS["messages"][2]["myers_diff_html"] = redline_res.html_rendered_diff

        # Render dynamic Sankey Canvas SVG
        sankey_renderer = SankeyCanvasRenderer()
        sankey_svg = sankey_renderer.render_svg()

        # Render default Hybrid Map
        geocoder = HybridReverseGeocoder()
        default_loc = geocoder.resolve_location(25.317600, 82.973900, force_offline=False)
        map_html = geocoder.render_hybrid_map_html(
            markers=[
                {"lat": f["lat"], "lon": f["lon"], "label": f"{f['label']} ({f['tier']})"}
                for f in self.GEOSPATIAL_FIXES
            ]
        )

        return {
            "status": "BOOTSTRAP_SUCCESS",
            "case_metadata": self.CASE_METADATA,
            "timeline_events": self.TIMELINE_EVENTS,
            "chat_threads": self.CHAT_THREADS,
            "action_burst_storyboard": self.ACTION_BURST_STORYBOARD,
            "geospatial_fixes": self.GEOSPATIAL_FIXES,
            "resolved_default_location": {
                "lat": default_loc.latitude,
                "lon": default_loc.longitude,
                "formatted": default_loc.lat_lon_formatted,
                "cardinal": default_loc.cardinal_formatted,
                "address": default_loc.display_address,
                "city": default_loc.city_or_district,
                "state": default_loc.state_name,
                "source": default_loc.resolution_source,
                "map_html": map_html,
            },
            "visual_tamper_exhibits": self.VISUAL_TAMPER_EXHIBITS,
            "key_broker_vaults": self.KEY_BROKER_VAULTS,
            "freeze_1930_rows": self.FREEZE_1930_ROWS,
            "financial_ledger_transactions": self.FINANCIAL_LEDGER_TRANSACTIONS,
            "forensic_groups_registry": self.FORENSIC_GROUPS_REGISTRY,
            "initial_redline": {
                "html_rendered_diff": redline_res.html_rendered_diff,
                "insertions": redline_res.insertions_count,
                "deletions": redline_res.deletions_count,
            },
            "initial_sankey_svg": sankey_svg,
            "generated_timestamp": time.time(),
        }

    def get_event_hex_inspection(self, event_id: str) -> dict[str, Any]:
        """Calculates 64-byte raw binary hex representation and data interpreter values."""
        product_a = self.CASE_METADATA["dual_sha256"]["product_a_container"]
        product_b = self.CASE_METADATA["dual_sha256"]["product_b_staging"]
        matched: Optional[dict[str, Any]] = None
        raw_bytes: bytes = b""

        ios_events: dict[str, dict[str, Any]] = {
            "EVT-IOS-01": {
                "event_id": "EVT-IOS-01",
                "summary": "com.apple.MobileSMS brought to foreground during DLT OTP ingress",
                "vfs_path": "/private/var/mobile/Library/Biome/streams/restricted/App.InFocus",
                "sqlite_page": 84,
                "cell_offset": 512,
                "wal_frame": None,
                "raw_hex": "5345474230303032" + "02" * 24 + "00" * 32,
                "product_a": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
                "product_b": "9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
            },
            "EVT-IOS-02": {
                "event_id": "EVT-IOS-02",
                "summary": "DLT Bank SMS from *-SBIINB: OTP 849201 for Rs 95,000 transfer",
                "vfs_path": "/private/var/mobile/Library/SMS/sms.db",
                "sqlite_page": 218,
                "cell_offset": 1024,
                "wal_frame": 42,
                "raw_hex": "53514C69746520666F726D6174203300" + "42" * 16 + "00" * 32,
                "product_a": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
                "product_b": "9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
            },
            "EVT-IOS-03": {
                "event_id": "EVT-IOS-03",
                "summary": "DCIM/100APPLE/IMG_0192.PNG: Payment confirmation captured",
                "vfs_path": "/private/var/mobile/Media/PhotoData/Photos.sqlite",
                "sqlite_page": 512,
                "cell_offset": 256,
                "wal_frame": None,
                "raw_hex": "89504E470D0A1A0A0000000D49484452" + "FF" * 16 + "00" * 32,
                "product_a": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
                "product_b": "9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
            },
        }

        if event_id in ios_events:
            matched = ios_events[event_id]
            product_a = str(matched["product_a"])
            product_b = str(matched["product_b"])
            raw_bytes = bytes.fromhex(str(matched["raw_hex"])[:128].ljust(128, "0"))
        else:
            matched_tl = next((e for e in self.TIMELINE_EVENTS if e["event_id"] == event_id), None)
            if matched_tl:
                matched = matched_tl
                raw_buffer = bytearray(64)
                raw_buffer[0:16] = b"SQLITE FORMAT 3\x00"
                raw_buffer[16:40] = b"\x05\x1B\x24\xA9\x10\xE8\x29\x10UTR631014892011"
                raw_buffer[40:56] = b"WAL_FRM_SALT_001"
                raw_buffer[56:64] = b"\x00\xFF\x00\xFF\xAA\x55\xAA\x55"
                raw_bytes = bytes(raw_buffer)
            else:
                try:
                    from src.workstation_app.dashboard_server import GLOBAL_INGEST_ENGINE
                    for dev in GLOBAL_INGEST_ENGINE.active_devices.values():
                        for evt in dev.timeline_events:
                            if evt.get("event_id") == event_id:
                                matched = evt
                                product_a = dev.product_a_sha256
                                product_b = dev.product_b_sha256
                                hex_p = evt.get("raw_hex_preview", "")
                                if hex_p:
                                    raw_bytes = bytes.fromhex(hex_p[:128].ljust(128, "0"))
                                else:
                                    raw_bytes = b"SQLITE FORMAT 3\x00" + b"\x00" * 48
                                break
                        if matched:
                            break
                except Exception as exc_ingest:
                    _ = str(exc_ingest)

        if not matched:
            matched = self.TIMELINE_EVENTS[0]
            raw_bytes = b"SQLITE FORMAT 3\x00\x05\x1B\x24\xA9\x10\xE8\x29\x10UTR631014892011WAL_FRM_SALT_001\x00\xFF\x00\xFF\xAA\x55\xAA\x55"

        if len(raw_bytes) < 64:
            raw_bytes = raw_bytes.ljust(64, b"\x00")
        elif len(raw_bytes) > 64:
            raw_bytes = raw_bytes[:64]
        inspector = HexProvenanceInspector()
        slice_res = inspector.inspect_byte_slice(raw_bytes, cursor_byte_offset=0, slice_length=64)

        # 4-Layer highlighting annotations
        layer_spans = [
            {"start": 0, "end": 16, "layer": "LAYER_1_HEADER", "color": "#f59e0b", "label": "Record / B-Tree Header"},
            {"start": 16, "end": 40, "layer": "LAYER_2_PAYLOAD", "color": "#38bdf8", "label": "Extracted Column Payload (UTR)"},
            {"start": 40, "end": 56, "layer": "LAYER_3_WAL", "color": "#a855f7", "label": "WAL Frame Header & Salts"},
            {"start": 56, "end": 64, "layer": "LAYER_4_SLACK", "color": "#f43f5e", "label": "Unallocated Cell Slack"},
        ]

        decoder = DataInterpreterDecoder()
        interp = decoder.decode_all_formats(raw_bytes[16:32])

        # Format 4 rows of 16 bytes each
        rows = []
        for r in range(4):
            offset_start = r * 16
            row_bytes = raw_bytes[offset_start : offset_start + 16]
            hex_tokens = [f"{b:02X}" for b in row_bytes]
            ascii_chars = "".join([chr(b) if 32 <= b <= 126 else "." for b in row_bytes])
            rows.append({
                "offset_hex": f"0x{offset_start:04X}",
                "hex_tokens": hex_tokens,
                "ascii_str": ascii_chars,
            })

        return {
            "event_id": matched["event_id"],
            "summary": matched["summary"],
            "vfs_path": matched["vfs_path"],
            "sqlite_page": matched.get("sqlite_page", 1),
            "cell_offset": matched.get("cell_offset", 0),
            "wal_frame": matched.get("wal_frame"),
            "product_a_sha256": product_a,
            "product_b_sha256": product_b,
            "md5_fingerprint": "9e107d9d372bb6826bd81d3542a419d6",
            "raw_hex_all": raw_bytes.hex().upper(),
            "hex_rows": rows,
            "layer_spans": layer_spans,
            "data_interpreter": {
                "uint8": interp.uint8,
                "int8": interp.int8,
                "uint16_le": interp.uint16_le,
                "uint16_be": interp.uint16_be,
                "int32_le": interp.int32_le,
                "uint32_le": interp.uint32_le,
                "int64_le": interp.int64_le,
                "uint64_le": interp.uint64_le,
                "sqlite_varint": interp.sqlite_varint,
                "sleb128": interp.leb128_varint,
                "float32_le": interp.float32_le,
                "float64_le": interp.float64_le,
                "unix_epoch_sec": interp.unix_s_ist_utc,
                "unix_epoch_ms": interp.unix_ms_ist_utc,
                "apple_cocoa_epoch": interp.cocoa_s_ist_utc,
                "hex_representation": interp.hex_string[:32],
                "utf8_string": interp.utf8_string,
            },
        }

    def unlock_vault(self, vault_id: str, candidate_pass: str) -> dict[str, Any]:
        """Simulates unlocking a locked cryptographic vault with DAG hot-patching."""
        matched_vault = next((v for v in self.KEY_BROKER_VAULTS if v["vault_id"] == vault_id), None)
        if not matched_vault:
            return {
                "success": False,
                "message": f"Vault ID '{vault_id}' not found.",
                "elapsed_seconds": 0.05,
            }

        # Check candidate passphrase
        correct_key = next((k["key"] for k in matched_vault["candidate_keys"] if k.get("is_correct")), None)
        is_match = (candidate_pass.strip() == correct_key)

        if is_match:
            return {
                "success": True,
                "vault_id": vault_id,
                "file_name": matched_vault["file_name"],
                "status": "UNLOCKED_DECRYPTED",
                "message": f"Vault '{matched_vault['file_name']}' successfully decrypted with key '{candidate_pass}'.",
                "dag_hot_patch": {
                    "step1_target_decrypt": "PASSED (AES-256-GCM / PBKDF2 unwrap)",
                    "step2_incremental_carve": "PASSED (248 records recovered)",
                    "step3_entity_graph_append": "PASSED (14 new graph edges synthesized)",
                    "step4_timeline_resort": "PASSED (Indexed into Unified Super-Timeline)",
                    "step5_fts5_index_update": "PASSED (Full-text tokens refreshed)",
                },
                "elapsed_seconds": 1.42,
            }
        else:
            return {
                "success": False,
                "vault_id": vault_id,
                "file_name": matched_vault["file_name"],
                "status": "DECRYPTION_FAILED",
                "message": f"Passphrase '{candidate_pass}' failed authentication check (MAC / Checksum mismatch).",
                "elapsed_seconds": 0.18,
            }
