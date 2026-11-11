"""
Unit Tests for commercial_parity_engine.py
Verifies recursive multi-layer binary unpacker, universal App Genie classifier,
and universal all-category B-Tree / WAL carver.
"""

import base64
import gzip
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import tempfile
import unittest
import zlib
import pandas as pd

from parsers.commercial_parity_engine import (
    MODEL_CALL_LOG,
    MODEL_CHAT_MESSAGE,
    MODEL_FINANCIAL_TRANSACTION,
    MODEL_LOCATION_PIN,
    MODEL_USER_ACCOUNT_OR_CONTACT,
    MODEL_WEB_OR_SEARCH_HISTORY,
    app_genie_classify_table,
    carve_deleted_all_categories_mmap,
    pure_python_decode_cbor,
    pure_python_decode_msgpack,
    pure_python_decompress_lz4_block,
    pure_python_decompress_lz4_frame,
    recursive_forensic_unpack,
    resolve_nskeyedarchiver_tree,
)


class TestCommercialParityEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_parity_engine_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. MODULE 1: COMPRESSION & CONTAINER DECODERS
    # --------------------------------------------------------------------------
    def test_pure_python_lz4_decompression(self):
        # 1. Literal block
        block_literal = bytes([0x50]) + b"Hello"
        self.assertEqual(pure_python_decompress_lz4_block(block_literal), b"Hello")

        # 2. Block with match copy: ABCDEF + ABCDEF
        block_match = bytes([0x62]) + b"ABCDEF" + bytes([6, 0])
        self.assertEqual(pure_python_decompress_lz4_block(block_match), b"ABCDEFABCDEF")

        # 3. Frame format
        frame_header = b"\x04\x22\x4D\x18" + bytes([0x40, 0x40, 0x00])
        block_size_bytes = struct.pack("<I", len(block_match))
        end_mark = struct.pack("<I", 0)
        lz4_frame_data = frame_header + block_size_bytes + block_match + end_mark
        decomp = pure_python_decompress_lz4_frame(lz4_frame_data)
        self.assertEqual(decomp, b"ABCDEFABCDEF")

    def test_pure_python_msgpack_and_cbor(self):
        # 1. MessagePack test map: {"name": "Satoshi", "age": 42}
        # fixmap(2) = 0x82, fixstr(4) "name" = 0xa4 'name', fixstr(7) "Satoshi" = 0xa7 'Satoshi'
        # fixstr(3) "age" = 0xa3 'age', positive fixint(42) = 42
        mp_data = bytes([0x82, 0xA4]) + b"name" + bytes([0xA7]) + b"Satoshi" + bytes([0xA3]) + b"age" + bytes([42])
        mp_obj, _ = pure_python_decode_msgpack(mp_data)
        self.assertIsInstance(mp_obj, dict)
        self.assertEqual(mp_obj.get("name"), "Satoshi")
        self.assertEqual(mp_obj.get("age"), 42)

        # 2. CBOR test map: {"vpa": "test@okhdfcbank", "amount": 500}
        # major 5 (map 2 pairs) -> 0xa2
        # major 3 (text 3 "vpa") -> 0x63 'vpa'
        # major 3 (text 15 "test@okhdfcbank") -> 0x6f 'test@okhdfcbank'
        # major 3 (text 6 "amount") -> 0x66 'amount'
        # major 0 (uint 500) -> 0x19, 0x01, 0xf4
        cbor_data = bytes([0xA2, 0x63]) + b"vpa" + bytes([0x6F]) + b"test@okhdfcbank" + bytes([0x66]) + b"amount" + bytes([0x19, 0x01, 0xF4])
        cbor_obj, _ = pure_python_decode_cbor(cbor_data)
        self.assertIsInstance(cbor_obj, dict)
        self.assertEqual(cbor_obj.get("vpa"), "test@okhdfcbank")
        self.assertEqual(cbor_obj.get("amount"), 500)

    def test_nskeyedarchiver_tree_resolution(self):
        mock_plist = {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {
                    "$class": plistlib.UID(3),
                    "NS.keys": [plistlib.UID(2)],
                    "NS.objects": [plistlib.UID(4)],
                },
                "suspect_vpa",
                {
                    "$classes": ["NSDictionary", "NSObject"],
                    "$classname": "NSDictionary",
                },
                "scammer@okhdfcbank",
            ],
        }
        bplist_data = plistlib.dumps(mock_plist, fmt=plistlib.FMT_BINARY)
        res = recursive_forensic_unpack(bplist_data)
        self.assertIn("nskeyedarchiver_plist", res["layers"])
        self.assertIsInstance(res["unpacked"], dict)
        self.assertEqual(res["unpacked"].get("suspect_vpa"), "scammer@okhdfcbank")
        self.assertIn("scammer@okhdfcbank", res["entities"]["vpas"])

    def test_recursive_nested_unpacking(self):
        # Create a nested payload: Inner JSON -> Gzip compressed -> Base64 encoded
        inner_dict = {
            "vpa": "ransom@paytm",
            "phone": "+919876543210",
            "utr": "628192837491",
            "url": "https://cybercrime.gov.in/report",
            "loc": "12.9716, 77.5946",
        }
        json_bytes = json.dumps(inner_dict).encode("utf-8")
        gzip_bytes = gzip.compress(json_bytes)
        b64_string = base64.b64encode(gzip_bytes).decode("ascii")

        unpacked_res = recursive_forensic_unpack(b64_string)
        self.assertIn("base64", unpacked_res["layers"])
        self.assertIn("gzip", unpacked_res["layers"])
        self.assertIn("json", unpacked_res["layers"])
        self.assertIsInstance(unpacked_res["unpacked"], dict)
        self.assertEqual(unpacked_res["unpacked"]["vpa"], "ransom@paytm")

        # Verify entity harvester
        self.assertIn("ransom@paytm", unpacked_res["entities"]["vpas"])
        self.assertIn("+919876543210", unpacked_res["entities"]["phones"])
        self.assertIn("628192837491", unpacked_res["entities"]["utrs"])
        self.assertIn("https://cybercrime.gov.in/report", unpacked_res["entities"]["urls"])
        self.assertIn("12.9716, 77.5946", unpacked_res["entities"]["coordinates"])

    # --------------------------------------------------------------------------
    # 2. MODULE 2: APP GENIE UNIVERSAL HEURISTIC CLASSIFIER
    # --------------------------------------------------------------------------
    def test_app_genie_chat_classification(self):
        df_chat = pd.DataFrame({
            "msg_id": [1, 2],
            "text_content": ["Send the payment", "Already transferred"],
            "timestamp": [1700000000000, 1700000001000],
            "sender_jid": ["user1@chat.net", "user2@chat.net"],
            "is_outgoing": [0, 1],
        })
        res = app_genie_classify_table(df_chat, "conversations", "chat.db")
        self.assertEqual(res["model"], MODEL_CHAT_MESSAGE)
        self.assertGreaterEqual(res["confidence"], 0.7)
        extracted = res["extracted_records"]
        self.assertEqual(len(extracted), 2)
        self.assertIn("Application", extracted.columns)
        self.assertIn("Message_Body", extracted.columns)
        self.assertEqual(extracted.iloc[0]["Message_Body"], "Send the payment")

    def test_app_genie_call_log_classification(self):
        df_call = pd.DataFrame({
            "call_id": [101, 102],
            "peer_phone": ["+919876543210", "+919876543211"],
            "call_duration": [120, 0],
            "call_time": [1700000000, 1700001000],
            "direction": [1, 0],
        })
        res = app_genie_classify_table(df_call, "call_history", "calls.db")
        self.assertEqual(res["model"], MODEL_CALL_LOG)
        extracted = res["extracted_records"]
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted.iloc[0]["Duration_Sec"], 120)
        self.assertEqual(extracted.iloc[0]["Call_Result"], "Connected Call")
        self.assertEqual(extracted.iloc[1]["Call_Result"], "Missed Call")

    def test_app_genie_location_classification(self):
        df_geo = pd.DataFrame({
            "point_id": [1, 2],
            "geo_lat": [12.9716, 28.6139],
            "geo_lon": [77.5946, 77.2090],
            "timestamp": [1700000000, 1700002000],
            "place": ["Bangalore", "New Delhi"],
        })
        res = app_genie_classify_table(df_geo, "waypoints", "geo.db")
        self.assertEqual(res["model"], MODEL_LOCATION_PIN)
        extracted = res["extracted_records"]
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted.iloc[0]["Geo_Coordinates"], "12.9716, 77.5946")

    def test_app_genie_contact_classification(self):
        df_contact = pd.DataFrame({
            "uid": [1, 2],
            "display_name": ["Rahul Sharma", "Priya Patel"],
            "phone_number": ["+919876543210", "+919123456789"],
            "email": ["rahul@example.com", "priya@example.com"],
        })
        res = app_genie_classify_table(df_contact, "friends_list", "app.db")
        self.assertEqual(res["model"], MODEL_USER_ACCOUNT_OR_CONTACT)
        extracted = res["extracted_records"]
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted.iloc[0]["Contact_Name"], "Rahul Sharma")

    def test_app_genie_financial_classification(self):
        df_tx = pd.DataFrame({
            "txn_id": ["T2401010001", "T2401010002"],
            "trans_amount": [2500.0, 150.0],
            "payee_vpa": ["merchant@okaxis", "coffee@paytm"],
            "timestamp": [1700000000, 1700001000],
        })
        res = app_genie_classify_table(df_tx, "passbook_entries", "bank.db")
        self.assertEqual(res["model"], MODEL_FINANCIAL_TRANSACTION)
        extracted = res["extracted_records"]
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted.iloc[0]["Counterparty"], "merchant@okaxis")

    # --------------------------------------------------------------------------
    # 3. MODULE 3: UNIVERSAL CARVER FOR ALL CATEGORIES
    # --------------------------------------------------------------------------
    def test_carve_deleted_all_categories_mmap(self):
        db_path = os.path.join(self.test_dir, "test_carve.db")
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA page_size = 4096;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("CREATE TABLE chats (id INTEGER PRIMARY KEY, msg TEXT, sender TEXT, ts INTEGER);")
        conn.execute("CREATE TABLE calls (id INTEGER PRIMARY KEY, peer TEXT, dur INTEGER, ts INTEGER);")
        conn.execute("CREATE TABLE locations (id INTEGER PRIMARY KEY, lat REAL, lon REAL, ts INTEGER);")
        conn.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, vpa TEXT, amt REAL, ts INTEGER);")

        conn.execute("INSERT INTO chats VALUES (1, 'Active chat', '+919876543210', 1700000000);")
        conn.execute("INSERT INTO calls VALUES (1, '+919876543210', 45, 1700000000);")
        conn.execute("INSERT INTO locations VALUES (1, 12.9716, 77.5946, 1700000000);")
        conn.execute("INSERT INTO payments VALUES (1, 'victim@okhdfcbank', 12500.0, 1700000000);")
        conn.commit()

        # Delete rows so they become freeblocks / unallocated cell slack
        conn.execute("DELETE FROM chats WHERE id = 1;")
        conn.execute("DELETE FROM calls WHERE id = 1;")
        conn.execute("DELETE FROM locations WHERE id = 1;")
        conn.execute("DELETE FROM payments WHERE id = 1;")
        conn.commit()
        conn.close()

        carved = carve_deleted_all_categories_mmap(db_path)
        self.assertIn("deleted_transactions", carved)
        self.assertIn("deleted_chats", carved)
        self.assertIn("deleted_calls", carved)
        self.assertIn("deleted_locations", carved)

        # Verify carver outputs
        df_tx = carved["deleted_transactions"]
        df_chats = carved["deleted_chats"]
        df_calls = carved["deleted_calls"]
        df_locs = carved["deleted_locations"]

        # At least one category successfully recovered from unallocated gaps / WAL frames
        total_recovered = len(df_tx) + len(df_chats) + len(df_calls) + len(df_locs)
        self.assertGreater(total_recovered, 0)


if __name__ == "__main__":
    unittest.main()
