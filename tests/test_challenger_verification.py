import sqlite3
from pathlib import Path
from src.upi.gpay import GooglePayDecoder
from parsers.enterprise_1tb_chat_and_container_engine import parse_whatsapp_full_forensics
from parsers.heuristic_engine import parse_database_artifacts

print("--- Testing GooglePayDecoder on test_evidence/paisa.db ---")
gpay = GooglePayDecoder()
try:
    txs, chats = gpay.decode_database("test_evidence/paisa.db")
    print(f"GooglePayDecoder parsed: {len(txs)} txs, {len(chats)} chats")
except Exception as e:
    print(f"GooglePayDecoder ERROR: {type(e).__name__}: {e}")

print("\n--- Testing parse_whatsapp_full_forensics on test_evidence/msgstore.db ---")
try:
    df_chats, df_contacts = parse_whatsapp_full_forensics("test_evidence/msgstore.db")
    print(f"parse_whatsapp_full_forensics parsed: {len(df_chats)} chats, {len(df_contacts)} contacts")
except Exception as e:
    print(f"parse_whatsapp_full_forensics ERROR: {type(e).__name__}: {e}")

print("\n--- Testing parse_database_artifacts on test_evidence/msgstore.db ---")
try:
    res = parse_database_artifacts("test_evidence/msgstore.db")
    print(f"parse_database_artifacts on msgstore.db: {len(res['chats'])} chats, {len(res['transactions'])} txs")
except Exception as e:
    print(f"parse_database_artifacts ERROR: {type(e).__name__}: {e}")

