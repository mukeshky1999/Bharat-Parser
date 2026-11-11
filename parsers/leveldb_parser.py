"""Pure-Python LevelDB Carver.

Extracts structured JSON events and binary Protobuf entries from .ldb, .log,
and .sst files.
"""

import os
import re
from typing import List
import pandas as pd
from parsers.protobuf_decoder import decode_protobuf_stream, extract_financials_from_protobuf


def carve_leveldb_directory(leveldb_dir: str) -> pd.DataFrame:
  """Scans LevelDB stores (.ldb, .log, and .sst files) without external C++

  bindings. Extracts key-value text pairs, JSON strings, and binary Protobuf
  blobs.
  """
  records: List[dict] = []
  if not os.path.isdir(leveldb_dir):
    return pd.DataFrame(
        columns=['Timestamp', 'Title', 'Body', 'Source_File', 'Type']
    )

  for root, _, files in os.walk(leveldb_dir):
    for f in files:
      if f.lower().endswith(('.log', '.ldb', '.sst')):
        file_path = os.path.join(root, f)
        try:
          with open(file_path, 'rb') as fp:
            raw_data = fp.read()

          # 1. Carve ASCII/UTF-8 JSON & String blocks
          json_matches = re.finditer(rb'\{[^{}]{20,1000}\}', raw_data)
          for m in json_matches:
            try:
              s = m.group(0).decode('utf-8', errors='ignore')
              if any(
                  k in s.lower()
                  for k in [
                      'amount',
                      'txn',
                      'vpa',
                      'upi',
                      'balance',
                      'payment',
                  ]
              ):
                records.append({
                    'Timestamp': None,
                    'Title': f'LevelDB JSON ({f})',
                    'Body': s[:300].strip(),
                    'Source_File': f,
                    'Type': 'LevelDB_JSON',
                })
            except Exception:
              continue

          # 2. Carve Binary Protobuf slices
          for offset in range(0, max(0, len(raw_data) - 16), 32):
            b0 = raw_data[offset]
            if b0 == 0x00:
              continue
            if not (b0 & 0x80 or 0x01 <= b0 <= 0x7F):
              continue
            chunk = raw_data[offset : offset + 128]
            decoded_pb = decode_protobuf_stream(chunk, max_depth=2)
            if decoded_pb:
              fin = extract_financials_from_protobuf(decoded_pb)
              if fin['Amount'] or fin['Counterparty']:
                records.append({
                    'Timestamp': (
                        str(fin.get('Date')) if fin.get('Date') else None
                    ),
                    'Title': f'LevelDB Protobuf ({f})',
                    'Body': (
                        f"Amount: {fin['Amount']} | VPA:"
                        f" {fin['Counterparty']} | TxID:"
                        f" {fin['Transaction_ID']}"
                    ),
                    'Source_File': f,
                    'Type': 'LevelDB_Protobuf',
                })
        except Exception:
          continue

  if records:
    return pd.DataFrame(records)
  return pd.DataFrame(
      columns=['Timestamp', 'Title', 'Body', 'Source_File', 'Type']
  )


def classify_leveldb_payload(payload: dict) -> str:
  """Returns 'TRANSACTION' when payload dict contains financial keys/amounts, else 'NOTIFICATION'."""
  if not isinstance(payload, dict):
    return 'NOTIFICATION'
  body = str(payload.get('Body', '')).lower()
  title = str(payload.get('Title', '')).lower()
  combined = f"{title} {body}"
  tx_indicators = [
      'amount:', 'amount :', 'vpa:', 'txid:', 'txn', 'transaction',
      'paid', 'received', 'transferred', 'debited', 'credited', 'payment', 'order_id'
  ]
  if any(ind in combined for ind in tx_indicators):
    return 'TRANSACTION'
  return 'NOTIFICATION'
