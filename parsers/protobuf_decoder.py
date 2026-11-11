"""
Phase 1 & 2: Schema-less Protobuf Deserializer & Dynamic Schema Synthesis Engine.
Requires a valid VPA or Transaction ID anchor before extracting numeric amounts from raw wire streams.
"""

from __future__ import annotations

import re
import struct
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decodes a variable-length integer (varint) from binary data with strict 10-byte bound."""
    res = 0
    shift = 0
    bytes_read = 0
    while offset < len(data) and bytes_read < 10:
        b = data[offset]
        offset += 1
        bytes_read += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, offset
        shift += 7
    return res, offset


def decode_protobuf_stream(
    data: bytes, max_depth: int = 4
) -> Optional[Dict[int, List[Any]]]:
    """
    Pure Python schema-less Protobuf wire-type parser.
    Supports wire types: 0 (Varint), 1 (64-bit), 2 (Length-delimited), 5 (32-bit).
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0 or max_depth < 0:
        return None

    offset = 0
    fields: Dict[int, List[Any]] = {}

    while offset < len(data):
        try:
            key, offset = decode_varint(data, offset)
            field_num = key >> 3
            wire_type = key & 0x07

            if field_num == 0 or field_num > 536870911:
                break

            if wire_type == 0:  # Varint
                val, offset = decode_varint(data, offset)
            elif wire_type == 1:  # 64-bit
                if offset + 8 > len(data):
                    break
                val = struct.unpack('<Q', data[offset:offset + 8])[0]
                offset += 8
            elif wire_type == 2:  # Length-delimited
                length, offset = decode_varint(data, offset)
                if length < 0 or offset + length > len(data):
                    break
                if length == 0:
                    val = ""
                    if field_num not in fields:
                        fields[field_num] = []
                    fields[field_num].append(val)
                    continue
                chunk = data[offset:offset + length]
                offset += length

                sub_msg = decode_protobuf_stream(chunk, max_depth - 1)
                if sub_msg:
                    val = sub_msg
                else:
                    try:
                        val = chunk.decode('utf-8')
                    except UnicodeDecodeError:
                        val = chunk
            elif wire_type == 5:  # 32-bit
                if offset + 4 > len(data):
                    break
                val = struct.unpack('<I', data[offset:offset + 4])[0]
                offset += 4
            else:
                break

            if field_num not in fields:
                fields[field_num] = []
            fields[field_num].append(val)
        except Exception:
            break

    return fields if fields else None


class ProtobufSchemaSynthesizer:
    """
    Synthesizes coherent .proto schema definitions by aggregating observations
    across deserialized records.
    """
    def __init__(self, message_name: str = 'FinancialEntityPayload'):
        self.message_name = message_name
        self.field_observations: Dict[int, List[Any]] = defaultdict(list)
        self.field_wire_types: Dict[int, Counter] = defaultdict(Counter)

    def observe(self, decoded_dict: Dict[int, List[Any]]) -> None:
        if not isinstance(decoded_dict, dict):
            return
        for tag, values in decoded_dict.items():
            for v in values:
                self.field_observations[tag].append(v)
                if isinstance(v, int):
                    self.field_wire_types[tag]['varint'] += 1
                elif isinstance(v, float):
                    self.field_wire_types[tag]['float'] += 1
                elif isinstance(v, str):
                    self.field_wire_types[tag]['string'] += 1
                elif isinstance(v, dict):
                    self.field_wire_types[tag]['message'] += 1
                elif isinstance(v, (bytes, bytearray)):
                    self.field_wire_types[tag]['bytes'] += 1

    def synthesize_proto_definition(self) -> str:
        lines = [
            'syntax = "proto3";',
            '// Synthesized by UPI Forensic Intelligence Suite',
            f'message {self.message_name} {{',
        ]
        for tag in sorted(self.field_observations.keys()):
            samples = self.field_observations[tag]
            top_type = self.field_wire_types[tag].most_common(1)[0][0] if self.field_wire_types[tag] else 'bytes'

            proto_type = 'bytes'
            field_name = f'field_{tag}'

            if top_type == 'varint':
                sample_ints = [s for s in samples if isinstance(s, int)]
                if sample_ints and all(s in (0, 1) for s in sample_ints):
                    proto_type = 'bool'
                    field_name = f'is_flag_{tag}'
                elif sample_ints and any(s > 1500000000000 for s in sample_ints):
                    proto_type = 'int64'
                    field_name = f'timestamp_{tag}'
                elif sample_ints and any(100 <= s <= 10000000 for s in sample_ints):
                    proto_type = 'int64'
                    field_name = f'amount_paise_{tag}'
                else:
                    proto_type = 'int64'
            elif top_type == 'string':
                proto_type = 'string'
                sample_strs = [s for s in samples if isinstance(s, str)]
                if any('@' in s for s in sample_strs):
                    field_name = f'vpa_handle_{tag}'
                elif any(re.match(r'^[0-9A-Za-z]{12,22}$', s) for s in sample_strs):
                    field_name = f'utr_ref_{tag}'
                else:
                    field_name = f'text_{tag}'
            elif top_type == 'message':
                proto_type = f'SubMessage_{tag}'
                field_name = f'nested_payload_{tag}'

            is_repeated = len(samples) > 1 and len(samples) != len(set(id(s) for s in samples))
            prefix = 'repeated ' if is_repeated else ''
            lines.append(f'    {prefix}{proto_type} {field_name} = {tag};')

        lines.append('}')
        return '\n'.join(lines)


def infer_protobuf_schema(parsed_dict: Dict[int, List[Any]]) -> Dict[str, str]:
    schema: Dict[str, str] = {}
    if not isinstance(parsed_dict, dict):
        return schema

    wire_type_names = {
        int: 'int64 (varint)',
        str: 'string',
        bytes: 'bytes',
        dict: 'message (nested)',
        float: 'float/double',
    }
    for field_tag, values in parsed_dict.items():
        if values:
            val_type = type(values[0])
            schema[f'field_{field_tag}'] = wire_type_names.get(val_type, 'unknown_type')
    return schema


def extract_financials_from_protobuf(parsed_dict: Any) -> Dict[str, Any]:
    """
    Traverses a decoded Protobuf tree to extract financial indicators.
    Specifically recognizes Google Pay's `google.type.Money` sub-messages (`"INR"` + units/micros),
    verified NPCI VPAs, 12-digit UTRs, and 35-char NPCI transaction IDs.
    """
    empty_out: Dict[str, Any] = {
        'Amount': None,
        'Transaction_ID': None,
        'Date': None,
        'Counterparty': None,
    }
    if not isinstance(parsed_dict, dict):
        return empty_out

    from parsers.vpa_harvester import clean_and_validate_vpa

    inr_submsg_amt: Optional[float] = None
    candidate_amt: Optional[float] = None
    candidate_date: Optional[int] = None
    candidate_cpty: Optional[str] = None
    candidate_txid: Optional[str] = None

    def walk(node: Any) -> None:
        nonlocal inr_submsg_amt, candidate_amt, candidate_date, candidate_cpty, candidate_txid
        if isinstance(node, dict):
            # Check if this sub-message is a Google Pay CurrencyAmount / Money object containing "INR"
            flat_vals = [v for v_list in node.values() for v in (v_list if isinstance(v_list, list) else [v_list])]
            has_inr = any(isinstance(x, str) and x.strip().upper() == 'INR' for x in flat_vals)
            if has_inr and inr_submsg_amt is None:
                for x in flat_vals:
                    if isinstance(x, (int, float)) and not isinstance(x, bool) and x > 0:
                        if x >= 10_000_000 and x % 10000 == 0:
                            inr_submsg_amt = float(x) / 1_000_000.0
                        else:
                            inr_submsg_amt = float(x)
                        break

            for _, val_list in node.items():
                if isinstance(val_list, list):
                    for v in val_list:
                        walk(v)
                else:
                    walk(val_list)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            node_clean = node.strip()
            if '@' in node_clean and not candidate_cpty:
                for tok in re.findall(r'[a-zA-Z0-9.\-_]{3,64}@[a-zA-Z0-9]{2,32}', node_clean):
                    v_ok = clean_and_validate_vpa(tok)
                    if v_ok:
                        candidate_cpty = v_ok
                        break
            elif not candidate_txid and (
                re.match(r'^[0-9]{12}$', node_clean)
                or re.match(r'^T\d{18,24}$', node_clean)
                or re.match(r'^(?:YBL|IBL|AXL|OKH|OKI|OKA|OKS|PTM|PYT|UPI|SBI|ICI|HDF|CIC)[a-zA-Z0-9]{15,32}$', node_clean)
            ):
                candidate_txid = node_clean
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            if 1450000000000 < node < 2100000000000 and not candidate_date:
                candidate_date = int(node)
            elif 10_000_000 <= node <= 500_000_000_000 and node % 100000 == 0 and candidate_amt is None:
                candidate_amt = float(node) / 1_000_000.0
            elif 100 <= node <= 10_000_000 and node % 100 == 0 and candidate_amt is None:
                candidate_amt = float(node) / 100.0

    walk(parsed_dict)

    final_amt = inr_submsg_amt if inr_submsg_amt is not None else candidate_amt
    if not candidate_cpty and not candidate_txid and inr_submsg_amt is None:
        return empty_out

    return {
        'Amount': final_amt,
        'Transaction_ID': candidate_txid,
        'Date': candidate_date,
        'Counterparty': candidate_cpty,
    }
