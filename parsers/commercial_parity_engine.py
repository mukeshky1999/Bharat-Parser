"""
Commercial Forensic Parity Engine: Recursive Multi-Layer Unpacker,
Universal 'App Genie' Table Classifier, and All-Category B-Tree / WAL Carver.
Cellebrite Physical Analyzer, Oxygen Forensic Detective, and Magnet AXIOM parity.
"""

from __future__ import annotations

import base64
import binascii
import json
import mmap
import os
import plistlib
import re
import struct
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union

import pandas as pd

from parsers.app_overrides import normalize_timestamp_value
from parsers.enterprise_1tb_chat_and_container_engine import (
    PA_CATEGORIZED_CHAT_COLUMNS,
    _empty_pa_row,
    format_timestamp_triplet,
)
from parsers.freelist_carver import (
    AMOUNT_VALID_RE,
    STANDARD_TX_COLUMNS,
    VPA_VALID_RE,
    decode_record_payload,
    read_varint,
)
from parsers.protobuf_decoder import decode_protobuf_stream

# Timezone
IST = timezone(timedelta(hours=5, minutes=30))

# Optional native accelerators
try:
    import lz4.block as lz4_block_mod
    import lz4.frame as lz4_frame_mod
    HAS_NATIVE_LZ4 = True
except ImportError:
    HAS_NATIVE_LZ4 = False

try:
    import zstandard as zstd_mod
    HAS_NATIVE_ZSTD = True
except ImportError:
    HAS_NATIVE_ZSTD = False

try:
    import msgpack as msgpack_mod
    HAS_NATIVE_MSGPACK = True
except ImportError:
    HAS_NATIVE_MSGPACK = False

try:
    import cbor2 as cbor2_mod
    HAS_NATIVE_CBOR = True
except ImportError:
    HAS_NATIVE_CBOR = False


# ==============================================================================
# SECTION 1: PURE-PYTHON FALLBACK DECOMPRESSORS & CONTAINER PARSERS
# ==============================================================================

def pure_python_decompress_lz4_block(src: bytes, uncompressed_size: int = -1) -> bytes:
    """
    Pure-Python LZ4 block decompressor supporting standard LZ4 block format.
    Operates with zero external C dependencies.
    """
    pos = 0
    src_len = len(src)
    dst = bytearray()

    while pos < src_len:
        token = src[pos]
        pos += 1
        lit_len = token >> 4

        # Extended literal length
        if lit_len == 15:
            while pos < src_len:
                s = src[pos]
                pos += 1
                lit_len += s
                if s != 255:
                    break

        if pos + lit_len > src_len:
            break

        dst.extend(src[pos : pos + lit_len])
        pos += lit_len

        # End of block reached after literals
        if pos >= src_len:
            break

        if pos + 2 > src_len:
            break

        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset == 0 or offset > len(dst):
            break

        match_len = token & 0x0F
        # Extended match length
        if match_len == 15:
            while pos < src_len:
                s = src[pos]
                pos += 1
                match_len += s
                if s != 255:
                    break

        match_len += 4
        match_pos = len(dst) - offset
        for _ in range(match_len):
            dst.append(dst[match_pos])
            match_pos += 1

        if uncompressed_size > 0 and len(dst) >= uncompressed_size:
            break

    return bytes(dst)


def pure_python_decompress_lz4_frame(src: bytes) -> bytes:
    """
    Pure-Python LZ4 frame decompressor supporting magic 0x184D2204.
    """
    if len(src) < 7:
        return b''
    # Check Magic Number 0x184D2204 (LE)
    magic = int.from_bytes(src[:4], 'little')
    if magic != 0x184D2204:
        return b''

    pos = 4
    flg = src[pos]
    pos += 2  # skip FLG and BD bytes

    # Content size present
    if (flg & 0x08) != 0:
        pos += 8
    # Dict ID present
    if (flg & 0x01) != 0:
        pos += 4

    pos += 1  # skip header checksum

    out = bytearray()
    src_len = len(src)

    while pos + 4 <= src_len:
        block_size = int.from_bytes(src[pos : pos + 4], 'little')
        pos += 4
        # EndMark is 0
        if block_size == 0:
            break

        is_uncompressed = (block_size & 0x80000000) != 0
        block_size = block_size & 0x7FFFFFFF

        if pos + block_size > src_len:
            break

        block_data = src[pos : pos + block_size]
        pos += block_size

        if is_uncompressed:
            out.extend(block_data)
        else:
            decomp = pure_python_decompress_lz4_block(block_data)
            out.extend(decomp)

        # Skip block checksum if flag bit 4 set
        if (flg & 0x10) != 0:
            pos += 4

    return bytes(out)


def pure_python_decode_msgpack(data: bytes) -> Tuple[Any, int]:
    """
    Pure-Python recursive MessagePack decoder for Android / Flutter fintech apps.
    Returns (decoded_object, bytes_consumed).
    """
    if not data:
        return None, 0

    first = data[0]

    # Positive fixint (0x00 - 0x7f)
    if first <= 0x7F:
        return first, 1

    # Fixmap (0x80 - 0x8f)
    if 0x80 <= first <= 0x8F:
        num_pairs = first & 0x0F
        offset = 1
        res_map: Dict[Any, Any] = {}
        for _ in range(num_pairs):
            k, k_len = pure_python_decode_msgpack(data[offset:])
            offset += k_len
            v, v_len = pure_python_decode_msgpack(data[offset:])
            offset += v_len
            res_map[str(k)] = v
        return res_map, offset

    # Fixarray (0x90 - 0x9f)
    if 0x90 <= first <= 0x9F:
        num_items = first & 0x0F
        offset = 1
        res_arr: List[Any] = []
        for _ in range(num_items):
            item, i_len = pure_python_decode_msgpack(data[offset:])
            offset += i_len
            res_arr.append(item)
        return res_arr, offset

    # Fixstr (0xa0 - 0xbf)
    if 0xA0 <= first <= 0xBF:
        str_len = first & 0x1F
        s = data[1 : 1 + str_len].decode('utf-8', errors='replace')
        return s, 1 + str_len

    # Nil
    if first == 0xC0:
        return None, 1
    # False / True
    if first == 0xC2:
        return False, 1
    if first == 0xC3:
        return True, 1

    # Bin 8 / 16 / 32
    if first == 0xC4 and len(data) >= 2:
        blen = data[1]
        return data[2 : 2 + blen], 2 + blen
    if first == 0xC5 and len(data) >= 3:
        blen = struct.unpack('>H', data[1:3])[0]
        return data[3 : 3 + blen], 3 + blen
    if first == 0xC6 and len(data) >= 5:
        blen = struct.unpack('>I', data[1:5])[0]
        return data[5 : 5 + blen], 5 + blen

    # Float 32 / Float 64
    if first == 0xCA and len(data) >= 5:
        return struct.unpack('>f', data[1:5])[0], 5
    if first == 0xCB and len(data) >= 9:
        return struct.unpack('>d', data[1:9])[0], 9

    # UInt 8 / 16 / 32 / 64
    if first == 0xCC and len(data) >= 2:
        return data[1], 2
    if first == 0xCD and len(data) >= 3:
        return struct.unpack('>H', data[1:3])[0], 3
    if first == 0xCE and len(data) >= 5:
        return struct.unpack('>I', data[1:5])[0], 5
    if first == 0xCF and len(data) >= 9:
        return struct.unpack('>Q', data[1:9])[0], 9

    # Int 8 / 16 / 32 / 64
    if first == 0xD0 and len(data) >= 2:
        return struct.unpack('>b', data[1:2])[0], 2
    if first == 0xD1 and len(data) >= 3:
        return struct.unpack('>h', data[1:3])[0], 3
    if first == 0xD2 and len(data) >= 5:
        return struct.unpack('>i', data[1:5])[0], 5
    if first == 0xD3 and len(data) >= 9:
        return struct.unpack('>q', data[1:9])[0], 9

    # Str 8 / 16 / 32
    if first == 0xD9 and len(data) >= 2:
        slen = data[1]
        return data[2 : 2 + slen].decode('utf-8', errors='replace'), 2 + slen
    if first == 0xDA and len(data) >= 3:
        slen = struct.unpack('>H', data[1:3])[0]
        return data[3 : 3 + slen].decode('utf-8', errors='replace'), 3 + slen
    if first == 0xDB and len(data) >= 5:
        slen = struct.unpack('>I', data[1:5])[0]
        return data[5 : 5 + slen].decode('utf-8', errors='replace'), 5 + slen

    # Array 16 / 32
    if first == 0xDC and len(data) >= 3:
        num = struct.unpack('>H', data[1:3])[0]
        offset = 3
        arr = []
        for _ in range(num):
            item, ilen = pure_python_decode_msgpack(data[offset:])
            offset += ilen
            arr.append(item)
        return arr, offset

    # Map 16 / 32
    if first == 0xDE and len(data) >= 3:
        num = struct.unpack('>H', data[1:3])[0]
        offset = 3
        m = {}
        for _ in range(num):
            k, klen = pure_python_decode_msgpack(data[offset:])
            offset += klen
            v, vlen = pure_python_decode_msgpack(data[offset:])
            offset += vlen
            m[str(k)] = v
        return m, offset

    # Negative fixint (0xe0 - 0xff)
    if first >= 0xE0:
        return struct.unpack('>b', bytes([first]))[0], 1

    return None, 1


def pure_python_decode_cbor(data: bytes) -> Tuple[Any, int]:
    """
    Pure-Python recursive CBOR (RFC 7049) decoder for React-Native fintech apps.
    Returns (decoded_object, bytes_consumed).
    """
    if not data:
        return None, 0

    first = data[0]
    major = first >> 5
    info = first & 0x1F

    offset = 1
    val = 0

    if info < 24:
        val = info
    elif info == 24:
        if len(data) < 2:
            return None, len(data)
        val = data[1]
        offset = 2
    elif info == 25:
        if len(data) < 3:
            return None, len(data)
        val = struct.unpack('>H', data[1:3])[0]
        offset = 3
    elif info == 26:
        if len(data) < 5:
            return None, len(data)
        val = struct.unpack('>I', data[1:5])[0]
        offset = 5
    elif info == 27:
        if len(data) < 9:
            return None, len(data)
        val = struct.unpack('>Q', data[1:9])[0]
        offset = 9
    elif info == 31:
        # Indefinite length
        val = -1
    else:
        return None, 1

    # Major 0: Unsigned int
    if major == 0:
        return val, offset
    # Major 1: Negative int
    if major == 1:
        return -1 - val, offset
    # Major 2: Byte string
    if major == 2:
        if val >= 0 and offset + val <= len(data):
            return data[offset : offset + val], offset + val
        return b'', offset
    # Major 3: UTF-8 text string
    if major == 3:
        if val >= 0 and offset + val <= len(data):
            return data[offset : offset + val].decode('utf-8', errors='replace'), offset + val
        return '', offset
    # Major 4: Array
    if major == 4:
        arr: List[Any] = []
        if val >= 0:
            for _ in range(val):
                item, ilen = pure_python_decode_cbor(data[offset:])
                offset += ilen
                arr.append(item)
        return arr, offset
    # Major 5: Map
    if major == 5:
        c_map: Dict[Any, Any] = {}
        if val >= 0:
            for _ in range(val):
                k, klen = pure_python_decode_cbor(data[offset:])
                offset += klen
                v, vlen = pure_python_decode_cbor(data[offset:])
                offset += vlen
                c_map[str(k)] = v
        return c_map, offset
    # Major 6: Tagged value
    if major == 6:
        item, ilen = pure_python_decode_cbor(data[offset:])
        return item, offset + ilen
    # Major 7: Primitives
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        if info == 26 and len(data) >= 5:
            return struct.unpack('>f', data[1:5])[0], 5
        if info == 27 and len(data) >= 9:
            return struct.unpack('>d', data[1:9])[0], 9

    return None, offset


def resolve_nskeyedarchiver_tree(parsed: Dict[str, Any]) -> Any:
    """
    Recursively resolves Apple `NSKeyedArchiver` object references ($objects & $top)
    into a clean, human-readable Python dict/list hierarchy without integer UID indices.
    """
    objects = parsed.get('$objects', [])
    top = parsed.get('$top', {})
    if not isinstance(objects, list) or not isinstance(top, dict):
        return parsed

    visited_indices: Set[int] = set()

    def _resolve(node: Any) -> Any:
        if isinstance(node, plistlib.UID):
            idx = node.data
            if idx == 0 or idx >= len(objects):
                return None
            if idx in visited_indices:
                return f"<Circular_Ref_UID_{idx}>"
            visited_indices.add(idx)
            res = _resolve(objects[idx])
            visited_indices.remove(idx)
            return res

        if isinstance(node, dict):
            # Inspect $class metadata
            cls_name = ''
            if '$class' in node and isinstance(node['$class'], plistlib.UID):
                c_idx = node['$class'].data
                if c_idx < len(objects) and isinstance(objects[c_idx], dict):
                    cls_name = str(objects[c_idx].get('$classname') or '')

            # 1. NSDictionary / NSMutableDictionary
            if 'NSDictionary' in cls_name or ('NS.keys' in node and 'NS.objects' in node):
                keys = [_resolve(k) for k in node.get('NS.keys', [])]
                vals = [_resolve(v) for v in node.get('NS.objects', [])]
                return {str(k): v for k, v in zip(keys, vals) if k is not None}

            # 2. NSArray / NSMutableArray / NSSet
            if any(k in cls_name for k in ('NSArray', 'NSSet', 'NSMutableArray')) or 'NS.objects' in node:
                return [_resolve(item) for item in node.get('NS.objects', [])]

            # 3. NSDate
            if 'NSDate' in cls_name or 'NS.time' in node:
                cocoa_time = node.get('NS.time')
                if isinstance(cocoa_time, (int, float)):
                    # Cocoa epoch 2001-01-01
                    unix_ts = cocoa_time + 978307200
                    try:
                        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    except Exception:
                        return cocoa_time
                return cocoa_time

            # 4. NSString
            if 'NSString' in cls_name or 'NS.string' in node:
                return str(node.get('NS.string', ''))

            # 5. NSData
            if 'NSData' in cls_name or 'NS.data' in node:
                return node.get('NS.data')

            # Generic dictionary
            out_d: Dict[str, Any] = {}
            for k, v in node.items():
                if not k.startswith('$'):
                    out_d[k] = _resolve(v)
            return out_d if out_d else {k: str(v) for k, v in node.items()}

        if isinstance(node, list):
            return [_resolve(item) for item in node]

        return node

    root_node = top.get('root')
    if root_node is None and top:
        root_node = next(iter(top.values()))

    return _resolve(root_node)


# ==============================================================================
# SECTION 2: MODULE 1 — RECURSIVE MULTI-LAYER FORENSIC BINARY UNPACKER
# ==============================================================================

def _extract_forensic_entities_from_text(text: str) -> Dict[str, List[Any]]:
    """
    Scans plain text for VPAs, Indian mobile numbers, UTRs, URLs, and coordinates.
    """
    res: Dict[str, List[Any]] = {
        'vpas': [],
        'phones': [],
        'utrs': [],
        'urls': [],
        'timestamps': [],
        'coordinates': [],
    }
    if not text:
        return res

    # 1. Indian VPAs
    for v in VPA_VALID_RE.finditer(text):
        res['vpas'].append(v.group(0).lower())

    # 2. Indian Phone Numbers (+91 or 10-digit mobile starting 6-9)
    for p in re.finditer(r'(?:\+91[\-\s]?)?[6-9]\d{9}\b', text):
        res['phones'].append(p.group(0))

    # 3. 12-digit UTRs
    for u in re.finditer(r'\b[0-9]{12}\b', text):
        res['utrs'].append(u.group(0))

    # 4. URLs & Payment URIs
    for url in re.finditer(r'(?:https?://|upi://pay\?)[^\s"\'<>]+', text):
        res['urls'].append(url.group(0))

    # 5. Geo Coordinates
    for geo in re.finditer(r'([-+]?\d{1,2}\.\d{4,8})\s*,\s*([-+]?\d{1,3}\.\d{4,8})', text):
        lat = float(geo.group(1))
        lon = float(geo.group(2))
        if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
            res['coordinates'].append(f"{lat}, {lon}")

    # Deduplicate
    for k in res:
        res[k] = list(dict.fromkeys(res[k]))
    return res


def recursive_forensic_unpack(
    raw_bytes: Union[bytes, bytearray, memoryview, str],
    max_depth: int = 5,
) -> Dict[str, Any]:
    """
    Automatically detects and unwraps nested encodings in any order:
    1. Compression: zlib, gzip, deflate, LZ4 (pure-Python + native), Zstandard (zstd).
    2. Plist: Apple NSKeyedArchiver binary plists resolved into clean Python dicts.
    3. Serialization: JSON, Protobuf, CBOR, and MessagePack.
    4. Text Encodings: Base64, Base64URL, and Hex strings.
    5. Entity extraction: VPAs, phone numbers, UTRs, URLs, and coordinates.
    """
    if raw_bytes is None:
        return {'unpacked': None, 'layers': [], 'content_type': 'none', 'raw_text': '', 'entities': {}}

    if isinstance(raw_bytes, str):
        data = raw_bytes.encode('utf-8')
    else:
        data = bytes(raw_bytes)

    if len(data) == 0:
        return {'unpacked': None, 'layers': [], 'content_type': 'empty', 'raw_text': '', 'entities': {}}

    layers: List[str] = []
    current: Any = data
    primary_type = 'binary'

    for _ in range(max_depth):
        if not isinstance(current, (bytes, bytearray)):
            break

        cur_bytes = bytes(current)
        progress = False

        # ---------------- 1. COMPRESSION: GZIP / ZLIB / DEFLATE ----------------
        if len(cur_bytes) >= 2:
            # Gzip magic (0x1F, 0x8B)
            if cur_bytes[:2] == b'\x1f\x8b':
                try:
                    current = zlib.decompress(cur_bytes, 16 + zlib.MAX_WBITS)
                    layers.append('gzip')
                    progress = True
                    continue
                except Exception:
                    pass

            # Zlib header (0x78)
            if cur_bytes[0] == 0x78:
                try:
                    current = zlib.decompress(cur_bytes, zlib.MAX_WBITS)
                    layers.append('zlib')
                    progress = True
                    continue
                except Exception:
                    pass

            # Raw deflate
            try:
                current = zlib.decompress(cur_bytes, -zlib.MAX_WBITS)
                layers.append('deflate')
                progress = True
                continue
            except Exception:
                pass

        # ---------------- 2. COMPRESSION: LZ4 FRAME & BLOCK ----------------
        if len(cur_bytes) >= 4:
            # LZ4 Frame magic 0x184D2204
            if cur_bytes[:4] == b'\x04\x22\x4D\x18':
                decomp = None
                if HAS_NATIVE_LZ4:
                    try:
                        decomp = lz4_frame_mod.decompress(cur_bytes)
                    except Exception:
                        pass
                if not decomp:
                    try:
                        decomp = pure_python_decompress_lz4_frame(cur_bytes)
                    except Exception:
                        pass
                if decomp and len(decomp) > 0:
                    current = decomp
                    layers.append('lz4_frame')
                    progress = True
                    continue

        # ---------------- 3. COMPRESSION: ZSTANDARD (ZSTD) ----------------
        if len(cur_bytes) >= 4 and cur_bytes[:4] == b'\x28\xb5\x2f\xfd':
            if HAS_NATIVE_ZSTD:
                try:
                    dctx = zstd_mod.ZstdDecompressor()
                    current = dctx.decompress(cur_bytes)
                    layers.append('zstd')
                    progress = True
                    continue
                except Exception:
                    pass

        # ---------------- 4. APPLE NSKEYEDARCHIVER BINARY PLIST ----------------
        if cur_bytes.startswith(b'bplist00'):
            try:
                parsed_plist = plistlib.loads(cur_bytes)
                if isinstance(parsed_plist, dict) and ('$archiver' in parsed_plist or '$objects' in parsed_plist):
                    resolved = resolve_nskeyedarchiver_tree(parsed_plist)
                    current = resolved
                    layers.append('nskeyedarchiver_plist')
                    primary_type = 'plist'
                    progress = True
                    break
                else:
                    current = parsed_plist
                    layers.append('bplist')
                    primary_type = 'plist'
                    progress = True
                    break
            except Exception:
                pass

        # ---------------- 5. JSON PAYLOAD ----------------
        trimmed = cur_bytes.strip()
        if (trimmed.startswith(b'{') and trimmed.endswith(b'}')) or (trimmed.startswith(b'[') and trimmed.endswith(b']')):
            try:
                j_obj = json.loads(cur_bytes.decode('utf-8', errors='replace'))
                current = j_obj
                layers.append('json')
                primary_type = 'json'
                progress = True
                break
            except Exception:
                pass

        # ---------------- 6. BASE64 / BASE64URL STRING ----------------
        if len(cur_bytes) >= 16 and re.match(rb'^[A-Za-z0-9+/=_-]{16,}$', trimmed):
            try:
                b64_norm = trimmed.replace(b'-', b'+').replace(b'_', b'/')
                pad = len(b64_norm) % 4
                if pad:
                    b64_norm += b'=' * (4 - pad)
                decoded_b64 = base64.b64decode(b64_norm)
                if len(decoded_b64) >= 4 and decoded_b64 != cur_bytes:
                    current = decoded_b64
                    layers.append('base64')
                    progress = True
                    continue
            except Exception:
                pass

        # ---------------- 7. HEX ENCODED STRING ----------------
        if len(cur_bytes) >= 16 and len(cur_bytes) % 2 == 0 and re.match(rb'^[0-9a-fA-F]{16,}$', trimmed):
            try:
                decoded_hex = binascii.unhexlify(trimmed)
                if len(decoded_hex) >= 8 and decoded_hex != cur_bytes:
                    current = decoded_hex
                    layers.append('hex')
                    progress = True
                    continue
            except Exception:
                pass

        # ---------------- 8. PROTOBUF WIRE PAYLOAD ----------------
        pb = decode_protobuf_stream(cur_bytes, max_depth=4)
        if pb and len(pb) >= 1:
            current = pb
            layers.append('protobuf')
            primary_type = 'protobuf'
            progress = True
            break

        # ---------------- 9. CBOR PAYLOAD ----------------
        cbor_res = None
        if HAS_NATIVE_CBOR:
            try:
                cbor_res = cbor2_mod.loads(cur_bytes)
            except Exception:
                pass
        if cbor_res is None:
            try:
                cbor_candidate, _ = pure_python_decode_cbor(cur_bytes)
                if isinstance(cbor_candidate, (dict, list)) and len(cbor_candidate) > 0:
                    cbor_res = cbor_candidate
            except Exception:
                pass
        if cbor_res is not None:
            current = cbor_res
            layers.append('cbor')
            primary_type = 'cbor'
            progress = True
            break

        # ---------------- 10. MESSAGEPACK PAYLOAD ----------------
        msgpack_res = None
        if HAS_NATIVE_MSGPACK:
            try:
                msgpack_res = msgpack_mod.unpackb(cur_bytes, raw=False)
            except Exception:
                pass
        if msgpack_res is None:
            try:
                mp_candidate, _ = pure_python_decode_msgpack(cur_bytes)
                if isinstance(mp_candidate, (dict, list)) and len(mp_candidate) > 0:
                    msgpack_res = mp_candidate
            except Exception:
                pass
        if msgpack_res is not None:
            current = msgpack_res
            layers.append('msgpack')
            primary_type = 'msgpack'
            progress = True
            break

        # ---------------- 11. UTF-8 TEXT CHECK ----------------
        try:
            txt = cur_bytes.decode('utf-8')
            if txt.strip() and any(c.isalnum() for c in txt):
                current = txt
                primary_type = 'text'
                layers.append('utf8')
                break
        except Exception:
            pass

        if not progress:
            break

    # Format extracted string & harvest entities
    raw_text = ''
    if isinstance(current, (dict, list)):
        try:
            raw_text = json.dumps(current, default=str)
        except Exception:
            raw_text = str(current)
    elif isinstance(current, str):
        raw_text = current
    elif isinstance(current, (bytes, bytearray)):
        raw_text = bytes(current).decode('utf-8', errors='replace')

    entities = _extract_forensic_entities_from_text(raw_text)

    return {
        'unpacked': current,
        'layers': layers,
        'content_type': primary_type,
        'raw_text': raw_text[:50000],
        'entities': entities,
    }


# ==============================================================================
# SECTION 3: MODULE 2 — UNIVERSAL "APP GENIE" HEURISTIC TABLE CLASSIFIER
# ==============================================================================

# Model definitions matching Cellebrite Physical Analyzer
MODEL_CHAT_MESSAGE = 'MODEL_CHAT_MESSAGE'
MODEL_CALL_LOG = 'MODEL_CALL_LOG'
MODEL_LOCATION_PIN = 'MODEL_LOCATION_PIN'
MODEL_USER_ACCOUNT_OR_CONTACT = 'MODEL_USER_ACCOUNT_OR_CONTACT'
MODEL_WEB_OR_SEARCH_HISTORY = 'MODEL_WEB_OR_SEARCH_HISTORY'
MODEL_FINANCIAL_TRANSACTION = 'MODEL_FINANCIAL_TRANSACTION'
MODEL_UNKNOWN = 'MODEL_UNKNOWN'


def _find_best_matching_column(
    col_names: List[str], target_patterns: List[str]
) -> Optional[str]:
    """
    Returns the first column name that matches one of target regex patterns.
    """
    for pat in target_patterns:
        regex = re.compile(pat, re.IGNORECASE)
        for c in col_names:
            if regex.search(c):
                return c
    return None


def app_genie_classify_table(
    df: pd.DataFrame, table_name: str, db_path: str
) -> Dict[str, Any]:
    """
    Inspects any unknown SQLite table from any unlisted application and classifies
    it into one of 6 Cellebrite Physical Analyzer Models based on column names
    and cell content distributions.
    """
    empty_result = {
        'model': MODEL_UNKNOWN,
        'confidence': 0.0,
        'table_name': table_name,
        'db_path': db_path,
        'mapped_fields': {},
        'extracted_records': pd.DataFrame(),
    }

    if df is None or df.empty or len(df.columns) == 0:
        return empty_result

    cols = list(df.columns)
    col_lows = [c.lower() for c in cols]
    col_map = {c.lower(): c for c in cols}
    num_rows = len(df)
    sample_df = df.head(min(num_rows, 50))

    # Candidate Column Finders
    ts_col = _find_best_matching_column(
        cols, [r'(?:timestamp|created_at|created_time|date_sent|sent_at|time_ms|post_time|datetime|epoch|date)']
    )
    body_col = _find_best_matching_column(
        cols, [r'(?:message_body|message_text|text_data|chat_text|content|body|message|text|payload|data)']
    )
    sender_col = _find_best_matching_column(
        cols, [r'(?:sender_jid|sender_id|from_id|caller|sender|address|peer|author)']
    )
    from_me_col = _find_best_matching_column(
        cols, [r'(?:from_me|is_outgoing|outbox|out|direction|is_sent)']
    )
    duration_col = _find_best_matching_column(
        cols, [r'(?:call_duration|duration_sec|duration|length|call_time)']
    )
    lat_col = _find_best_matching_column(
        cols, [r'(?:latitude|geo_lat|loc_lat|coord_y|^lat$)']
    )
    lon_col = _find_best_matching_column(
        cols, [r'(?:longitude|geo_lon|loc_lon|coord_x|^lon$|^lng$)']
    )
    name_col = _find_best_matching_column(
        cols, [r'(?:display_name|contact_name|person_name|full_name|username|first_name|profile_name|^name$)']
    )
    phone_col = _find_best_matching_column(
        cols, [r'(?:phone_number|mobile_no|phone|msisdn|mobile|e164)']
    )
    url_col = _find_best_matching_column(
        cols, [r'(?:url|link|href|search_query|query|keyword|web_address)']
    )
    amount_col = _find_best_matching_column(
        cols, [r'(?:amount|trans_amount|txn_amt|price|value_paise|balance)']
    )
    vpa_col = _find_best_matching_column(
        cols, [r'(?:vpa|upi_id|payee_vpa|payer_vpa|counterparty|handle)']
    )

    scores: Dict[str, float] = {
        MODEL_CHAT_MESSAGE: 0.0,
        MODEL_CALL_LOG: 0.0,
        MODEL_LOCATION_PIN: 0.0,
        MODEL_USER_ACCOUNT_OR_CONTACT: 0.0,
        MODEL_WEB_OR_SEARCH_HISTORY: 0.0,
        MODEL_FINANCIAL_TRANSACTION: 0.0,
    }

    # 1. EVALUATE MODEL_FINANCIAL_TRANSACTION
    if amount_col and (vpa_col or sender_col):
        scores[MODEL_FINANCIAL_TRANSACTION] += 50.0
        # Check cell values for numeric amounts or currency symbols
        sample_vals = sample_df[amount_col].dropna()
        if any(isinstance(v, (int, float)) or (isinstance(v, str) and re.search(r'\d', v)) for v in sample_vals):
            scores[MODEL_FINANCIAL_TRANSACTION] += 30.0
        if any(k in table_name.lower() for k in ('trans', 'payment', 'passbook', 'ledger', 'order')):
            scores[MODEL_FINANCIAL_TRANSACTION] += 20.0

    # 2. EVALUATE MODEL_LOCATION_PIN
    if lat_col and lon_col:
        scores[MODEL_LOCATION_PIN] += 50.0
        try:
            sample_lats = pd.to_numeric(sample_df[lat_col], errors='coerce').dropna()
            sample_lons = pd.to_numeric(sample_df[lon_col], errors='coerce').dropna()
            if not sample_lats.empty and not sample_lons.empty:
                if (sample_lats.between(-90, 90).all()) and (sample_lons.between(-180, 180).all()):
                    scores[MODEL_LOCATION_PIN] += 40.0
        except Exception:
            pass

    # 3. EVALUATE MODEL_CALL_LOG
    if duration_col and (sender_col or phone_col or ts_col):
        scores[MODEL_CALL_LOG] += 50.0
        try:
            sample_dur = pd.to_numeric(sample_df[duration_col], errors='coerce').dropna()
            if not sample_dur.empty and (sample_dur.between(0, 86400).all()):
                scores[MODEL_CALL_LOG] += 35.0
        except Exception:
            pass
        if any(k in table_name.lower() for k in ('call', 'voip', 'telephony', 'cdr')):
            scores[MODEL_CALL_LOG] += 15.0

    # 4. EVALUATE MODEL_CHAT_MESSAGE
    if body_col and (ts_col or sender_col or from_me_col):
        scores[MODEL_CHAT_MESSAGE] += 45.0
        # Check text distribution
        sample_texts = sample_df[body_col].dropna().astype(str)
        if any(len(s.strip()) > 1 for s in sample_texts):
            scores[MODEL_CHAT_MESSAGE] += 35.0
        if any(k in table_name.lower() for k in ('msg', 'message', 'chat', 'conversation', 'thread', 'timeline')):
            scores[MODEL_CHAT_MESSAGE] += 20.0

    # 5. EVALUATE MODEL_USER_ACCOUNT_OR_CONTACT
    if name_col and (phone_col or sender_col or 'email' in col_lows or 'avatar' in col_lows):
        scores[MODEL_USER_ACCOUNT_OR_CONTACT] += 50.0
        if any(k in table_name.lower() for k in ('contact', 'friend', 'user', 'profile', 'person', 'recipient')):
            scores[MODEL_USER_ACCOUNT_OR_CONTACT] += 30.0

    # 6. EVALUATE MODEL_WEB_OR_SEARCH_HISTORY
    if url_col:
        scores[MODEL_WEB_OR_SEARCH_HISTORY] += 50.0
        sample_urls = sample_df[url_col].dropna().astype(str)
        if any(s.startswith(('http://', 'https://', 'upi://', 'www.')) for s in sample_urls):
            scores[MODEL_WEB_OR_SEARCH_HISTORY] += 40.0

    best_model, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score < 40.0:
        return empty_result

    confidence = min(1.0, best_score / 100.0)
    mapped_fields: Dict[str, str] = {}
    extracted_df = pd.DataFrame()

    bname = os.path.basename(db_path)

    # ---------------- BUILD MODEL_CHAT_MESSAGE ----------------
    if best_model == MODEL_CHAT_MESSAGE:
        mapped_fields = {
            'body_col': body_col or '',
            'timestamp_col': ts_col or '',
            'sender_col': sender_col or '',
            'direction_col': from_me_col or '',
        }
        rows: List[Dict[str, Any]] = []
        for idx, r in df.iterrows():
            row_id = r.name if hasattr(r, 'name') else idx
            raw_body = str(r.get(body_col) or '') if body_col else ''
            ts_val = r.get(ts_col) if ts_col else None
            sender_val = str(r.get(sender_col) or '') if sender_col else ''
            is_out = False
            if from_me_col:
                dir_raw = r.get(from_me_col)
                is_out = bool(dir_raw in (1, '1', True, 'true', 'OUTGOING', 'outgoing', 'out'))

            row = _empty_pa_row('Generic App Genie', db_path, table_name, row_id, f"RowID={row_id}")
            row['Message_Body'] = raw_body
            row['Direction'] = 'Outgoing' if is_out else 'Incoming'
            row['Sender_Identifier'] = sender_val or ('Owner' if is_out else 'Unknown')
            row['Thread_Title'] = sender_val or f"Chat {table_name}"
            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='auto')
            row['Raw_Timestamp_Value'] = raw_ts
            row['Timestamp_UTC'] = utc_ts
            row['Timestamp_IST'] = ist_ts
            rows.append(row)
        extracted_df = pd.DataFrame(rows, columns=PA_CATEGORIZED_CHAT_COLUMNS)

    # ---------------- BUILD MODEL_CALL_LOG ----------------
    elif best_model == MODEL_CALL_LOG:
        mapped_fields = {
            'duration_col': duration_col or '',
            'timestamp_col': ts_col or '',
            'peer_col': sender_col or phone_col or '',
        }
        rows = []
        for idx, r in df.iterrows():
            dur = int(r.get(duration_col) or 0) if duration_col else 0
            ts_val = r.get(ts_col) if ts_col else None
            peer = str(r.get(sender_col) or r.get(phone_col) or '')
            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='auto')
            rows.append({
                'Timestamp': utc_ts,
                'Timestamp_IST': ist_ts,
                'Peer_Number': peer,
                'Direction': 'Outgoing' if (from_me_col and r.get(from_me_col) in (1, True, 'out')) else 'Incoming',
                'Duration_Sec': dur,
                'Call_Type': 'VoIP Call' if any(k in table_name.lower() for k in ('voip', 'app')) else 'Cellular Call',
                'Call_Result': 'Connected Call' if dur > 0 else 'Missed Call',
                'Forensic_Provenance': f"{bname} :: {table_name} :: Row={idx} :: AppGenie",
            })
        extracted_df = pd.DataFrame(rows)

    # ---------------- BUILD MODEL_LOCATION_PIN ----------------
    elif best_model == MODEL_LOCATION_PIN:
        mapped_fields = {
            'lat_col': lat_col or '',
            'lon_col': lon_col or '',
            'timestamp_col': ts_col or '',
        }
        rows = []
        for idx, r in df.iterrows():
            lat = float(r.get(lat_col) or 0.0) if lat_col else 0.0
            lon = float(r.get(lon_col) or 0.0) if lon_col else 0.0
            ts_val = r.get(ts_col) if ts_col else None
            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='auto')
            rows.append({
                'Timestamp': utc_ts,
                'Timestamp_IST': ist_ts,
                'Latitude': lat,
                'Longitude': lon,
                'Geo_Coordinates': f"{lat}, {lon}",
                'Place_Name': str(r.get('name') or r.get('place') or r.get('address') or ''),
                'Forensic_Provenance': f"{bname} :: {table_name} :: Row={idx} :: AppGenie",
            })
        extracted_df = pd.DataFrame(rows)

    # ---------------- BUILD MODEL_USER_ACCOUNT_OR_CONTACT ----------------
    elif best_model == MODEL_USER_ACCOUNT_OR_CONTACT:
        mapped_fields = {
            'name_col': name_col or '',
            'phone_col': phone_col or '',
            'id_col': sender_col or '',
        }
        rows = []
        for idx, r in df.iterrows():
            name = str(r.get(name_col) or '').strip()
            phone = str(r.get(phone_col) or '').strip()
            uid = str(r.get(sender_col) or '').strip()
            rows.append({
                'Contact_Name': name or phone or uid,
                'Identifier': uid or phone,
                'Phone': phone,
                'Email': str(r.get('email') or '').strip(),
                'Bio_Note': str(r.get('bio') or r.get('status') or '').strip(),
                'Application': bname.split('.')[0].title(),
                'Source_Table': table_name,
                'Forensic_Provenance': f"{bname} :: {table_name} :: Row={idx} :: AppGenie",
            })
        extracted_df = pd.DataFrame(rows)

    # ---------------- BUILD MODEL_WEB_OR_SEARCH_HISTORY ----------------
    elif best_model == MODEL_WEB_OR_SEARCH_HISTORY:
        mapped_fields = {
            'url_col': url_col or '',
            'timestamp_col': ts_col or '',
        }
        rows = []
        for idx, r in df.iterrows():
            url = str(r.get(url_col) or '').strip()
            ts_val = r.get(ts_col) if ts_col else None
            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='auto')
            rows.append({
                'Timestamp': utc_ts,
                'Timestamp_IST': ist_ts,
                'URL_or_Query': url,
                'Page_Title': str(r.get('title') or '').strip(),
                'Visit_Count': int(r.get('visits') or r.get('count') or 1),
                'Forensic_Provenance': f"{bname} :: {table_name} :: Row={idx} :: AppGenie",
            })
        extracted_df = pd.DataFrame(rows)

    # ---------------- BUILD MODEL_FINANCIAL_TRANSACTION ----------------
    elif best_model == MODEL_FINANCIAL_TRANSACTION:
        mapped_fields = {
            'amount_col': amount_col or '',
            'vpa_col': vpa_col or sender_col or '',
            'timestamp_col': ts_col or '',
        }
        rows = []
        for idx, r in df.iterrows():
            amt = float(r.get(amount_col) or 0.0) if amount_col else 0.0
            vpa = str(r.get(vpa_col) or r.get(sender_col) or '')
            ts_val = r.get(ts_col) if ts_col else None
            raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_val, epoch_hint='auto')
            rows.append({
                'Date': ist_ts or utc_ts,
                'Transaction_ID': str(r.get('txid') or r.get('utr') or f"GEN_{idx}"),
                'Amount': amt,
                'Counterparty': vpa or 'AppGenie Counterparty',
                'Status': 'COMPLETED',
                'Type': 'TRANSFER',
            })
        extracted_df = pd.DataFrame(rows, columns=STANDARD_TX_COLUMNS)

    return {
        'model': best_model,
        'confidence': confidence,
        'table_name': table_name,
        'db_path': db_path,
        'mapped_fields': mapped_fields,
        'extracted_records': extracted_df,
    }


# ==============================================================================
# SECTION 4: MODULE 3 — UNIVERSAL B-TREE FREELIST, SLACK & WAL CARVER
# ==============================================================================

def _classify_and_record(
    rec_vals: List[Any],
    global_offset: int,
    page_num: int,
    source_tag: str,
    db_path: str,
    tx_list: List[Dict[str, Any]],
    chat_list: List[Dict[str, Any]],
    call_list: List[Dict[str, Any]],
    loc_list: List[Dict[str, Any]],
) -> bool:
    """
    Classifies a decoded SQLite record payload into one of 4 forensic models:
    Transaction, Call Log, Location Pin, or Chat Message.
    Returns True if classified and appended to the respective list.
    """
    if not rec_vals or len(rec_vals) < 2:
        return False

    bname = os.path.basename(db_path)
    hex_off = f"0x{global_offset:08X}"
    prov_str = f"{bname} :: Page_{page_num} :: Offset={hex_off} :: State={source_tag}"

    vpa_found = None
    text_found = None
    ts_found = None
    amt_found = None
    phone_found = None
    duration_found = None
    coords_found = None

    for item in rec_vals:
        if isinstance(item, (int, float)):
            num = float(item)
            # Timestamp check (seconds, milliseconds, or cocoa)
            if 1420070400 <= num <= 2051222400 and ts_found is None:
                ts_found = num  # Unix seconds
            elif 1420070400000 <= num <= 2051222400000 and ts_found is None:
                ts_found = num  # Unix milliseconds
            elif 441763200 <= num <= 1072915200 and ts_found is None:
                ts_found = num + 978307200  # Cocoa seconds

            # Call duration (1 to 86400 seconds)
            if 0 < item <= 86400 and duration_found is None and item != ts_found:
                duration_found = int(item)

            # Monetary amount
            if 1.0 <= num <= 10000000.0 and amt_found is None and item != ts_found and item != duration_found:
                amt_found = num

            # Coordinates (latitude / longitude)
            if (-90.0 <= num <= 90.0) and int(num) != num:
                if coords_found is None:
                    coords_found = [num]
                elif len(coords_found) == 1 and (-180.0 <= num <= 180.0):
                    coords_found.append(num)

        elif isinstance(item, str):
            s_clean = item.strip()
            if '@' in s_clean:
                m_vpa = VPA_VALID_RE.search(s_clean)
                if m_vpa:
                    vpa_found = m_vpa.group(0).lower()
            if re.search(r'(?:\+91[\-\s]?)?[6-9]\d{9}\b', s_clean) and phone_found is None:
                phone_found = s_clean
            elif len(s_clean) >= 3 and text_found is None and not s_clean.startswith(('SQLite', 'PRAGMA', 'TABLE', 'CREATE')):
                text_found = s_clean

    # 1. TRANSACTION
    if vpa_found and (amt_found is not None or ts_found is not None):
        tx_list.append({
            'Date': str(ts_found or ''),
            'Transaction_ID': f"CARVED_PG{page_num}_{hex_off}",
            'Amount': amt_found or 0.0,
            'Counterparty': vpa_found,
            'Status': 'CARVED',
            'Type': 'TRANSFER',
            'Page_Number': page_num,
            'Byte_Offset': hex_off,
            'Recovery_Method': source_tag,
        })
        return True

    # 2. CALL LOG
    if phone_found and duration_found is not None and ts_found is not None:
        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_found, epoch_hint='auto')
        call_list.append({
            'Timestamp': utc_ts,
            'Timestamp_IST': ist_ts,
            'Peer': phone_found,
            'Duration_Sec': duration_found,
            'Direction': 'Incoming',
            'Forensic_Provenance': prov_str,
        })
        return True

    # 3. LOCATION PIN
    if coords_found and len(coords_found) == 2:
        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_found, epoch_hint='auto')
        loc_list.append({
            'Latitude': coords_found[0],
            'Longitude': coords_found[1],
            'Timestamp': utc_ts,
            'Timestamp_IST': ist_ts,
            'Geo_Coordinates': f"{coords_found[0]}, {coords_found[1]}",
            'Forensic_Provenance': prov_str,
        })
        return True

    # 4. CHAT MESSAGE
    if text_found and (ts_found is not None or phone_found is not None):
        row = _empty_pa_row('Carved Artifact', db_path, 'UnallocatedSpace', f"PG{page_num}_{hex_off}", hex_off, source_tag)
        row['Message_Body'] = text_found
        row['Sender_Identifier'] = phone_found or 'Carved Identifier'
        row['Thread_Title'] = phone_found or f"Carved Thread ({hex_off})"
        raw_ts, utc_ts, ist_ts = format_timestamp_triplet(ts_found, epoch_hint='auto')
        row['Raw_Timestamp_Value'] = raw_ts
        row['Timestamp_UTC'] = utc_ts
        row['Timestamp_IST'] = ist_ts
        chat_list.append(row)
        return True

    return False


def _scan_unallocated_slice_for_records(
    raw_slice: bytes,
    page_num: int,
    base_offset: int,
    source_tag: str,
    db_path: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Scans a raw unallocated slice of bytes for valid SQLite record payloads
    and classifies them into transactions, chats, calls, and locations.
    """
    tx_list: List[Dict[str, Any]] = []
    chat_list: List[Dict[str, Any]] = []
    call_list: List[Dict[str, Any]] = []
    loc_list: List[Dict[str, Any]] = []

    slice_len = len(raw_slice)
    if slice_len < 4:
        return tx_list, chat_list, call_list, loc_list

    pos = 0
    while pos < slice_len - 3:
        classified = False

        # Attempt 1: Table Leaf Cell format: [p_size (varint), rowid (varint), payload (starts with hdr_len)]
        try:
            p_size, off1 = read_varint(raw_slice, pos)
            if 3 <= p_size <= 4096 and off1 < slice_len:
                rowid, off2 = read_varint(raw_slice, off1)
                if off2 + 2 <= slice_len:
                    cell_payload = raw_slice[off2 : min(off2 + p_size, slice_len)]
                    rec_vals = decode_record_payload(cell_payload)
                    if rec_vals:
                        classified = _classify_and_record(
                            rec_vals, base_offset + off2, page_num, source_tag, db_path,
                            tx_list, chat_list, call_list, loc_list
                        )
                        if classified:
                            pos = max(pos + 1, off2 + p_size)
                            continue
        except Exception:
            pass

        # Attempt 2: Raw Record Format: [hdr_len (varint), serial_types..., values...]
        try:
            hdr_len, _ = read_varint(raw_slice, pos)
            if 2 <= hdr_len <= min(250, slice_len - pos):
                rec_payload = raw_slice[pos : min(pos + 4096, slice_len)]
                rec_vals = decode_record_payload(rec_payload)
                if rec_vals:
                    classified = _classify_and_record(
                        rec_vals, base_offset + pos, page_num, source_tag, db_path,
                        tx_list, chat_list, call_list, loc_list
                    )
                    if classified:
                        pos += max(hdr_len, 4)
                        continue
        except Exception:
            pass

        pos += 1

    return tx_list, chat_list, call_list, loc_list


def carve_deleted_all_categories_mmap(db_path: str) -> Dict[str, pd.DataFrame]:
    """
    Universal Carver: Walks SQLite Freelist trunk/leaf pages, all 0x0D Table B-Tree
    freeblocks and unallocated slack, and all .db-wal frames using mmap.ACCESS_READ.
    Recovers deleted records across 4 categories:
    1. deleted_transactions
    2. deleted_chats (28-Column Cellebrite PA Categorized Schema)
    3. deleted_calls
    4. deleted_locations
    """
    empty_result = {
        'deleted_transactions': pd.DataFrame(columns=STANDARD_TX_COLUMNS + ['Page_Number', 'Byte_Offset', 'Recovery_Method']),
        'deleted_chats': pd.DataFrame(columns=PA_CATEGORIZED_CHAT_COLUMNS),
        'deleted_calls': pd.DataFrame(columns=['Timestamp', 'Timestamp_IST', 'Peer', 'Duration_Sec', 'Direction', 'Forensic_Provenance']),
        'deleted_locations': pd.DataFrame(columns=['Latitude', 'Longitude', 'Timestamp', 'Timestamp_IST', 'Geo_Coordinates', 'Forensic_Provenance']),
    }

    if not os.path.exists(db_path) or os.path.getsize(db_path) < 100:
        return empty_result

    file_size = os.path.getsize(db_path)
    all_tx: List[Dict[str, Any]] = []
    all_chats: List[Dict[str, Any]] = []
    all_calls: List[Dict[str, Any]] = []
    all_locs: List[Dict[str, Any]] = []

    try:
        with open(db_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                if mm[:16] != b'SQLite format 3\x00':
                    return empty_result

                page_size = int.from_bytes(mm[16:18], 'big')
                if page_size == 1:
                    page_size = 65536
                elif page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                    page_size = 4096

                first_trunk = int.from_bytes(mm[32:36], 'big')
                total_free = int.from_bytes(mm[36:40], 'big')
                freelist_pages: List[int] = []
                curr = first_trunk

                # 1. Harvest Freelist trunk & leaf page pointers
                while curr != 0 and len(freelist_pages) < min(total_free, 50000):
                    freelist_pages.append(curr)
                    t_off = (curr - 1) * page_size
                    if t_off + 8 > file_size:
                        break
                    next_t = int.from_bytes(mm[t_off : t_off + 4], 'big')
                    leaf_cnt = int.from_bytes(mm[t_off + 4 : t_off + 8], 'big')
                    for i in range(min(leaf_cnt, page_size // 4)):
                        p_off = t_off + 8 + (i * 4)
                        if p_off + 4 <= file_size:
                            l_pg = int.from_bytes(mm[p_off : p_off + 4], 'big')
                            if l_pg != 0:
                                freelist_pages.append(l_pg)
                    curr = next_t

                # 2. Carve all Freelist pages
                for pg_num in set(freelist_pages):
                    pg_off = (pg_num - 1) * page_size
                    if pg_off + page_size <= file_size:
                        pg_slice = mm[pg_off : pg_off + page_size]
                        txs, chs, cls, lcs = _scan_unallocated_slice_for_records(
                            pg_slice, pg_num, pg_off, 'CARVED_FREELIST', db_path
                        )
                        all_tx.extend(txs)
                        all_chats.extend(chs)
                        all_calls.extend(cls)
                        all_locs.extend(lcs)

                # 3. Walk all Table B-Tree Leaf Pages (0x0D) for Freeblocks & Cell Slack
                total_pages = min(file_size // page_size, 250000)
                free_set = set(freelist_pages)

                for p in range(1, total_pages + 1):
                    if p in free_set:
                        continue
                    pg_off = (p - 1) * page_size
                    hdr_off = 100 if p == 1 else 0
                    if pg_off + hdr_off + 8 > file_size:
                        continue

                    page_type = mm[pg_off + hdr_off]
                    if page_type == 0x0D:  # Table Leaf
                        first_freeblock = int.from_bytes(mm[pg_off + hdr_off + 1 : pg_off + hdr_off + 3], 'big')
                        num_cells = int.from_bytes(mm[pg_off + hdr_off + 3 : pg_off + hdr_off + 5], 'big')
                        cell_content_offset = int.from_bytes(mm[pg_off + hdr_off + 5 : pg_off + hdr_off + 7], 'big')
                        if cell_content_offset == 0:
                            cell_content_offset = page_size

                        # 3a. Carve the Unallocated Gap (between cell pointers and content area)
                        gap_start = hdr_off + 8 + (2 * num_cells)
                        if gap_start < cell_content_offset:
                            gap_bytes = mm[pg_off + gap_start : pg_off + cell_content_offset]
                            txs, chs, cls, lcs = _scan_unallocated_slice_for_records(
                                gap_bytes, p, pg_off + gap_start, 'CARVED_UNALLOCATED_GAP', db_path
                            )
                            all_tx.extend(txs)
                            all_chats.extend(chs)
                            all_calls.extend(cls)
                            all_locs.extend(lcs)

                        # 3b. Follow the Freeblock Chain
                        fb_curr = first_freeblock
                        visited_fb = 0
                        while fb_curr != 0 and visited_fb < 500:
                            fb_abs = pg_off + fb_curr
                            if fb_abs + 4 > file_size:
                                break
                            fb_next = int.from_bytes(mm[fb_abs : fb_abs + 2], 'big')
                            fb_size = int.from_bytes(mm[fb_abs + 2 : fb_abs + 4], 'big')
                            if fb_size >= 4 and fb_abs + fb_size <= pg_off + page_size:
                                fb_bytes = mm[fb_abs + 4 : fb_abs + fb_size]
                                txs, chs, cls, lcs = _scan_unallocated_slice_for_records(
                                    fb_bytes, p, fb_abs + 4, 'CARVED_FREEBLOCK', db_path
                                )
                                all_tx.extend(txs)
                                all_chats.extend(chs)
                                all_calls.extend(cls)
                                all_locs.extend(lcs)
                            fb_curr = fb_next
                            visited_fb += 1

    except Exception:
        pass

    # 4. WALK WRITE-AHEAD LOG (.db-wal) FRAMES
    wal_path = f"{db_path}-wal"
    if os.path.exists(wal_path) and os.path.getsize(wal_path) >= 56:
        try:
            wal_size = os.path.getsize(wal_path)
            with open(wal_path, 'rb') as f_wal:
                with mmap.mmap(f_wal.fileno(), 0, access=mmap.ACCESS_READ) as mm_wal:
                    wal_magic = int.from_bytes(mm_wal[:4], 'big')
                    if wal_magic in (0x377f0682, 0x377f0683):
                        wal_page_size = int.from_bytes(mm_wal[8:12], 'big')
                        if wal_page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                            wal_page_size = 4096

                        frame_offset = 32
                        while frame_offset + 24 + wal_page_size <= wal_size:
                            pg_num = int.from_bytes(mm_wal[frame_offset : frame_offset + 4], 'big')
                            frame_data = mm_wal[frame_offset + 24 : frame_offset + 24 + wal_page_size]

                            txs, chs, cls, lcs = _scan_unallocated_slice_for_records(
                                frame_data, pg_num, frame_offset + 24, 'WAL_RECOVERED', db_path
                            )
                            all_tx.extend(txs)
                            all_chats.extend(chs)
                            all_calls.extend(cls)
                            all_locs.extend(lcs)

                            frame_offset += 24 + wal_page_size
        except Exception:
            pass

    # Construct and deduplicate output DataFrames
    df_tx = pd.DataFrame(all_tx).drop_duplicates(subset=['Counterparty', 'Transaction_ID']) if all_tx else pd.DataFrame(columns=STANDARD_TX_COLUMNS + ['Page_Number', 'Byte_Offset', 'Recovery_Method'])
    df_chats = pd.DataFrame(all_chats, columns=PA_CATEGORIZED_CHAT_COLUMNS).drop_duplicates(subset=['Sender_Identifier', 'Message_Body', 'Raw_Timestamp_Value']) if all_chats else pd.DataFrame(columns=PA_CATEGORIZED_CHAT_COLUMNS)
    df_calls = pd.DataFrame(all_calls).drop_duplicates(subset=['Peer', 'Timestamp', 'Duration_Sec']) if all_calls else pd.DataFrame(columns=['Timestamp', 'Timestamp_IST', 'Peer', 'Duration_Sec', 'Direction', 'Forensic_Provenance'])
    df_locs = pd.DataFrame(all_locs).drop_duplicates(subset=['Latitude', 'Longitude', 'Timestamp']) if all_locs else pd.DataFrame(columns=['Latitude', 'Longitude', 'Timestamp', 'Timestamp_IST', 'Geo_Coordinates', 'Forensic_Provenance'])

    return {
        'deleted_transactions': df_tx,
        'deleted_chats': df_chats,
        'deleted_calls': df_calls,
        'deleted_locations': df_locs,
    }
