/**
 * SQLite 1-to-9 Byte Huffman Varint Reader and Serial Type Binary Decoder.
 * Fully compliant with the official SQLite3 Database File Format Specification.
 */

export interface VarintResult {
  value: bigint | number;
  bytesRead: number;
}

export interface SerialTypeResult {
  value: any;
  bytesRead: number;
}

export interface DecodedRecordResult {
  values: any[];
  serialTypes: (number | bigint)[];
  headerBytesRead: number;
}

/**
 * Exact SQLite 1-to-9 byte variable-length integer reader.
 * Bytes 1 to 8: highest bit (0x80) indicates continuation, lowest 7 bits are payload.
 * Byte 9 (if reached): all 8 bits are used directly as lowest significant bits.
 */
export function readSqliteVarint(buf: Buffer, offset: number): VarintResult {
  if (offset >= buf.length) {
    return { value: 0, bytesRead: 0 };
  }

  let value = 0n;
  let bytesRead = 0;

  for (let i = 0; i < 8; i++) {
    if (offset + i >= buf.length) {
      break;
    }
    const byte = BigInt(buf[offset + i]);
    bytesRead++;
    value = (value << 7n) | (byte & 0x7fn);

    if ((byte & 0x80n) === 0n) {
      // Normal integer return if fits in Number.MAX_SAFE_INTEGER
      const numVal = Number(value);
      return {
        value: Number.isSafeInteger(numVal) ? numVal : value,
        bytesRead
      };
    }
  }

  // 9th byte: uses all 8 bits without continuation flag
  if (offset + 8 < buf.length) {
    const byte9 = BigInt(buf[offset + 8]);
    bytesRead++;
    value = (value << 8n) | byte9;
  }

  const numVal = Number(value);
  return {
    value: Number.isSafeInteger(numVal) ? numVal : value,
    bytesRead
  };
}

/**
 * Decodes SQLite Serial Types into JavaScript native types.
 * Supports:
 * - 0: NULL
 * - 1: Int8 (1 byte signed)
 * - 2: Int16 (2 bytes big-endian signed)
 * - 3: Int24 (3 bytes big-endian signed)
 * - 4: Int32 (4 bytes big-endian signed)
 * - 5: Int48 (6 bytes big-endian signed)
 * - 6: Int64 (8 bytes big-endian signed)
 * - 7: Float64 (8 bytes IEEE-754 double precision float)
 * - 8: Integer constant 0 (0 bytes)
 * - 9: Integer constant 1 (0 bytes)
 * - 10, 11: Reserved
 * - N >= 12 and even: BLOB of length (N - 12) / 2
 * - N >= 13 and odd: UTF-8 Text of length (N - 13) / 2
 */
export function decodeSerialType(
  serialType: number | bigint,
  buf: Buffer,
  offset: number
): SerialTypeResult {
  const st = typeof serialType === 'bigint' ? Number(serialType) : serialType;

  if (st === 0) {
    return { value: null, bytesRead: 0 };
  }

  if (st === 1) {
    if (offset >= buf.length) return { value: null, bytesRead: 0 };
    return { value: buf.readInt8(offset), bytesRead: 1 };
  }

  if (st === 2) {
    if (offset + 2 > buf.length) return { value: null, bytesRead: 0 };
    return { value: buf.readInt16BE(offset), bytesRead: 2 };
  }

  if (st === 3) {
    if (offset + 3 > buf.length) return { value: null, bytesRead: 0 };
    const b0 = buf[offset];
    const b1 = buf[offset + 1];
    const b2 = buf[offset + 2];
    let val = (b0 << 16) | (b1 << 8) | b2;
    if (b0 & 0x80) val |= 0xff000000; // Sign extend
    return { value: val, bytesRead: 3 };
  }

  if (st === 4) {
    if (offset + 4 > buf.length) return { value: null, bytesRead: 0 };
    return { value: buf.readInt32BE(offset), bytesRead: 4 };
  }

  if (st === 5) {
    if (offset + 6 > buf.length) return { value: null, bytesRead: 0 };
    const high = buf.readInt16BE(offset);
    const low = buf.readUInt32BE(offset + 2);
    const val = high * 0x100000000 + low;
    return { value: val, bytesRead: 6 };
  }

  if (st === 6) {
    if (offset + 8 > buf.length) return { value: null, bytesRead: 0 };
    const big = buf.readBigInt64BE(offset);
    const num = Number(big);
    return {
      value: Number.isSafeInteger(num) ? num : big.toString(),
      bytesRead: 8
    };
  }

  if (st === 7) {
    if (offset + 8 > buf.length) return { value: null, bytesRead: 0 };
    return { value: buf.readDoubleBE(offset), bytesRead: 8 };
  }

  if (st === 8) {
    return { value: 0, bytesRead: 0 };
  }

  if (st === 9) {
    return { value: 1, bytesRead: 0 };
  }

  if (st >= 12 && st % 2 === 0) {
    // BLOB
    const len = (st - 12) / 2;
    if (offset + len > buf.length) {
      return { value: Buffer.alloc(0), bytesRead: 0 };
    }
    const blob = buf.subarray(offset, offset + len);
    return { value: blob, bytesRead: len };
  }

  if (st >= 13 && st % 2 === 1) {
    // UTF-8 Text
    const len = (st - 13) / 2;
    if (offset + len > buf.length) {
      return { value: '', bytesRead: 0 };
    }
    const text = buf.toString('utf8', offset, offset + len);
    return { value: text, bytesRead: len };
  }

  return { value: null, bytesRead: 0 };
}

/**
 * Decodes a complete SQLite Record payload:
 * 1. Reads Record Header Size Varint
 * 2. Reads Serial Type Varints for all columns
 * 3. Decodes each column value sequentially
 */
export function decodeRecordPayload(
  buf: Buffer,
  offset: number,
  payloadLength: number
): DecodedRecordResult {
  if (offset >= buf.length || payloadLength <= 0) {
    return { values: [], serialTypes: [], headerBytesRead: 0 };
  }

  const maxOffset = Math.min(offset + payloadLength, buf.length);
  const headerSizeVarint = readSqliteVarint(buf, offset);
  const headerSize = Number(headerSizeVarint.value);

  if (headerSize < 1 || headerSize > payloadLength || offset + headerSize > maxOffset) {
    return { values: [], serialTypes: [], headerBytesRead: 0 };
  }

  let currentHeaderOffset = offset + headerSizeVarint.bytesRead;
  const headerEndOffset = offset + headerSize;

  const serialTypes: (number | bigint)[] = [];
  while (currentHeaderOffset < headerEndOffset) {
    const stVarint = readSqliteVarint(buf, currentHeaderOffset);
    if (stVarint.bytesRead === 0) break;
    serialTypes.push(stVarint.value);
    currentHeaderOffset += stVarint.bytesRead;
  }

  const values: any[] = [];
  let dataOffset = headerEndOffset;

  for (const st of serialTypes) {
    if (dataOffset > maxOffset) {
      values.push(null);
      continue;
    }
    const decoded = decodeSerialType(st, buf, dataOffset);
    values.push(decoded.value);
    dataOffset += decoded.bytesRead;
  }

  return {
    values,
    serialTypes,
    headerBytesRead: headerSize
  };
}
