import { readVarint } from '../sqlite_carver/sqlite_binary';

export interface MmkvEntry {
  key: string;
  value: any;
  rawValueHex: string;
}

/**
 * Tencent MMKV Key-Value Binary Decoder.
 * Decodes length-prefixed key-value pairs stored in MMKV memory-mapped files.
 */
export class MmkvDecoder {
  public static decode(buf: Buffer): MmkvEntry[] {
    const entries: MmkvEntry[] = [];
    if (buf.length < 4) return entries;

    // First 4 bytes is actual data size in MMKV file
    const dataSize = buf.readUInt32LE(0);
    const maxOffset = Math.min(4 + dataSize, buf.length);
    let offset = 4;

    while (offset < maxOffset) {
      try {
        // Read Key Length (Varint)
        const keyLenVarint = readVarint(buf, offset);
        if (keyLenVarint.length === 0) break;
        offset += keyLenVarint.length;
        const keyLen = keyLenVarint.value;

        if (keyLen <= 0 || offset + keyLen > maxOffset) break;
        const key = buf.toString('utf8', offset, offset + keyLen);
        offset += keyLen;

        // Read Value Length (Varint)
        const valLenVarint = readVarint(buf, offset);
        offset += valLenVarint.length;
        const valLen = valLenVarint.value;

        if (valLen < 0 || offset + valLen > maxOffset) break;
        const valSlice = buf.subarray(offset, offset + valLen);
        offset += valLen;

        // Determine value type: String, JSON, Integer, or Hex
        let decodedVal: any = valSlice.toString('utf8');
        if (/^[\x20-\x7E\r\n\t]*$/.test(decodedVal)) {
          if (
            (decodedVal.startsWith('{') && decodedVal.endsWith('}')) ||
            (decodedVal.startsWith('[') && decodedVal.endsWith(']'))
          ) {
            try {
              decodedVal = JSON.parse(decodedVal);
            } catch {
              // Leave as string
            }
          }
        } else {
          decodedVal = valSlice.toString('hex');
        }

        entries.push({
          key,
          value: decodedVal,
          rawValueHex: valSlice.subarray(0, Math.min(valSlice.length, 64)).toString('hex')
        });
      } catch {
        break;
      }
    }

    return entries;
  }
}
