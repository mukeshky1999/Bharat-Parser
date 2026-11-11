import { readVarint } from '../sqlite_carver/sqlite_binary';

export interface ProtobufField {
  tag: number;
  wireType: number;
  value: any;
  rawBytes?: Buffer;
}

/**
 * Universal Schema-less Protobuf Wire Decoder.
 * Decodes binary Protobuf streams into structured tag-value trees.
 * Recurses into embedded messages (wireType 2) automatically when valid.
 */
export class ProtobufDecoder {
  public static decode(buf: Buffer): ProtobufField[] {
    const fields: ProtobufField[] = [];
    let offset = 0;

    while (offset < buf.length) {
      const keyVarint = readVarint(buf, offset);
      if (keyVarint.length === 0 || offset + keyVarint.length > buf.length) break;

      const key = keyVarint.value;
      offset += keyVarint.length;

      const tag = key >>> 3;
      const wireType = key & 0x07;

      if (tag === 0) break; // Invalid tag

      if (wireType === 0) {
        // Varint
        const valVarint = readVarint(buf, offset);
        fields.push({ tag, wireType, value: valVarint.value });
        offset += valVarint.length;
      } else if (wireType === 1) {
        // 64-bit fixed
        if (offset + 8 > buf.length) break;
        const val = buf.readDoubleLE(offset);
        const raw = buf.subarray(offset, offset + 8);
        fields.push({ tag, wireType, value: val, rawBytes: raw });
        offset += 8;
      } else if (wireType === 2) {
        // Length-delimited (string, bytes, or embedded message)
        const lenVarint = readVarint(buf, offset);
        offset += lenVarint.length;
        const length = lenVarint.value;

        if (offset + length > buf.length) break;
        const slice = buf.subarray(offset, offset + length);
        offset += length;

        // Try decoding as sub-message
        let isSubMessage = false;
        if (slice.length >= 2) {
          try {
            const sub = ProtobufDecoder.decode(slice);
            if (sub.length > 0) {
              fields.push({ tag, wireType, value: sub, rawBytes: slice });
              isSubMessage = true;
            }
          } catch {
            isSubMessage = false;
          }
        }

        if (!isSubMessage) {
          // Check if valid UTF-8 string
          const str = slice.toString('utf8');
          // Check if printable
          const isPrintable = /^[\x20-\x7E\r\n\t]*$/.test(str) && str.length > 0;
          fields.push({
            tag,
            wireType,
            value: isPrintable ? str : slice.toString('hex'),
            rawBytes: slice
          });
        }
      } else if (wireType === 5) {
        // 32-bit fixed
        if (offset + 4 > buf.length) break;
        const val = buf.readFloatLE(offset);
        const raw = buf.subarray(offset, offset + 4);
        fields.push({ tag, wireType, value: val, rawBytes: raw });
        offset += 4;
      } else {
        // Wire type 3/4 deprecated, or unknown
        break;
      }
    }

    return fields;
  }

  /**
   * Searches recursively for a field with a specific tag number.
   */
  public static findFieldByTag(fields: ProtobufField[], targetTag: number): ProtobufField | undefined {
    for (const f of fields) {
      if (f.tag === targetTag) return f;
      if (Array.isArray(f.value)) {
        const found = ProtobufDecoder.findFieldByTag(f.value, targetTag);
        if (found) return found;
      }
    }
    return undefined;
  }
}
