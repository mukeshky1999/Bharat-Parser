export interface AxmlManifestResult {
  packageName: string;
  permissions: string[];
  receivers: string[];
  services: string[];
  activities: string[];
}

/**
 * Android Binary XML (AXML) Parser.
 * Decodes compiled AndroidManifest.xml from raw bytes inside APKs.
 */
export class AxmlParser {
  public static parse(buf: Buffer): AxmlManifestResult {
    const result: AxmlManifestResult = {
      packageName: '',
      permissions: [],
      receivers: [],
      services: [],
      activities: []
    };

    if (buf.length < 8) return result;

    const magic = buf.readUInt32LE(0);
    // RES_XML_TYPE = 0x00080003
    if ((magic & 0xffff) !== 0x0003) {
      // Fallback: search for strings in raw buffer
      return AxmlParser.fallbackStringSearch(buf);
    }

    let offset = 8;
    const stringPool: string[] = [];

    while (offset < buf.length) {
      const chunkType = buf.readUInt16LE(offset);
      const headerSize = buf.readUInt16LE(offset + 2);
      const chunkSize = buf.readUInt32LE(offset + 4);

      if (chunkSize <= 0 || offset + chunkSize > buf.length + 8) break;

      if (chunkType === 0x0001) {
        // String Pool Chunk
        const stringCount = buf.readUInt32LE(offset + 8);
        const stringsStart = offset + buf.readUInt32LE(offset + 20);
        const isUtf8 = (buf.readUInt32LE(offset + 16) & (1 << 8)) !== 0;

        const stringOffsets: number[] = [];
        for (let i = 0; i < stringCount; i++) {
          stringOffsets.push(buf.readUInt32LE(offset + 28 + i * 4));
        }

        for (let i = 0; i < stringCount; i++) {
          const strOffset = stringsStart + stringOffsets[i];
          if (strOffset < buf.length) {
            if (isUtf8) {
              // Length prefix
              let strLen = buf[strOffset];
              let p = strOffset + 1;
              if (strLen & 0x80) {
                p++; // 2-byte length
              }
              const len = buf[p];
              p++;
              const str = buf.toString('utf8', p, p + len);
              stringPool.push(str);
            } else {
              const u16Len = buf.readUInt16LE(strOffset);
              const str = buf.toString('utf16le', strOffset + 2, strOffset + 2 + u16Len * 2);
              stringPool.push(str);
            }
          }
        }
      } else if (chunkType === 0x0102) {
        // START_TAG chunk
        const nameIdx = buf.readUInt32LE(offset + 20);
        const attrCount = buf.readUInt16LE(offset + 28);
        const tagName = stringPool[nameIdx] || '';

        const attrOffset = offset + 36;
        for (let a = 0; a < attrCount; a++) {
          const aOffset = attrOffset + a * 20;
          if (aOffset + 20 > buf.length) break;

          const attrNameIdx = buf.readUInt32LE(aOffset + 4);
          const attrValIdx = buf.readUInt32LE(aOffset + 8);
          const attrName = stringPool[attrNameIdx] || '';
          let attrVal = stringPool[attrValIdx] || '';

          // If raw value index is -1, decode typed data
          if (!attrVal && attrValIdx === 0xffffffff) {
            const rawData = buf.readUInt32LE(aOffset + 16);
            attrVal = stringPool[rawData] || String(rawData);
          }

          if (tagName === 'manifest' && attrName === 'package') {
            result.packageName = attrVal;
          } else if (tagName === 'uses-permission' && (attrName === 'name' || attrName.endsWith(':name'))) {
            if (attrVal && !result.permissions.includes(attrVal)) {
              result.permissions.push(attrVal);
            }
          } else if (tagName === 'receiver' && (attrName === 'name' || attrName.endsWith(':name'))) {
            result.receivers.push(attrVal);
          } else if (tagName === 'service' && (attrName === 'name' || attrName.endsWith(':name'))) {
            result.services.push(attrVal);
          } else if (tagName === 'activity' && (attrName === 'name' || attrName.endsWith(':name'))) {
            result.activities.push(attrVal);
          }
        }
      }

      offset += chunkSize;
    }

    if (!result.packageName || result.permissions.length === 0) {
      const fb = AxmlParser.fallbackStringSearch(buf);
      if (!result.packageName) result.packageName = fb.packageName;
      for (const p of fb.permissions) {
        if (!result.permissions.includes(p)) result.permissions.push(p);
      }
    }

    return result;
  }

  private static fallbackStringSearch(buf: Buffer): AxmlManifestResult {
    const rawText = buf.toString('latin1');
    const permissions: string[] = [];
    const permRegex = /android\.permission\.[A-Z_]+/g;
    let match: RegExpExecArray | null;

    while ((match = permRegex.exec(rawText)) !== null) {
      if (!permissions.includes(match[0])) {
        permissions.push(match[0]);
      }
    }

    let packageName = 'unknown.package';
    const pkgMatch = /package="([a-zA-Z0-9._]+)"/.exec(rawText) || /([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)/.exec(rawText);
    if (pkgMatch) {
      packageName = pkgMatch[1];
    }

    return {
      packageName,
      permissions,
      receivers: [],
      services: [],
      activities: []
    };
  }
}
