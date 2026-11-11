import { RecoveryState } from '../../shared/forensic-types';

export interface SqliteVarint {
  value: number;
  length: number;
}

export interface SqliteFileHeader {
  magic: string;
  pageSize: number;
  writeVersion: number;
  readVersion: number;
  reservedBytes: number;
  changeCounter: number;
  pageCount: number;
  firstFreelistPage: number;
  freelistPageCount: number;
  schemaCookie: number;
  textEncoding: number;
}

export interface BTreePageHeader {
  pageNumber: number;
  pageOffset: number;
  pageType: number; // 0x02, 0x05, 0x0a, 0x0d
  isLeafTable: boolean;
  firstFreeblockOffset: number;
  cellCount: number;
  cellContentStart: number;
  fragmentedFreeBytes: number;
  rightChildPage?: number;
  headerSize: number;
}

export interface SqliteDecodedRecord {
  pageNumber: number;
  byteOffset: number;
  byteLength: number;
  rowId: number;
  values: any[];
  rawPayloadHex: string;
  state: RecoveryState;
}

/**
 * Decodes SQLite Variable-Length Integer (Varint) from a buffer.
 */
export function readVarint(buf: Buffer, offset: number): SqliteVarint {
  let value = 0;
  let i = 0;
  while (i < 8) {
    if (offset + i >= buf.length) {
      return { value, length: i + 1 };
    }
    const byte = buf[offset + i];
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      return { value, length: i + 1 };
    }
    i++;
  }
  // 9th byte uses all 8 bits
  if (offset + 8 < buf.length) {
    value = (value << 8) | buf[offset + 8];
  }
  return { value, length: 9 };
}

/**
 * Lab-Grade Raw SQLite Binary Parser.
 * Walks B-Trees, parses records, and computes exact byte offsets without standard SQLite drivers.
 */
export class SqliteBinaryParser {
  private header: SqliteFileHeader;

  constructor(private dbBuffer: Buffer) {
    this.header = this.parseFileHeader();
  }

  public getFileHeader(): SqliteFileHeader {
    return this.header;
  }

  private parseFileHeader(): SqliteFileHeader {
    if (this.dbBuffer.length < 100) {
      throw new Error('[SQLITE_BINARY] Buffer is too small for SQLite header.');
    }

    const magic = this.dbBuffer.toString('utf8', 0, 16);
    if (!magic.startsWith('SQLite format 3')) {
      throw new Error(`[SQLITE_BINARY] Invalid SQLite magic: "${magic}"`);
    }

    let pageSize = this.dbBuffer.readUInt16BE(16);
    if (pageSize === 1) pageSize = 65536;

    return {
      magic,
      pageSize,
      writeVersion: this.dbBuffer[18],
      readVersion: this.dbBuffer[19],
      reservedBytes: this.dbBuffer[20],
      changeCounter: this.dbBuffer.readUInt32BE(24),
      pageCount: this.dbBuffer.readUInt32BE(28),
      firstFreelistPage: this.dbBuffer.readUInt32BE(32),
      freelistPageCount: this.dbBuffer.readUInt32BE(36),
      schemaCookie: this.dbBuffer.readUInt32BE(40),
      textEncoding: this.dbBuffer.readUInt32BE(56)
    };
  }

  public getPageCount(): number {
    return Math.floor(this.dbBuffer.length / this.header.pageSize);
  }

  public getPageHeader(pageNumber: number): BTreePageHeader {
    const pageSize = this.header.pageSize;
    const pageOffset = (pageNumber - 1) * pageSize;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;
    const absOffset = pageOffset + headerStartInPage;

    if (absOffset + 8 > this.dbBuffer.length) {
      throw new Error(`[SQLITE_BINARY] Page ${pageNumber} offset out of bounds.`);
    }

    const pageType = this.dbBuffer[absOffset];
    const firstFreeblockOffset = this.dbBuffer.readUInt16BE(absOffset + 1);
    const cellCount = this.dbBuffer.readUInt16BE(absOffset + 3);
    let cellContentStart = this.dbBuffer.readUInt16BE(absOffset + 5);
    if (cellContentStart === 0) cellContentStart = 65536;
    const fragmentedFreeBytes = this.dbBuffer[absOffset + 7];

    const isInterior = pageType === 0x02 || pageType === 0x05;
    let rightChildPage: number | undefined;
    const headerSize = isInterior ? 12 : 8;

    if (isInterior && absOffset + 12 <= this.dbBuffer.length) {
      rightChildPage = this.dbBuffer.readUInt32BE(absOffset + 8);
    }

    return {
      pageNumber,
      pageOffset,
      pageType,
      isLeafTable: pageType === 0x0d,
      firstFreeblockOffset,
      cellCount,
      cellContentStart,
      fragmentedFreeBytes,
      rightChildPage,
      headerSize
    };
  }

  /**
   * Parses active cells on a leaf table page (0x0d).
   */
  public parseLeafTablePageCells(pageNumber: number): SqliteDecodedRecord[] {
    const pageHeader = this.getPageHeader(pageNumber);
    if (pageHeader.pageType !== 0x0d) {
      return [];
    }

    const records: SqliteDecodedRecord[] = [];
    const pageOffset = pageHeader.pageOffset;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;
    const cellPointerArrayOffset = pageOffset + headerStartInPage + pageHeader.headerSize;

    for (let i = 0; i < pageHeader.cellCount; i++) {
      const ptrOffset = cellPointerArrayOffset + i * 2;
      if (ptrOffset + 2 > this.dbBuffer.length) break;

      const cellOffsetInPage = this.dbBuffer.readUInt16BE(ptrOffset);
      const absCellOffset = pageOffset + cellOffsetInPage;

      if (absCellOffset >= this.dbBuffer.length) continue;

      try {
        const payloadVarint = readVarint(this.dbBuffer, absCellOffset);
        const payloadSize = payloadVarint.value;
        const rowIdOffset = absCellOffset + payloadVarint.length;
        const rowIdVarint = readVarint(this.dbBuffer, rowIdOffset);
        const rowId = rowIdVarint.value;

        const recordStartOffset = rowIdOffset + rowIdVarint.length;
        const cellTotalLength = (recordStartOffset - absCellOffset) + payloadSize;

        const recordValues = this.parseRecordPayload(recordStartOffset, payloadSize);
        const rawPayloadHex = this.dbBuffer.subarray(absCellOffset, Math.min(absCellOffset + Math.min(cellTotalLength, 64), this.dbBuffer.length)).toString('hex');

        records.push({
          pageNumber,
          byteOffset: absCellOffset,
          byteLength: cellTotalLength,
          rowId,
          values: recordValues,
          rawPayloadHex,
          state: 'ACTIVE'
        });
      } catch {
        // Continue parsing next cell
      }
    }

    return records;
  }

  /**
   * Decodes SQLite Record payload format (Header size, Serial types, Column values).
   */
  public parseRecordPayload(payloadOffset: number, payloadLength: number): any[] {
    if (payloadOffset >= this.dbBuffer.length || payloadLength <= 0) return [];

    const headerSizeVarint = readVarint(this.dbBuffer, payloadOffset);
    const headerSize = headerSizeVarint.value;
    let currentHeaderOffset = payloadOffset + headerSizeVarint.length;
    const headerEndOffset = payloadOffset + headerSize;

    const serialTypes: number[] = [];
    while (currentHeaderOffset < headerEndOffset && currentHeaderOffset < this.dbBuffer.length) {
      const st = readVarint(this.dbBuffer, currentHeaderOffset);
      serialTypes.push(st.value);
      currentHeaderOffset += st.length;
    }

    const values: any[] = [];
    let dataOffset = headerEndOffset;

    for (const st of serialTypes) {
      if (dataOffset > this.dbBuffer.length) {
        values.push(null);
        continue;
      }

      if (st === 0) {
        values.push(null);
      } else if (st === 1) {
        // 8-bit integer
        values.push(this.dbBuffer.readInt8(dataOffset));
        dataOffset += 1;
      } else if (st === 2) {
        // 16-bit big endian integer
        values.push(this.dbBuffer.readInt16BE(dataOffset));
        dataOffset += 2;
      } else if (st === 3) {
        // 24-bit big endian integer
        const b0 = this.dbBuffer[dataOffset];
        const b1 = this.dbBuffer[dataOffset + 1];
        const b2 = this.dbBuffer[dataOffset + 2];
        let val = (b0 << 16) | (b1 << 8) | b2;
        if (b0 & 0x80) val |= 0xff000000;
        values.push(val);
        dataOffset += 3;
      } else if (st === 4) {
        // 32-bit big endian integer
        values.push(this.dbBuffer.readInt32BE(dataOffset));
        dataOffset += 4;
      } else if (st === 5) {
        // 48-bit big endian integer
        const high = this.dbBuffer.readInt16BE(dataOffset);
        const low = this.dbBuffer.readUInt32BE(dataOffset + 2);
        values.push(high * 0x100000000 + low);
        dataOffset += 6;
      } else if (st === 6) {
        // 64-bit integer
        values.push(Number(this.dbBuffer.readBigInt64BE(dataOffset)));
        dataOffset += 8;
      } else if (st === 7) {
        // 64-bit float
        values.push(this.dbBuffer.readDoubleBE(dataOffset));
        dataOffset += 8;
      } else if (st === 8) {
        values.push(0);
      } else if (st === 9) {
        values.push(1);
      } else if (st >= 12 && st % 2 === 0) {
        // BLOB
        const len = (st - 12) / 2;
        const blob = this.dbBuffer.subarray(dataOffset, dataOffset + len);
        values.push(blob);
        dataOffset += len;
      } else if (st >= 13 && st % 2 === 1) {
        // String
        const len = (st - 13) / 2;
        const str = this.dbBuffer.toString('utf8', dataOffset, dataOffset + len);
        values.push(str);
        dataOffset += len;
      } else {
        values.push(null);
      }
    }

    return values;
  }
}
