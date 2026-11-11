import { readVarint, SqliteBinaryParser, SqliteDecodedRecord } from './sqlite_binary';

/**
 * Freeblock & Unallocated Space Carver for SQLite.
 * Carves deleted rows, messages, and transactions left behind in SQLite database freeblocks
 * and unallocated gaps between the cell pointer array and the cell content area.
 */
export class FreeblockCarver {
  constructor(private parser: SqliteBinaryParser, private dbBuffer: Buffer) {}

  public carvePage(pageNumber: number): SqliteDecodedRecord[] {
    const pageHeader = this.parser.getPageHeader(pageNumber);
    if (!pageHeader.isLeafTable) {
      return [];
    }

    const carvedRecords: SqliteDecodedRecord[] = [];
    const pageOffset = pageHeader.pageOffset;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;

    // 1. Carve Explicit Freeblocks linked list
    let freeblockOffsetInPage = pageHeader.firstFreeblockOffset;
    const visited = new Set<number>();

    while (freeblockOffsetInPage > 0 && freeblockOffsetInPage < this.parser.getFileHeader().pageSize) {
      if (visited.has(freeblockOffsetInPage)) break;
      visited.add(freeblockOffsetInPage);

      const absFbOffset = pageOffset + freeblockOffsetInPage;
      if (absFbOffset + 4 > this.dbBuffer.length) break;

      const nextFbOffset = this.dbBuffer.readUInt16BE(absFbOffset);
      const fbSize = this.dbBuffer.readUInt16BE(absFbOffset + 2);

      if (fbSize >= 8 && absFbOffset + fbSize <= this.dbBuffer.length) {
        const fbContentOffset = absFbOffset + 4;
        const fbContentLen = fbSize - 4;
        const candidate = this.carveRecordCandidate(fbContentOffset, fbContentLen, pageNumber);
        if (candidate) {
          carvedRecords.push(candidate);
        }
      }

      freeblockOffsetInPage = nextFbOffset;
    }

    // 2. Carve Unallocated Space between cell pointer array and cell content start
    const cellPointerArrayEnd = pageOffset + headerStartInPage + pageHeader.headerSize + pageHeader.cellCount * 2;
    const cellContentStartAbs = pageOffset + pageHeader.cellContentStart;

    if (cellContentStartAbs > cellPointerArrayEnd) {
      const unallocLen = cellContentStartAbs - cellPointerArrayEnd;
      // Scan unallocated chunk for candidate record headers
      for (let offset = cellPointerArrayEnd; offset < cellContentStartAbs - 8; offset += 2) {
        const candidate = this.carveRecordCandidate(offset, cellContentStartAbs - offset, pageNumber);
        if (candidate && candidate.values.length >= 2) {
          carvedRecords.push(candidate);
          offset += candidate.byteLength; // Skip beyond candidate
        }
      }
    }

    return carvedRecords;
  }

  public carveAllPages(): SqliteDecodedRecord[] {
    const allCarved: SqliteDecodedRecord[] = [];
    const pageCount = this.parser.getPageCount();

    for (let p = 1; p <= pageCount; p++) {
      try {
        const pageCarved = this.carvePage(p);
        allCarved.push(...pageCarved);
      } catch {
        // Skip corrupted pages safely
      }
    }

    return allCarved;
  }

  private carveRecordCandidate(
    offset: number,
    maxLen: number,
    pageNumber: number
  ): SqliteDecodedRecord | null {
    if (offset + 4 >= this.dbBuffer.length || maxLen < 6) return null;

    try {
      // Check if candidate starts with a Varint payload length
      const payloadVarint = readVarint(this.dbBuffer, offset);
      let payloadSize = payloadVarint.value;
      let recordStart = offset + payloadVarint.length;

      // Check if candidate has a rowid varint
      const rowIdVarint = readVarint(this.dbBuffer, recordStart);
      let rowId = rowIdVarint.value;
      recordStart += rowIdVarint.length;

      // Sanity checks on payload size
      if (payloadSize <= 0 || payloadSize > 65536 || payloadSize > maxLen) {
        // Direct record test without cell wrapper
        payloadSize = maxLen;
        recordStart = offset;
        rowId = 0;
      }

      const headerVarint = readVarint(this.dbBuffer, recordStart);
      const headerSize = headerVarint.value;
      if (headerSize < 2 || headerSize > 128 || headerSize > payloadSize) {
        return null;
      }

      const values = this.parser.parseRecordPayload(recordStart, payloadSize);
      if (values.length < 2) return null;

      // Filter out records that are completely null
      const nonNullCount = values.filter((v) => v !== null && v !== undefined && v !== '').length;
      if (nonNullCount === 0) return null;

      const totalLen = Math.min(recordStart - offset + payloadSize, maxLen);
      const rawPayloadHex = this.dbBuffer.subarray(offset, offset + Math.min(totalLen, 64)).toString('hex');

      return {
        pageNumber,
        byteOffset: offset,
        byteLength: totalLen,
        rowId,
        values,
        rawPayloadHex,
        state: 'CARVED_UNALLOCATED'
      };
    } catch {
      return null;
    }
  }
}
