import { CarvedSqliteRow } from './sqlite-binary-carver';
import { readSqliteVarint, decodeRecordPayload } from './sqlite-varint';

export interface WalHeader {
  magic: number;
  fileFormat: number;
  pageSize: number;
  checkpointSequence: number;
  salt1: number;
  salt2: number;
  checksum1: number;
  checksum2: number;
}

export interface WalFrameRecord {
  frameIndex: number;
  frameHeaderOffset: number; // 24-byte header offset in .db-wal file
  pageDataOffset: number;    // Page data start in .db-wal file
  pageNumber: number;
  dbSizeAfterCommit: number;
  pageBuffer: Buffer;
}

/**
 * SQLite Write-Ahead Log (.db-wal) Binary Carver.
 * Walks WAL frame headers, analyzes historical and uncommitted page states,
 * and recovers rows modified or deleted from the main database.
 */
export class WalCarver {
  private header: WalHeader;
  private frames: WalFrameRecord[] = [];

  constructor(
    private walBuffer: Buffer,
    private defaultPageSize: number = 4096,
    private activeRows: CarvedSqliteRow[] = []
  ) {
    this.header = this.parseWalHeader();
    this.parseFrames();
  }

  public getHeader(): WalHeader {
    return this.header;
  }

  public getFrames(): WalFrameRecord[] {
    return this.frames;
  }

  /**
   * Verifies .db-wal magic numbers (0x377f0682 or 0x377f0683).
   * Supports both Big-Endian and Little-Endian dumps.
   */
  private parseWalHeader(): WalHeader {
    if (this.walBuffer.length < 32) {
      throw new Error('[WAL_CARVER] WAL buffer smaller than 32-byte header.');
    }

    let magic = this.walBuffer.readUInt32BE(0);
    let isBE = true;

    if (magic !== 0x377f0682 && magic !== 0x377f0683) {
      const magicLE = this.walBuffer.readUInt32LE(0);
      if (magicLE === 0x377f0682 || magicLE === 0x377f0683) {
        magic = magicLE;
        isBE = false;
      } else {
        throw new Error(`[WAL_CARVER] Invalid WAL magic signature: 0x${magic.toString(16)}`);
      }
    }

    const pageSize = isBE ? this.walBuffer.readUInt32BE(8) : this.walBuffer.readUInt32LE(8);
    const validPageSize = (pageSize >= 512 && pageSize <= 65536) ? pageSize : this.defaultPageSize;

    return {
      magic,
      fileFormat: isBE ? this.walBuffer.readUInt32BE(4) : this.walBuffer.readUInt32LE(4),
      pageSize: validPageSize,
      checkpointSequence: isBE ? this.walBuffer.readUInt32BE(12) : this.walBuffer.readUInt32LE(12),
      salt1: isBE ? this.walBuffer.readUInt32BE(16) : this.walBuffer.readUInt32LE(16),
      salt2: isBE ? this.walBuffer.readUInt32BE(20) : this.walBuffer.readUInt32LE(20),
      checksum1: isBE ? this.walBuffer.readUInt32BE(24) : this.walBuffer.readUInt32LE(24),
      checksum2: isBE ? this.walBuffer.readUInt32BE(28) : this.walBuffer.readUInt32LE(28)
    };
  }

  /**
   * Walks every 24-byte Frame Header + Page payload from Offset 32 to EOF.
   */
  private parseFrames(): void {
    const pageSize = this.header.pageSize;
    const frameSize = 24 + pageSize;
    let offset = 32;
    let frameIndex = 0;

    while (offset + frameSize <= this.walBuffer.length) {
      const pageNumber = this.walBuffer.readUInt32BE(offset);
      const dbSizeAfterCommit = this.walBuffer.readUInt32BE(offset + 4);
      const pageDataOffset = offset + 24;

      const pageBuffer = this.walBuffer.subarray(pageDataOffset, pageDataOffset + pageSize);

      this.frames.push({
        frameIndex,
        frameHeaderOffset: offset,
        pageDataOffset,
        pageNumber,
        dbSizeAfterCommit,
        pageBuffer
      });

      offset += frameSize;
      frameIndex++;
    }
  }

  /**
   * Extracts all 0x0D Table Leaf cells inside uncommitted and historical WAL frames.
   * Compares each row against active B-Tree rows:
   * Marks rows modified or deleted from active database as recoveryState: 'WAL_RECOVERED'.
   */
  public carveAllWalRows(tableName: string = 'wal_table'): CarvedSqliteRow[] {
    const walRecoveredRows: CarvedSqliteRow[] = [];
    const activeFingerprints = new Set<string>();

    for (const ar of this.activeRows) {
      const fp = `${ar.pageNumber}_${ar.rowId}_${JSON.stringify(ar.values)}`;
      activeFingerprints.add(fp);
    }

    for (const frame of this.frames) {
      const pageBuf = frame.pageBuffer;
      const headerStartInPage = frame.pageNumber === 1 ? 100 : 0;

      if (headerStartInPage + 8 > pageBuf.length) continue;

      const pageType = pageBuf[headerStartInPage];
      // Only carve Table Leaf (0x0D) pages
      if (pageType !== 0x0d) {
        continue;
      }

      const firstFreeblock = pageBuf.readUInt16BE(headerStartInPage + 1);
      const cellCount = pageBuf.readUInt16BE(headerStartInPage + 3);
      let cellContentStart = pageBuf.readUInt16BE(headerStartInPage + 5);
      if (cellContentStart === 0) cellContentStart = 65536;

      const cellPtrArrayOffset = headerStartInPage + 8;

      // Extract Active Cells in this WAL frame
      for (let i = 0; i < cellCount; i++) {
        const ptrOffset = cellPtrArrayOffset + i * 2;
        if (ptrOffset + 2 > pageBuf.length) break;

        const cellOffsetInPage = pageBuf.readUInt16BE(ptrOffset);
        if (cellOffsetInPage >= pageBuf.length) continue;

        try {
          const payloadVarint = readSqliteVarint(pageBuf, cellOffsetInPage);
          const payloadLength = Number(payloadVarint.value);
          let cursor = cellOffsetInPage + payloadVarint.bytesRead;

          const rowIdVarint = readSqliteVarint(pageBuf, cursor);
          const rowId = rowIdVarint.value;
          cursor += rowIdVarint.bytesRead;

          const recordResult = decodeRecordPayload(pageBuf, cursor, payloadLength);
          const cellTotalLength = (cursor - cellOffsetInPage) + payloadLength;

          // Physical byte offset inside the .db-wal file
          const physicalWalByteOffset = frame.pageDataOffset + cellOffsetInPage;

          const rawHex = pageBuf.subarray(
            cellOffsetInPage,
            Math.min(cellOffsetInPage + Math.min(cellTotalLength, 64), pageBuf.length)
          ).toString('hex');

          const fp = `${frame.pageNumber}_${rowId}_${JSON.stringify(recordResult.values)}`;
          const isIdenticalInActive = activeFingerprints.has(fp);

          const namedValues: Record<string, any> = {};
          recordResult.values.forEach((v, idx) => {
            namedValues[`col_${idx + 1}`] = v;
          });

          // If not in active B-tree, row was modified or deleted!
          if (!isIdenticalInActive) {
            walRecoveredRows.push({
              tableName,
              pageNumber: frame.pageNumber,
              byteOffset: physicalWalByteOffset,
              byteLength: cellTotalLength,
              rowId,
              values: recordResult.values,
              namedValues,
              recoveryState: 'WAL_RECOVERED',
              rawHex
            });
          }
        } catch {
          // Continue to next cell in frame
        }
      }

      // Also carve unallocated freeblocks inside the WAL frame page
      let fbOffsetInPage = firstFreeblock;
      const visitedFb = new Set<number>();

      while (fbOffsetInPage > 0 && fbOffsetInPage < pageBuf.length) {
        if (visitedFb.has(fbOffsetInPage)) break;
        visitedFb.add(fbOffsetInPage);

        if (fbOffsetInPage + 4 > pageBuf.length) break;
        const nextFb = pageBuf.readUInt16BE(fbOffsetInPage);
        const fbSize = pageBuf.readUInt16BE(fbOffsetInPage + 2);

        if (fbSize >= 6 && fbOffsetInPage + fbSize <= pageBuf.length) {
          const candidateDataOffset = fbOffsetInPage + 4;
          const candidateMaxSpan = fbSize - 4;

          try {
            const pVarint = readSqliteVarint(pageBuf, candidateDataOffset);
            let pLen = Number(pVarint.value);
            let cur = candidateDataOffset + pVarint.bytesRead;

            let rowId: number | bigint = 0;
            const rVarint = readSqliteVarint(pageBuf, cur);
            if (rVarint.bytesRead > 0) {
              rowId = rVarint.value;
              cur += rVarint.bytesRead;
            }

            if (pLen > 0 && pLen <= candidateMaxSpan) {
              const rec = decodeRecordPayload(pageBuf, cur, pLen);
              if (rec.values.length >= 2) {
                const totalSpan = (cur - candidateDataOffset) + pLen;
                const physicalWalByteOffset = frame.pageDataOffset + candidateDataOffset;

                const rawHex = pageBuf.subarray(
                  candidateDataOffset,
                  Math.min(candidateDataOffset + Math.min(totalSpan, 64), pageBuf.length)
                ).toString('hex');

                const namedValues: Record<string, any> = {};
                rec.values.forEach((v, idx) => {
                  namedValues[`col_${idx + 1}`] = v;
                });

                walRecoveredRows.push({
                  tableName,
                  pageNumber: frame.pageNumber,
                  byteOffset: physicalWalByteOffset,
                  byteLength: totalSpan,
                  rowId,
                  values: rec.values,
                  namedValues,
                  recoveryState: 'WAL_RECOVERED',
                  rawHex
                });
              }
            }
          } catch {}
        }

        fbOffsetInPage = nextFb;
      }
    }

    return walRecoveredRows;
  }
}
