import { SqliteBinaryParser, SqliteDecodedRecord } from './sqlite_binary';
import { FreeblockCarver } from './freeblock_carver';

export interface WalHeader {
  magic: number;
  fileFormat: number;
  pageSize: number;
  checkpointSequence: number;
  salt1: number;
  salt2: number;
}

export interface WalFrame {
  frameIndex: number;
  frameHeaderOffset: number;
  pageDataOffset: number;
  pageNumber: number;
  dbSizeAfterCommit: number;
  pageBuffer: Buffer;
}

/**
 * SQLite Write-Ahead Log (.db-wal) Forensic Analyzer.
 * Extracts historical, deleted, and uncommitted frames with exact physical byte offsets.
 */
export class WalAnalyzer {
  private walHeader: WalHeader;
  private frames: WalFrame[] = [];

  constructor(private walBuffer: Buffer, private defaultPageSize: number = 4096) {
    this.walHeader = this.parseWalHeader();
    this.parseFrames();
  }

  public getHeader(): WalHeader {
    return this.walHeader;
  }

  public getFrames(): WalFrame[] {
    return this.frames;
  }

  private parseWalHeader(): WalHeader {
    if (this.walBuffer.length < 32) {
      throw new Error('[WAL_ANALYZER] WAL buffer is smaller than 32-byte header.');
    }

    const magic = this.walBuffer.readUInt32BE(0);
    // Magic: 0x377f0682 or 0x377f0683
    if (magic !== 0x377f0682 && magic !== 0x377f0683) {
      // In some dumps endianness might be LE (0x82067f37 or 0x83067f37)
      const magicLE = this.walBuffer.readUInt32LE(0);
      if (magicLE !== 0x377f0682 && magicLE !== 0x377f0683) {
        throw new Error(`[WAL_ANALYZER] Invalid WAL magic: 0x${magic.toString(16)}`);
      }
    }

    let pageSize = this.walBuffer.readUInt32BE(8);
    if (pageSize === 0 || pageSize > 65536) {
      pageSize = this.defaultPageSize;
    }

    return {
      magic,
      fileFormat: this.walBuffer.readUInt32BE(4),
      pageSize,
      checkpointSequence: this.walBuffer.readUInt32BE(12),
      salt1: this.walBuffer.readUInt32BE(16),
      salt2: this.walBuffer.readUInt32BE(20)
    };
  }

  private parseFrames(): void {
    const pageSize = this.walHeader.pageSize;
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
   * Recovers all records from leaf table frames inside the WAL file.
   * Maps offsets relative to the .db-wal file.
   */
  public recoverAllRecords(): SqliteDecodedRecord[] {
    const recovered: SqliteDecodedRecord[] = [];

    for (const frame of this.frames) {
      // Create a virtual page buffer to pass to the binary parser
      // Notice: page 1 in standard SQLite has 100-byte header, but in WAL frames it carries the exact raw page
      const framePageType = frame.pageBuffer[frame.pageNumber === 1 ? 100 : 0];
      if (framePageType !== 0x0d) {
        continue;
      }

      // Construct a minimal buffer containing this frame at its page position
      const synthBuf = Buffer.alloc(frame.pageNumber * this.walHeader.pageSize);
      // Copy SQLite magic if page 1
      if (frame.pageNumber === 1) {
        frame.pageBuffer.copy(synthBuf, 0);
      } else {
        // synthesize header on page 1
        Buffer.from('SQLite format 3\0').copy(synthBuf, 0);
        synthBuf.writeUInt16BE(this.walHeader.pageSize, 16);
        synthBuf[18] = 2;
        synthBuf[19] = 2;
        frame.pageBuffer.copy(synthBuf, (frame.pageNumber - 1) * this.walHeader.pageSize);
      }

      try {
        const synthParser = new SqliteBinaryParser(synthBuf);
        const cellRecords = synthParser.parseLeafTablePageCells(frame.pageNumber);

        for (const r of cellRecords) {
          // Adjust byteOffset to point into the .db-wal file
          const offsetInPage = r.byteOffset - (frame.pageNumber - 1) * this.walHeader.pageSize;
          const walByteOffset = frame.pageDataOffset + offsetInPage;

          recovered.push({
            ...r,
            byteOffset: walByteOffset,
            state: 'WAL_RECOVERED'
          });
        }

        // Also carve unallocated / freeblocks inside this WAL frame
        const freeCarver = new FreeblockCarver(synthParser, synthBuf);
        const fbCarved = freeCarver.carvePage(frame.pageNumber);
        for (const fb of fbCarved) {
          const offsetInPage = fb.byteOffset - (frame.pageNumber - 1) * this.walHeader.pageSize;
          const walByteOffset = frame.pageDataOffset + offsetInPage;
          recovered.push({
            ...fb,
            byteOffset: walByteOffset,
            state: 'WAL_RECOVERED'
          });
        }
      } catch {
        // Skip unparseable frame
      }
    }

    return recovered;
  }
}
