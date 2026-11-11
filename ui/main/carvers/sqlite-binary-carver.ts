import { readSqliteVarint, decodeRecordPayload } from './sqlite-varint';
import { RecoveryState } from '../../shared/forensic-types';

export interface SqliteDatabaseHeader {
  magic: string;
  pageSize: number;
  writeVersion: number;
  readVersion: number;
  reservedSpace: number;
  changeCounter: number;
  pageCount: number;
  firstFreelistPage: number;
  freelistPagesCount: number;
  schemaCookie: number;
  textEncoding: number;
}

export interface SqliteTableSchema {
  name: string;
  rootPage: number;
  sql: string;
  columnNames: string[];
}

export interface CarvedSqliteRow {
  tableName: string;
  pageNumber: number;
  byteOffset: number;       // Physical byte offset in source database file
  byteLength: number;       // Exact byte span of cell payload
  rowId: number | bigint;
  values: any[];
  namedValues: Record<string, any>;
  recoveryState: RecoveryState;
  rawHex: string;
}

export interface PageHeaderInfo {
  pageNumber: number;
  pageOffset: number;
  pageType: number;         // 0x02: Interior Index, 0x05: Interior Table, 0x0a: Leaf Index, 0x0d: Leaf Table
  isLeafTable: boolean;
  isInteriorTable: boolean;
  firstFreeblockOffset: number;
  cellCount: number;
  cellContentStart: number;
  fragmentedFreeBytes: number;
  rightChildPage?: number;
  headerSize: number;
}

/**
 * Binary SQLite3 Database & Unallocated Freeblock Carver.
 * Directly inspects B-Trees at the binary byte level without SQLite drivers.
 * Extracts Active rows and carves Deleted rows from freeblock chains and unallocated gaps.
 */
export class SqliteBinaryCarver {
  private header: SqliteDatabaseHeader;
  private tables: Map<string, SqliteTableSchema> = new Map();
  private rootPageToTable: Map<number, string> = new Map();

  constructor(private dbBuffer: Buffer) {
    this.header = this.parseHeader();
    this.parseSqliteMaster();
  }

  public getHeader(): SqliteDatabaseHeader {
    return this.header;
  }

  public getTables(): SqliteTableSchema[] {
    return Array.from(this.tables.values());
  }

  /**
   * 1. Parses the 100-byte SQLite database header.
   */
  private parseHeader(): SqliteDatabaseHeader {
    if (this.dbBuffer.length < 100) {
      throw new Error('[SQLITE_CARVER] Buffer smaller than 100-byte SQLite header.');
    }

    const magic = this.dbBuffer.toString('utf8', 0, 16);
    if (!magic.startsWith('SQLite format 3')) {
      throw new Error(`[SQLITE_CARVER] Invalid SQLite magic signature: "${magic}"`);
    }

    let pageSize = this.dbBuffer.readUInt16BE(16);
    if (pageSize === 1) pageSize = 65536;

    let pageCount = this.dbBuffer.readUInt32BE(28);
    if (pageCount === 0) {
      pageCount = Math.floor(this.dbBuffer.length / pageSize);
    }

    return {
      magic,
      pageSize,
      writeVersion: this.dbBuffer[18],
      readVersion: this.dbBuffer[19],
      reservedSpace: this.dbBuffer[20],
      changeCounter: this.dbBuffer.readUInt32BE(24),
      pageCount,
      firstFreelistPage: this.dbBuffer.readUInt32BE(32),
      freelistPagesCount: this.dbBuffer.readUInt32BE(36),
      schemaCookie: this.dbBuffer.readUInt32BE(40),
      textEncoding: this.dbBuffer.readUInt32BE(56)
    };
  }

  /**
   * Reads B-Tree Page Header for any page (Page 1 starts at byte 100; Pages > 1 start at byte 0).
   */
  public getPageHeader(pageNumber: number): PageHeaderInfo {
    const pageSize = this.header.pageSize;
    const pageOffset = (pageNumber - 1) * pageSize;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;
    const absOffset = pageOffset + headerStartInPage;

    if (absOffset + 8 > this.dbBuffer.length) {
      throw new Error(`[SQLITE_CARVER] Page ${pageNumber} header out of buffer bounds.`);
    }

    const pageType = this.dbBuffer[absOffset];
    const firstFreeblockOffset = this.dbBuffer.readUInt16BE(absOffset + 1);
    const cellCount = this.dbBuffer.readUInt16BE(absOffset + 3);
    let cellContentStart = this.dbBuffer.readUInt16BE(absOffset + 5);
    if (cellContentStart === 0) cellContentStart = 65536;
    const fragmentedFreeBytes = this.dbBuffer[absOffset + 7];

    const isInteriorTable = pageType === 0x05;
    const isLeafTable = pageType === 0x0d;
    let rightChildPage: number | undefined;
    const headerSize = (pageType === 0x02 || pageType === 0x05) ? 12 : 8;

    if (isInteriorTable && absOffset + 12 <= this.dbBuffer.length) {
      rightChildPage = this.dbBuffer.readUInt32BE(absOffset + 8);
    }

    return {
      pageNumber,
      pageOffset,
      pageType,
      isLeafTable,
      isInteriorTable,
      firstFreeblockOffset,
      cellCount,
      cellContentStart,
      fragmentedFreeBytes,
      rightChildPage,
      headerSize
    };
  }

  /**
   * 2. Parses sqlite_master on Page 1 to map table names to root pages and column names.
   */
  private parseSqliteMaster(): void {
    try {
      const masterRows = this.extractLeafPageActiveCells(1, 'sqlite_master');

      for (const row of masterRows) {
        // Schema of sqlite_master: type (0), name (1), tbl_name (2), rootpage (3), sql (4)
        const type = row.values[0];
        const name = row.values[1];
        const rootPage = typeof row.values[3] === 'number' ? row.values[3] : parseInt(String(row.values[3]), 10);
        const sql = typeof row.values[4] === 'string' ? row.values[4] : '';

        if (type === 'table' && name && rootPage > 0) {
          const columnNames = this.extractColumnNamesFromSql(sql);

          const schema: SqliteTableSchema = {
            name,
            rootPage,
            sql,
            columnNames
          };

          this.tables.set(name, schema);
          this.rootPageToTable.set(rootPage, name);
        }
      }
    } catch {
      // Fallback for corrupt sqlite_master
    }
  }

  /**
   * Extracts column names from CREATE TABLE SQL statements.
   */
  private extractColumnNamesFromSql(sql: string): string[] {
    if (!sql) return [];
    const match = /CREATE\s+TABLE\s+[^(\n]+\((.*)\)/is.exec(sql);
    if (!match) return [];

    const columnDefs = match[1].split(',');
    const names: string[] = [];

    for (const def of columnDefs) {
      const trimmed = def.trim();
      if (!trimmed) continue;
      const upper = trimmed.toUpperCase();
      if (
        upper.startsWith('PRIMARY') ||
        upper.startsWith('FOREIGN') ||
        upper.startsWith('CONSTRAINT') ||
        upper.startsWith('UNIQUE') ||
        upper.startsWith('CHECK')
      ) {
        continue;
      }
      const colName = trimmed.split(/\s+/)[0].replace(/["`\[\]]/g, '');
      if (colName) names.push(colName);
    }

    return names;
  }

  /**
   * 3. Walks Table Interior (0x05) and Table Leaf (0x0D) pages recursively for a table.
   */
  public walkTableBTree(rootPage: number, tableName?: string): CarvedSqliteRow[] {
    const targetTable = tableName || this.rootPageToTable.get(rootPage) || `table_page_${rootPage}`;
    const rows: CarvedSqliteRow[] = [];
    const visitedPages = new Set<number>();

    const traverse = (pageNum: number) => {
      if (pageNum <= 0 || pageNum > this.header.pageCount || visitedPages.has(pageNum)) {
        return;
      }
      visitedPages.add(pageNum);

      try {
        const pageHdr = this.getPageHeader(pageNum);

        if (pageHdr.isLeafTable) {
          // Extract Active Cells
          const active = this.extractLeafPageActiveCells(pageNum, targetTable);
          rows.push(...active);

          // Carve Deleted Rows from Freeblocks & Unallocated Gap
          const carved = this.carveLeafPageUnallocated(pageNum, targetTable);
          rows.push(...carved);
        } else if (pageHdr.isInteriorTable) {
          // Table Interior (0x05): Walk interior cells to get child pages
          const childPages = this.extractInteriorChildPages(pageHdr);
          for (const cp of childPages) {
            traverse(cp);
          }
        }
      } catch {
        // Skip corrupt page gracefully
      }
    };

    traverse(rootPage);
    return rows;
  }

  /**
   * Extracts child page numbers from a 0x05 Table Interior page.
   */
  private extractInteriorChildPages(pageHdr: PageHeaderInfo): number[] {
    const children: number[] = [];
    const pageOffset = pageHdr.pageOffset;
    const headerStartInPage = pageHdr.pageNumber === 1 ? 100 : 0;
    const cellPtrArrayOffset = pageOffset + headerStartInPage + pageHdr.headerSize;

    for (let i = 0; i < pageHdr.cellCount; i++) {
      const ptrOffset = cellPtrArrayOffset + i * 2;
      if (ptrOffset + 2 > this.dbBuffer.length) break;

      const cellOffsetInPage = this.dbBuffer.readUInt16BE(ptrOffset);
      const absCellOffset = pageOffset + cellOffsetInPage;

      if (absCellOffset + 4 <= this.dbBuffer.length) {
        const leftChildPage = this.dbBuffer.readUInt32BE(absCellOffset);
        if (leftChildPage > 0 && leftChildPage <= this.header.pageCount) {
          children.push(leftChildPage);
        }
      }
    }

    if (pageHdr.rightChildPage && pageHdr.rightChildPage <= this.header.pageCount) {
      children.push(pageHdr.rightChildPage);
    }

    return children;
  }

  /**
   * 4. Extracts all Active Cells via the Cell Pointer Array on a 0x0D Table Leaf page.
   */
  public extractLeafPageActiveCells(pageNumber: number, tableName: string): CarvedSqliteRow[] {
    const pageHdr = this.getPageHeader(pageNumber);
    if (!pageHdr.isLeafTable) return [];

    const rows: CarvedSqliteRow[] = [];
    const pageOffset = pageHdr.pageOffset;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;
    const cellPtrArrayOffset = pageOffset + headerStartInPage + pageHdr.headerSize;

    const schema = this.tables.get(tableName);
    const colNames = schema?.columnNames || [];

    for (let i = 0; i < pageHdr.cellCount; i++) {
      const ptrOffset = cellPtrArrayOffset + i * 2;
      if (ptrOffset + 2 > this.dbBuffer.length) break;

      const cellOffsetInPage = this.dbBuffer.readUInt16BE(ptrOffset);
      const absCellOffset = pageOffset + cellOffsetInPage;

      if (absCellOffset >= this.dbBuffer.length) continue;

      try {
        const payloadVarint = readSqliteVarint(this.dbBuffer, absCellOffset);
        const payloadLength = Number(payloadVarint.value);
        let cursor = absCellOffset + payloadVarint.bytesRead;

        const rowIdVarint = readSqliteVarint(this.dbBuffer, cursor);
        const rowId = rowIdVarint.value;
        cursor += rowIdVarint.bytesRead;

        const recordResult = decodeRecordPayload(this.dbBuffer, cursor, payloadLength);
        const cellTotalLength = (cursor - absCellOffset) + payloadLength;

        const namedValues: Record<string, any> = {};
        recordResult.values.forEach((val, idx) => {
          const colName = colNames[idx] || `column_${idx + 1}`;
          namedValues[colName] = val;
        });

        const rawHex = this.dbBuffer.subarray(
          absCellOffset,
          Math.min(absCellOffset + Math.min(cellTotalLength, 64), this.dbBuffer.length)
        ).toString('hex');

        rows.push({
          tableName,
          pageNumber,
          byteOffset: absCellOffset,
          byteLength: cellTotalLength,
          rowId,
          values: recordResult.values,
          namedValues,
          recoveryState: 'ACTIVE',
          rawHex
        });
      } catch {
        // Continue to next cell
      }
    }

    return rows;
  }

  /**
   * 5. Carves Deleted Records from:
   *  A. Freeblock Linked List (Bytes 1..2 of page header)
   *  B. Unallocated Cell Content Gap (between cell pointer array end and cell content start)
   */
  public carveLeafPageUnallocated(pageNumber: number, tableName: string): CarvedSqliteRow[] {
    const pageHdr = this.getPageHeader(pageNumber);
    if (!pageHdr.isLeafTable) return [];

    const carvedRows: CarvedSqliteRow[] = [];
    const pageOffset = pageHdr.pageOffset;
    const headerStartInPage = pageNumber === 1 ? 100 : 0;

    const schema = this.tables.get(tableName);
    const colNames = schema?.columnNames || [];

    // A. Carve Freeblock Linked List
    let fbOffsetInPage = pageHdr.firstFreeblockOffset;
    const visitedFreeblocks = new Set<number>();

    while (fbOffsetInPage > 0 && fbOffsetInPage < this.header.pageSize) {
      if (visitedFreeblocks.has(fbOffsetInPage)) break;
      visitedFreeblocks.add(fbOffsetInPage);

      const absFbOffset = pageOffset + fbOffsetInPage;
      if (absFbOffset + 4 > this.dbBuffer.length) break;

      const nextFbOffset = this.dbBuffer.readUInt16BE(absFbOffset);
      const fbSize = this.dbBuffer.readUInt16BE(absFbOffset + 2);

      if (fbSize >= 6 && absFbOffset + fbSize <= this.dbBuffer.length) {
        // Data payload starts after 4-byte freeblock header
        const candidate = this.scanRecordCandidate(
          absFbOffset + 4,
          fbSize - 4,
          pageNumber,
          tableName,
          colNames
        );
        if (candidate) {
          carvedRows.push(candidate);
        }
      }

      fbOffsetInPage = nextFbOffset;
    }

    // B. Carve Unallocated Cell Content Gap
    const cellPtrArrayEnd =
      pageOffset + headerStartInPage + pageHdr.headerSize + pageHdr.cellCount * 2;
    const cellContentStartAbs = pageOffset + pageHdr.cellContentStart;

    if (cellContentStartAbs > cellPtrArrayEnd) {
      const gapLength = cellContentStartAbs - cellPtrArrayEnd;

      for (let cursor = cellPtrArrayEnd; cursor < cellContentStartAbs - 6; cursor += 2) {
        const candidate = this.scanRecordCandidate(
          cursor,
          cellContentStartAbs - cursor,
          pageNumber,
          tableName,
          colNames
        );
        if (candidate && candidate.values.length >= 2) {
          carvedRows.push(candidate);
          cursor += Math.max(candidate.byteLength, 8); // Skip carved record span
        }
      }
    }

    return carvedRows;
  }

  /**
   * Scans a raw binary slice for a candidate SQLite record header and column values.
   */
  private scanRecordCandidate(
    offset: number,
    maxSpan: number,
    pageNumber: number,
    tableName: string,
    colNames: string[]
  ): CarvedSqliteRow | null {
    if (offset + 4 >= this.dbBuffer.length || maxSpan < 6) return null;

    try {
      // Check if candidate starts with a Varint payload length
      const payloadVarint = readSqliteVarint(this.dbBuffer, offset);
      let payloadLength = Number(payloadVarint.value);
      let cursor = offset + payloadVarint.bytesRead;

      // Check if candidate has a rowid varint
      let rowId: number | bigint = 0;
      const rowIdVarint = readSqliteVarint(this.dbBuffer, cursor);
      if (rowIdVarint.bytesRead > 0) {
        rowId = rowIdVarint.value;
        cursor += rowIdVarint.bytesRead;
      }

      // Sanity checks on candidate sizes
      if (payloadLength <= 0 || payloadLength > this.header.pageSize || payloadLength > maxSpan) {
        payloadLength = maxSpan;
        cursor = offset;
      }

      // Validate candidate record header size
      const headerVarint = readSqliteVarint(this.dbBuffer, cursor);
      const headerSize = Number(headerVarint.value);
      if (headerSize < 2 || headerSize > 128 || headerSize > payloadLength) {
        return null;
      }

      const recordResult = decodeRecordPayload(this.dbBuffer, cursor, payloadLength);
      if (recordResult.values.length < 2) return null;

      // Ensure candidate row is not all null or zeroes
      const nonNulls = recordResult.values.filter((v) => v !== null && v !== undefined && v !== '');
      if (nonNulls.length === 0) return null;

      const totalSpan = Math.min((cursor - offset) + payloadLength, maxSpan);
      const namedValues: Record<string, any> = {};
      recordResult.values.forEach((val, idx) => {
        const colName = colNames[idx] || `column_${idx + 1}`;
        namedValues[colName] = val;
      });

      const rawHex = this.dbBuffer.subarray(
        offset,
        Math.min(offset + Math.min(totalSpan, 64), this.dbBuffer.length)
      ).toString('hex');

      return {
        tableName,
        pageNumber,
        byteOffset: offset,
        byteLength: totalSpan,
        rowId,
        values: recordResult.values,
        namedValues,
        recoveryState: 'CARVED_UNALLOCATED',
        rawHex
      };
    } catch {
      return null;
    }
  }

  /**
   * Complete database carver: scans all tables and all database pages.
   */
  public carveEntireDatabase(): CarvedSqliteRow[] {
    const allRows: CarvedSqliteRow[] = [];

    // 1. Walk through all recognized tables from sqlite_master
    for (const schema of this.tables.values()) {
      const tableRows = this.walkTableBTree(schema.rootPage, schema.name);
      allRows.push(...tableRows);
    }

    // 2. Scan remaining unallocated pages not claimed by active tables
    const totalPages = this.header.pageCount;
    for (let p = 1; p <= totalPages; p++) {
      try {
        const pageHdr = this.getPageHeader(p);
        if (pageHdr.isLeafTable) {
          const tableName = this.rootPageToTable.get(p) || `unallocated_page_${p}`;
          const unalloc = this.carveLeafPageUnallocated(p, tableName);
          allRows.push(...unalloc);
        }
      } catch {}
    }

    return allRows;
  }
}
