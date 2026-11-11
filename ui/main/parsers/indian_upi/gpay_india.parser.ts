import {
  ForensicProvenance,
  UnifiedUPITransaction
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import { ProtobufDecoder } from '../../binary_decoders/protobuf_decoder';
import { extractAccountMask, extractUtrFromText, extractVpaFromText } from '../../intelligence/indian_lea_regex';

/**
 * Google Pay India (Tez / paisa.db) Parser.
 * Decodes SQLite tables and parses nested Protobuf payment payloads.
 */
export class GPayIndiaParser {
  public static parse(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    const parser = new SqliteBinaryParser(dbBuffer);
    const freeblockCarver = new FreeblockCarver(parser, dbBuffer);

    // Active
    const pageCount = parser.getPageCount();
    const activeRecords: SqliteDecodedRecord[] = [];
    for (let p = 1; p <= pageCount; p++) {
      try {
        activeRecords.push(...parser.parseLeafTablePageCells(p));
      } catch {
        // Skip
      }
    }

    // Carved
    const carvedRecords = freeblockCarver.carveAllPages();

    // WAL
    let walRecords: SqliteDecodedRecord[] = [];
    if (walBuffer && walBuffer.length > 32) {
      try {
        const walAnalyzer = new WalAnalyzer(walBuffer, parser.getFileHeader().pageSize);
        walRecords = walAnalyzer.recoverAllRecords();
      } catch {
        // Skip
      }
    }

    const allRecords = [...activeRecords, ...walRecords, ...carvedRecords];

    for (const record of allRecords) {
      const tx = GPayIndiaParser.mapRecordToTransaction(
        record,
        evidenceId,
        archivePath,
        record.state === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath
      );
      if (tx) {
        transactions.push(tx);
      }
    }

    return transactions;
  }

  private static mapRecordToTransaction(
    rec: SqliteDecodedRecord,
    evidenceId: string,
    archivePath: string,
    vfsPath: string
  ): UnifiedUPITransaction | null {
    const vals = rec.values;
    if (!vals || vals.length === 0) return null;

    let appTxId: string | null = null;
    let utrNumber: string | null = null;
    let payerVpa: string | null = null;
    let payeeVpa: string | null = null;
    let amountInr = 0;
    let rawDateVal: any = null;
    let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
    let status: 'SUCCESS' | 'FAILED' | 'PENDING' | 'ABANDONED_INTENT' = 'SUCCESS';
    let accountMask: string | null = null;
    let notes: string | undefined;

    // Check values and parse Protobuf blobs
    for (const val of vals) {
      if (Buffer.isBuffer(val) && val.length > 4) {
        try {
          const protoFields = ProtobufDecoder.decode(val);
          for (const f of protoFields) {
            if (typeof f.value === 'string') {
              if (!appTxId && f.value.startsWith('CICAg')) appTxId = f.value;
              if (!utrNumber) {
                const u = extractUtrFromText(f.value);
                if (u && u !== appTxId) utrNumber = u;
              }
              const v = extractVpaFromText(f.value);
              if (v) {
                if (!payeeVpa) payeeVpa = v;
                else if (!payerVpa && v !== payeeVpa) payerVpa = v;
              }
            } else if (typeof f.value === 'number') {
              if (f.value > 1000000000000) {
                // Microseconds or Milliseconds
                rawDateVal = f.value > 1000000000000000 ? Math.floor(f.value / 1000) : f.value;
              } else if (f.value > 0 && amountInr === 0) {
                // In GPay Protobuf, amounts are often in micros (10^6)
                if (f.value >= 1000000) {
                  amountInr = f.value / 1000000;
                } else if (f.value >= 100 && f.value % 10 === 0) {
                  amountInr = f.value / 100;
                } else {
                  amountInr = f.value;
                }
              }
            }
          }
        } catch {
          // Skip corrupt protobuf
        }
      } else if (typeof val === 'string') {
        if (!appTxId && val.startsWith('CICAg')) appTxId = val;
        if (!utrNumber) {
          const u = extractUtrFromText(val);
          if (u && u !== appTxId) utrNumber = u;
        }
        if (!payeeVpa || !payerVpa) {
          const v = extractVpaFromText(val);
          if (v) {
            if (!payeeVpa) payeeVpa = v;
            else if (!payerVpa && v !== payeeVpa) payerVpa = v;
          }
        }
        if (!accountMask) {
          const acc = extractAccountMask(val);
          if (acc) accountMask = acc;
        }
        const lower = val.toLowerCase();
        if (lower.includes('credit') || lower.includes('received')) direction = 'CREDIT';
        if (lower.includes('failed')) status = 'FAILED';
      } else if (typeof val === 'number') {
        if (val > 100000000000 && !rawDateVal) {
          rawDateVal = val;
        } else if (val > 0 && val < 5000000 && amountInr === 0) {
          amountInr = val >= 100 && val % 10 === 0 ? val / 100 : val;
        }
      }
    }

    if (!appTxId && !utrNumber && !payeeVpa && amountInr === 0) {
      return null;
    }

    const timestamp = normalizeTimestamp(rawDateVal || Date.now(), 'UNIX_MS');
    const containerType = rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : (rec.state === 'CARVED_UNALLOCATED' ? 'RAW_CARVED' : 'PROTOBUF');

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: vfsPath,
      containerType,
      tableName: 'paisa_events',
      pageNumber: rec.pageNumber,
      rowId: rec.rowId,
      byteOffset: rec.byteOffset,
      byteLength: rec.byteLength,
      recoveryState: rec.state,
      rawPayloadHex: rec.rawPayloadHex
    };

    return {
      id: appTxId || utrNumber || `GPAY_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
      utrNumber,
      appTransactionId: appTxId,
      sourceApp: 'GPay',
      payerVpa,
      payeeVpa,
      accountMask,
      ifscCode: null,
      amountInr,
      currency: 'INR',
      direction,
      status,
      timestamp,
      corroboratedSources: [rec.state === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
      provenance,
      notes
    };
  }
}
