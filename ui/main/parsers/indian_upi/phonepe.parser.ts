import {
  ForensicProvenance,
  UnifiedUPITransaction
} from '../../../shared/forensic-types';
import { normalizeTimestamp, detectClockTampering } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import { extractAccountMask, extractUtrFromText, extractVpaFromText } from '../../intelligence/indian_lea_regex';

/**
 * PhonePe Deep Artifact Parser.
 * Ingests TransactionsStore.sqlite, foxtrot.db, and .db-wal files.
 * Recovers Active, WAL-recovered, and Carved unallocated transactions.
 * Extracts embedded TxID timestamps and detects device clock tampering.
 */
export class PhonePeParser {
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

    // 1. Parse Active Leaf Table records
    const pageCount = parser.getPageCount();
    const activeRecords: SqliteDecodedRecord[] = [];

    for (let p = 1; p <= pageCount; p++) {
      try {
        const cells = parser.parseLeafTablePageCells(p);
        activeRecords.push(...cells);
      } catch {
        // Skip unparseable page
      }
    }

    // 2. Carve Freeblocks & Unallocated space from main DB
    const carvedRecords = freeblockCarver.carveAllPages();

    // 3. Parse WAL frames if available
    let walRecords: SqliteDecodedRecord[] = [];
    if (walBuffer && walBuffer.length > 32) {
      try {
        const walAnalyzer = new WalAnalyzer(walBuffer, parser.getFileHeader().pageSize);
        walRecords = walAnalyzer.recoverAllRecords();
      } catch {
        // Continue with active & carved
      }
    }

    const allRecords = [...activeRecords, ...walRecords, ...carvedRecords];

    for (const record of allRecords) {
      const tx = PhonePeParser.mapRecordToTransaction(
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
    if (!vals || vals.length < 3) return null;

    // Search for PhonePe TxID or UTR pattern inside column values
    let appTxId: string | null = null;
    let utrNumber: string | null = null;
    let payerVpa: string | null = null;
    let payeeVpa: string | null = null;
    let amountInr = 0;
    let rawDateVal: any = null;
    let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
    let status: 'SUCCESS' | 'FAILED' | 'PENDING' | 'ABANDONED_INTENT' = 'SUCCESS';
    let accountMask: string | null = null;

    for (const val of vals) {
      if (typeof val === 'string') {
        if (!appTxId && (val.startsWith('T2') || val.startsWith('T1') || val.startsWith('P2')) && val.length >= 13) {
          appTxId = val;
        }
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
        if (lower.includes('credit') || lower.includes('received')) {
          direction = 'CREDIT';
        } else if (lower.includes('collect') || lower.includes('request')) {
          direction = 'COLLECT_REQUEST';
        } else if (lower.includes('intent_abandoned') || lower.includes('ghost')) {
          direction = 'GHOST_INTENT';
          status = 'ABANDONED_INTENT';
        }

        if (lower.includes('failed') || lower.includes('declined')) {
          status = 'FAILED';
        } else if (lower.includes('pending') || lower.includes('in_progress')) {
          status = 'PENDING';
        }
      } else if (typeof val === 'number') {
        if (val > 100000000000 && val < 2500000000000) {
          if (!rawDateVal) rawDateVal = val;
        } else if (val > 0 && val < 10000000 && amountInr === 0) {
          // Check if value is in paise (>= 100) or rupees
          amountInr = val >= 100 && Number.isInteger(val) && val % 10 === 0 ? val / 100 : val;
        }
      }
    }

    // Must have at least an amount, a TxID, a UTR, or a VPA to qualify as a valid transaction
    if (!appTxId && !utrNumber && !payeeVpa && amountInr === 0) {
      return null;
    }

    const timestamp = normalizeTimestamp(rawDateVal || Date.now(), 'UNIX_MS');

    let embeddedIdTimestamp;
    let clockTamperDetected = false;

    if (appTxId && appTxId.startsWith('T') && appTxId.length >= 13) {
      embeddedIdTimestamp = normalizeTimestamp(appTxId, 'PHONEPE_TXID');
      clockTamperDetected = detectClockTampering(timestamp, embeddedIdTimestamp);
    }

    const containerType = rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : (rec.state === 'CARVED_UNALLOCATED' ? 'RAW_CARVED' : 'SQLITE');

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: vfsPath,
      containerType,
      tableName: 'transactions',
      pageNumber: rec.pageNumber,
      rowId: rec.rowId,
      byteOffset: rec.byteOffset,
      byteLength: rec.byteLength,
      recoveryState: rec.state,
      rawPayloadHex: rec.rawPayloadHex
    };

    return {
      id: appTxId || utrNumber || `PHONEPE_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
      utrNumber,
      appTransactionId: appTxId,
      sourceApp: 'PhonePe',
      payerVpa,
      payeeVpa,
      accountMask,
      ifscCode: null,
      amountInr,
      currency: 'INR',
      direction,
      status,
      timestamp,
      embeddedIdTimestamp,
      clockTamperDetected,
      corroboratedSources: [rec.state === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
      provenance
    };
  }
}
