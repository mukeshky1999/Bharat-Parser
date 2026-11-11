import {
  ForensicProvenance,
  UnifiedUPITransaction
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import { MmkvDecoder } from '../../binary_decoders/mmkv_decoder';
import { extractAccountMask, extractUtrFromText, extractVpaFromText } from '../../intelligence/indian_lea_regex';

/**
 * Paytm Passbook & MMKV Cache Deep Parser.
 */
export class PaytmParser {
  public static parse(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    const isMmkv = vfsInternalPath.includes('mmkv') || dbBuffer.length < 100 || !dbBuffer.toString('utf8', 0, 16).startsWith('SQLite');

    if (isMmkv) {
      // Decode as MMKV
      const entries = MmkvDecoder.decode(dbBuffer);
      for (const entry of entries) {
        const valStr = typeof entry.value === 'object' ? JSON.stringify(entry.value) : String(entry.value);
        const utr = extractUtrFromText(valStr);
        const vpa = extractVpaFromText(valStr);
        const mask = extractAccountMask(valStr);

        if (utr || vpa) {
          transactions.push({
            id: utr || `PAYTM_MMKV_${entry.key}`,
            utrNumber: utr,
            appTransactionId: entry.key,
            sourceApp: 'Paytm',
            payerVpa: null,
            payeeVpa: vpa,
            accountMask: mask,
            ifscCode: null,
            amountInr: 0,
            currency: 'INR',
            direction: 'DEBIT',
            status: 'SUCCESS',
            timestamp: normalizeTimestamp(Date.now(), 'UNIX_MS'),
            corroboratedSources: ['APP_DB'],
            provenance: {
              evidenceId,
              archivePath,
              vfsInternalPath,
              containerType: 'MMKV',
              byteOffset: 0,
              byteLength: dbBuffer.length,
              recoveryState: 'ACTIVE',
              rawPayloadHex: entry.rawValueHex
            }
          });
        }
      }
      return transactions;
    }

    // Decode as SQLite
    const parser = new SqliteBinaryParser(dbBuffer);
    const freeCarver = new FreeblockCarver(parser, dbBuffer);

    const activeRecords: SqliteDecodedRecord[] = [];
    for (let p = 1; p <= parser.getPageCount(); p++) {
      try {
        activeRecords.push(...parser.parseLeafTablePageCells(p));
      } catch {
        // Skip
      }
    }

    const carvedRecords = freeCarver.carveAllPages();
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

    for (const rec of allRecords) {
      const vals = rec.values;
      if (!vals || vals.length < 2) continue;

      let utr: string | null = null;
      let orderId: string | null = null;
      let vpa: string | null = null;
      let amount = 0;
      let dateVal: any = null;
      let mask: string | null = null;
      let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';

      for (const val of vals) {
        if (typeof val === 'string') {
          if (!utr) utr = extractUtrFromText(val);
          if (!vpa) vpa = extractVpaFromText(val);
          if (!mask) mask = extractAccountMask(val);
          if (val.length >= 10 && /^\d+$/.test(val) && !orderId) orderId = val;
          if (val.toLowerCase().includes('cr') || val.toLowerCase().includes('received')) direction = 'CREDIT';
        } else if (typeof val === 'number') {
          if (val > 100000000000 && !dateVal) dateVal = val;
          else if (val > 0 && val < 5000000 && amount === 0) amount = val;
        }
      }

      if (utr || vpa || (amount > 0 && orderId)) {
        transactions.push({
          id: utr || orderId || `PAYTM_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
          utrNumber: utr,
          appTransactionId: orderId,
          sourceApp: 'Paytm',
          payerVpa: null,
          payeeVpa: vpa,
          accountMask: mask,
          ifscCode: null,
          amountInr: amount,
          currency: 'INR',
          direction,
          status: 'SUCCESS',
          timestamp: normalizeTimestamp(dateVal || Date.now(), 'UNIX_MS'),
          corroboratedSources: [rec.state === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
          provenance: {
            evidenceId,
            archivePath,
            vfsInternalPath: rec.state === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
            containerType: rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
            tableName: 'passbook',
            pageNumber: rec.pageNumber,
            rowId: rec.rowId,
            byteOffset: rec.byteOffset,
            byteLength: rec.byteLength,
            recoveryState: rec.state,
            rawPayloadHex: rec.rawPayloadHex
          }
        });
      }
    }

    return transactions;
  }
}
