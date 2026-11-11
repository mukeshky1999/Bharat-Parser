import {
  ForensicProvenance,
  UnifiedUPITransaction
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import {
  extractAccountMask,
  extractAmountInr,
  extractUtrFromText,
  extractVpaFromText
} from '../../intelligence/indian_lea_regex';

/**
 * Android Notification Log Spillover Parser.
 * Recovers deleted payment and banking alerts from system notification_log.db.
 */
export class NotifSpilloverParser {
  public static parse(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
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

      let pkg: string | null = null;
      let textContent = '';
      let dateVal: any = null;

      for (const val of vals) {
        if (typeof val === 'string') {
          if (!pkg && (val.includes('phonepe') || val.includes('paisa') || val.includes('paytm') || val.includes('bhim') || val.includes('sbi') || val.includes('hdfc'))) {
            pkg = val;
          }
          if (val.length > 10) {
            textContent += ' ' + val;
          }
        } else if (typeof val === 'number') {
          if (val > 100000000000 && !dateVal) {
            dateVal = val;
          }
        }
      }

      const utr = extractUtrFromText(textContent);
      const amount = extractAmountInr(textContent);
      const vpa = extractVpaFromText(textContent);
      const mask = extractAccountMask(textContent);

      if (utr || amount || vpa) {
        let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
        const lower = textContent.toLowerCase();
        if (lower.includes('credited') || lower.includes('received')) direction = 'CREDIT';

        transactions.push({
          id: utr || `NOTIF_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
          utrNumber: utr,
          appTransactionId: null,
          sourceApp: 'Notif_Log',
          payerVpa: direction === 'DEBIT' ? null : vpa,
          payeeVpa: direction === 'CREDIT' ? null : vpa,
          accountMask: mask,
          ifscCode: null,
          amountInr: amount || 0,
          currency: 'INR',
          direction,
          status: 'SUCCESS',
          timestamp: normalizeTimestamp(dateVal || Date.now(), 'UNIX_MS'),
          corroboratedSources: ['NOTIFICATION_LOG'],
          provenance: {
            evidenceId,
            archivePath,
            vfsInternalPath: rec.state === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
            containerType: rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
            tableName: 'notifications',
            pageNumber: rec.pageNumber,
            rowId: rec.rowId,
            byteOffset: rec.byteOffset,
            byteLength: rec.byteLength,
            recoveryState: rec.state,
            rawPayloadHex: rec.rawPayloadHex
          },
          notes: `Push Notification from package: ${pkg || 'unknown'}`
        });
      }
    }

    return transactions;
  }
}
