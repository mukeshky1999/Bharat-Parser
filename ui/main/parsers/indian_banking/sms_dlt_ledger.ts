import {
  ForensicProvenance,
  UnifiedUPITransaction
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import {
  INDIAN_LEA_REGEX,
  extractAccountMask,
  extractAmountInr,
  extractUtrFromText,
  extractVpaFromText
} from '../../intelligence/indian_lea_regex';

/**
 * TRAI DLT Banking SMS Ledger Parser.
 * Scans Android mmssms.db / telephony.db and extracts structured banking ledgers
 * from official TRAI DLT entity headers (e.g. AD-HDFCBK, VK-SBIINB, JM-PAYTM).
 */
export class SmsDltLedgerParser {
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

    // Active records
    const activeRecords: SqliteDecodedRecord[] = [];
    for (let p = 1; p <= parser.getPageCount(); p++) {
      try {
        activeRecords.push(...parser.parseLeafTablePageCells(p));
      } catch {
        // Skip
      }
    }

    // Carved records
    const carvedRecords = freeCarver.carveAllPages();

    // WAL records
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
      if (!vals || vals.length < 3) continue;

      let address: string | null = null;
      let body: string | null = null;
      let dateVal: any = null;

      for (const val of vals) {
        if (typeof val === 'string') {
          if (!address && INDIAN_LEA_REGEX.TRAI_DLT_SENDER.test(val)) {
            address = val;
          } else if (!body && val.length > 20) {
            // Check if body contains banking keywords
            const lower = val.toLowerCase();
            if (
              lower.includes('a/c') ||
              lower.includes('debited') ||
              lower.includes('credited') ||
              lower.includes('upi') ||
              lower.includes('inr') ||
              lower.includes('rs.') ||
              lower.includes('utr')
            ) {
              body = val;
            }
          }
        } else if (typeof val === 'number') {
          if (val > 100000000000 && !dateVal) {
            dateVal = val;
          }
        }
      }

      if (body) {
        const utr = extractUtrFromText(body);
        const amount = extractAmountInr(body);
        const vpa = extractVpaFromText(body);
        const accountMask = extractAccountMask(body);

        let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
        const lowerBody = body.toLowerCase();
        if (lowerBody.includes('credited') || lowerBody.includes('received')) {
          direction = 'CREDIT';
        }

        const timestamp = normalizeTimestamp(dateVal || Date.now(), 'UNIX_MS');
        const containerType = rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : (rec.state === 'CARVED_UNALLOCATED' ? 'RAW_CARVED' : 'SQLITE');

        const provenance: ForensicProvenance = {
          evidenceId,
          archivePath,
          vfsInternalPath: rec.state === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
          containerType,
          tableName: 'sms',
          pageNumber: rec.pageNumber,
          rowId: rec.rowId,
          byteOffset: rec.byteOffset,
          byteLength: rec.byteLength,
          recoveryState: rec.state,
          rawPayloadHex: rec.rawPayloadHex
        };

        transactions.push({
          id: utr || `SMS_${address || 'BANK'}_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
          utrNumber: utr,
          appTransactionId: null,
          sourceApp: 'SMS_DLT',
          payerVpa: direction === 'DEBIT' ? null : vpa,
          payeeVpa: direction === 'CREDIT' ? null : vpa,
          accountMask,
          ifscCode: null,
          amountInr: amount || 0,
          currency: 'INR',
          direction,
          status: 'SUCCESS',
          timestamp,
          corroboratedSources: ['SMS_DLT'],
          provenance,
          notes: `TRAI DLT Sender: ${address || 'BANKING_SMS'}`
        });
      }
    }

    return transactions;
  }
}
