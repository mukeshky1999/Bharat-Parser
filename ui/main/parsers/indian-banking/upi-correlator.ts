import {
  ForensicProvenance,
  UnifiedUPITransaction,
  normalizeTimestamp
} from '../../../shared/forensic-types';
import { SqliteBinaryCarver, CarvedSqliteRow } from '../../carvers/sqlite-binary-carver';
import { WalCarver } from '../../carvers/wal-carver';
import {
  INDIAN_LEA_REGEX,
  extractAccountMask,
  extractAmountInr,
  extractUtrFromText,
  extractVpaFromText
} from '../../intelligence/indian_lea_regex';

/**
 * TRAI DLT Indian Banking SMS & OS Notification Spillover Deep Parser,
 * integrated with the Cross-Artifact Deduplication and Fusion Engine.
 */
export class IndianBankingCorrelator {
  // ==========================================================================
  // 1. TRAI DLT SMS Banking Parser (mmssms.db / bugle_db)
  // ==========================================================================

  /**
   * Ingests Android mmssms.db, telephony.db, or Google Messages bugle_db.
   * Extracts banking ledgers by matching TRAI DLT 6-character sender headers
   * (e.g. VM-SBIINB, AD-HDFCBK, AX-ICICIB, VK-AXISBK, JM-PAYTM, CP-KOTAKB).
   */
  public static parseSmsDltDatabase(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    if (dbBuffer.length < 100) return transactions;

    try {
      const carver = new SqliteBinaryCarver(dbBuffer);
      const rows = carver.carveEntireDatabase();

      let walRows: CarvedSqliteRow[] = [];
      if (walBuffer && walBuffer.length > 32) {
        try {
          const walCarver = new WalCarver(walBuffer, carver.getHeader().pageSize, rows);
          walRows = walCarver.carveAllWalRows('sms_wal');
        } catch {}
      }

      for (const row of [...rows, ...walRows]) {
        const tx = IndianBankingCorrelator.mapSmsRow(row, evidenceId, archivePath, vfsInternalPath);
        if (tx) transactions.push(tx);
      }
    } catch {}

    return transactions;
  }

  private static mapSmsRow(
    row: CarvedSqliteRow,
    evidenceId: string,
    archivePath: string,
    vfsPath: string
  ): UnifiedUPITransaction | null {
    const vals = row.values;
    if (!vals || vals.length < 2) return null;

    let address: string | null = null;
    let body: string | null = null;
    let rawDateVal: any = null;

    for (const val of vals) {
      if (typeof val === 'string') {
        const trimmed = val.trim();
        // Check for TRAI DLT sender pattern (e.g. "AD-HDFCBK", "VM-SBIINB")
        if (!address && INDIAN_LEA_REGEX.TRAI_DLT_SENDER.test(trimmed)) {
          address = trimmed;
        } else if (!body && trimmed.length > 15) {
          const lower = trimmed.toLowerCase();
          if (
            lower.includes('a/c') ||
            lower.includes('debited') ||
            lower.includes('credited') ||
            lower.includes('upi') ||
            lower.includes('inr') ||
            lower.includes('rs.') ||
            lower.includes('utr') ||
            lower.includes('ref no')
          ) {
            body = trimmed;
          }
        }
      } else if (typeof val === 'number') {
        if (val > 100000000000 && !rawDateVal) {
          rawDateVal = val;
        }
      }
    }

    if (!body) return null;

    const utr = extractUtrFromText(body);
    const amount = extractAmountInr(body);
    const vpa = extractVpaFromText(body);
    const accountMask = extractAccountMask(body);

    let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
    const lowerBody = body.toLowerCase();
    if (lowerBody.includes('credited') || lowerBody.includes('received') || lowerBody.includes('deposited')) {
      direction = 'CREDIT';
    }

    const timestamp = normalizeTimestamp(rawDateVal || Date.now(), 'UNIX_MS');

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsPath}-wal` : vfsPath,
      containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
      tableName: row.tableName || 'sms',
      pageNumber: row.pageNumber,
      rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
      byteOffset: row.byteOffset,
      byteLength: row.byteLength,
      recoveryState: row.recoveryState,
      rawPayloadHex: row.rawHex
    };

    return {
      id: utr || `SMS_${address || 'BANK'}_${row.pageNumber}_${row.byteOffset.toString(16)}`,
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
    };
  }

  // ==========================================================================
  // 2. Android Notification Log Spillover Parser
  // ==========================================================================

  /**
   * Ingests Android notification_log.db or system notification records.
   */
  public static parseNotificationLogDatabase(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    if (dbBuffer.length < 100) return transactions;

    try {
      const carver = new SqliteBinaryCarver(dbBuffer);
      const rows = carver.carveEntireDatabase();

      let walRows: CarvedSqliteRow[] = [];
      if (walBuffer && walBuffer.length > 32) {
        try {
          const walCarver = new WalCarver(walBuffer, carver.getHeader().pageSize, rows);
          walRows = walCarver.carveAllWalRows('notif_wal');
        } catch {}
      }

      for (const row of [...rows, ...walRows]) {
        const vals = row.values;
        if (!vals || vals.length < 2) continue;

        let pkgName: string | null = null;
        let notifText: string | null = null;
        let dateVal: any = null;

        for (const val of vals) {
          if (typeof val === 'string') {
            const trimmed = val.trim();
            if (trimmed.includes('phonepe') || trimmed.includes('paisa') || trimmed.includes('paytm') || trimmed.includes('npci')) {
              pkgName = trimmed;
            } else if (trimmed.length > 15) {
              const lower = trimmed.toLowerCase();
              if (
                lower.includes('paid') ||
                lower.includes('received') ||
                lower.includes('sent') ||
                lower.includes('rs.') ||
                lower.includes('inr') ||
                lower.includes('transferred')
              ) {
                notifText = trimmed;
              }
            }
          } else if (typeof val === 'number') {
            if (val > 100000000000 && !dateVal) dateVal = val;
          }
        }

        if (notifText) {
          const utr = extractUtrFromText(notifText);
          const amount = extractAmountInr(notifText);
          const vpa = extractVpaFromText(notifText);
          const accountMask = extractAccountMask(notifText);

          let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
          if (notifText.toLowerCase().includes('received') || notifText.toLowerCase().includes('credited')) {
            direction = 'CREDIT';
          }

          transactions.push({
            id: utr || `NOTIF_${row.pageNumber}_${row.byteOffset.toString(16)}`,
            utrNumber: utr,
            appTransactionId: null,
            sourceApp: 'Notif_Log',
            payerVpa: direction === 'DEBIT' ? null : vpa,
            payeeVpa: direction === 'CREDIT' ? null : vpa,
            accountMask,
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
              vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
              containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
              tableName: row.tableName || 'notification_log',
              pageNumber: row.pageNumber,
              rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
              byteOffset: row.byteOffset,
              byteLength: row.byteLength,
              recoveryState: row.recoveryState,
              rawPayloadHex: row.rawHex
            },
            notes: `Notification spillover from package: ${pkgName || 'SYSTEM'}`
          });
        }
      }
    } catch {}

    return transactions;
  }

  // ==========================================================================
  // 3. Cross-Artifact Deduplication & Merge Engine
  // ==========================================================================

  /**
   * Cross-Artifact Deduplication & Merge Engine.
   * Links App DB rows, WAL-carved rows, DLT SMS alerts, and Notification logs:
   * 1. Primary matching key: 12-digit NPCI UTR / RRN.
   * 2. Secondary matching key: Proximity matching within 60-second window AND identical amount.
   * Merges all metadata, fuses corroboration source tags, and preserves provenance.
   */
  public static correlateAndFuse(allTransactions: UnifiedUPITransaction[]): UnifiedUPITransaction[] {
    const utrMap = new Map<string, UnifiedUPITransaction>();
    const nonUtrList: UnifiedUPITransaction[] = [];

    // Phase 1: Group and fuse by 12-digit UTR
    for (const tx of allTransactions) {
      if (tx.utrNumber && tx.utrNumber.length === 12) {
        if (!utrMap.has(tx.utrNumber)) {
          utrMap.set(tx.utrNumber, {
            ...tx,
            corroboratedSources: [...tx.corroboratedSources]
          });
        } else {
          const existing = utrMap.get(tx.utrNumber)!;
          IndianBankingCorrelator.fuseTransactions(existing, tx);
        }
      } else {
        nonUtrList.push({
          ...tx,
          corroboratedSources: [...tx.corroboratedSources]
        });
      }
    }

    // Phase 2: Correlate non-UTR transactions by 60-second timestamp window and exact amount
    const masterList = Array.from(utrMap.values());
    const remainingUncorrelated: UnifiedUPITransaction[] = [];

    for (const nonUtr of nonUtrList) {
      let matched = false;
      // 1. Check against master UTR transactions
      for (const master of masterList) {
        if (
          master.amountInr > 0 &&
          nonUtr.amountInr > 0 &&
          Math.abs(master.amountInr - nonUtr.amountInr) < 0.01 &&
          Math.abs(master.timestamp.epochMs - nonUtr.timestamp.epochMs) <= 60000
        ) {
          IndianBankingCorrelator.fuseTransactions(master, nonUtr);
          matched = true;
          break;
        }
      }

      // 2. If no UTR master matched, check against other non-UTR entries
      if (!matched) {
        for (const uncorr of remainingUncorrelated) {
          if (
            uncorr.amountInr > 0 &&
            nonUtr.amountInr > 0 &&
            Math.abs(uncorr.amountInr - nonUtr.amountInr) < 0.01 &&
            Math.abs(uncorr.timestamp.epochMs - nonUtr.timestamp.epochMs) <= 60000
          ) {
            IndianBankingCorrelator.fuseTransactions(uncorr, nonUtr);
            matched = true;
            break;
          }
        }
      }

      if (!matched) {
        remainingUncorrelated.push(nonUtr);
      }
    }

    // Sort all master records by timestamp descending
    const combined = [...masterList, ...remainingUncorrelated];
    combined.sort((a, b) => b.timestamp.epochMs - a.timestamp.epochMs);

    return combined;
  }

  private static fuseTransactions(master: UnifiedUPITransaction, incoming: UnifiedUPITransaction): void {
    // 1. Fuse corroborated sources
    for (const src of incoming.corroboratedSources) {
      if (!master.corroboratedSources.includes(src)) {
        master.corroboratedSources.push(src);
      }
    }

    // 2. Fuse VPAs
    if (!master.payeeVpa && incoming.payeeVpa) master.payeeVpa = incoming.payeeVpa;
    if (!master.payerVpa && incoming.payerVpa) master.payerVpa = incoming.payerVpa;

    // 3. Fuse Account Mask & IFSC
    if (!master.accountMask && incoming.accountMask) master.accountMask = incoming.accountMask;
    if (!master.ifscCode && incoming.ifscCode) master.ifscCode = incoming.ifscCode;

    // 4. Fuse Tx IDs
    if (!master.appTransactionId && incoming.appTransactionId) master.appTransactionId = incoming.appTransactionId;
    if (!master.utrNumber && incoming.utrNumber) master.utrNumber = incoming.utrNumber;

    // 5. Fuse Amount & Status
    if (master.amountInr === 0 && incoming.amountInr > 0) master.amountInr = incoming.amountInr;

    // 6. Propagate Embedded TxID Timestamp & Clock Tamper Detection
    if (!master.embeddedIdTimestamp && incoming.embeddedIdTimestamp) {
      master.embeddedIdTimestamp = incoming.embeddedIdTimestamp;
      master.clockTamperDetected = incoming.clockTamperDetected;
    }

    // 7. Upgrade sourceApp & provenance if incoming is an App DB with exact B-Tree page offset
    if (
      (master.sourceApp === 'SMS_DLT' || master.sourceApp === 'Notif_Log') &&
      incoming.sourceApp !== 'SMS_DLT' &&
      incoming.sourceApp !== 'Notif_Log'
    ) {
      master.sourceApp = incoming.sourceApp;
      if (incoming.provenance.pageNumber) {
        master.provenance = incoming.provenance;
      }
    }
  }
}

// Convenience export alias for backwards compatibility
export const UpiCorrelator = IndianBankingCorrelator;
