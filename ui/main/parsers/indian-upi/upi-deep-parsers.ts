import {
  ForensicProvenance,
  UnifiedUPITransaction,
  RecoveryState,
  normalizeTimestamp,
  detectClockTampering
} from '../../../shared/forensic-types';
import { SqliteBinaryCarver, CarvedSqliteRow } from '../../carvers/sqlite-binary-carver';
import { WalCarver } from '../../carvers/wal-carver';
import {
  extractAccountMask,
  extractAmountInr,
  extractUtrFromText,
  extractVpaFromText,
  INDIAN_LEA_REGEX
} from '../../intelligence/indian_lea_regex';

// ============================================================================
// 1. Raw Schema-less Protobuf Wire Decoder
// ============================================================================

export interface ProtobufField {
  tag: number;
  wireType: number;
  value: any;
  rawBytes?: Buffer;
}

/**
 * Universal Protobuf Wire Format Decoder.
 * Decodes binary protobuf blobs into structured fields by parsing:
 * - Varint (wireType === 0)
 * - 64-bit fixed (wireType === 1)
 * - Length-delimited (wireType === 2) - recurses into embedded messages
 * - 32-bit fixed (wireType === 5)
 */
export function decodeProtobufWire(buf: Buffer): ProtobufField[] {
  const fields: ProtobufField[] = [];
  let offset = 0;

  const readVarint = (buffer: Buffer, startOffset: number): { value: number | bigint; bytesRead: number } => {
    let result = 0n;
    let bytesRead = 0;
    for (let i = 0; i < 10; i++) {
      if (startOffset + i >= buffer.length) break;
      const b = BigInt(buffer[startOffset + i]);
      bytesRead++;
      result |= (b & 0x7fn) << BigInt(7 * i);
      if ((b & 0x80n) === 0n) {
        const num = Number(result);
        return { value: Number.isSafeInteger(num) ? num : result, bytesRead };
      }
    }
    return { value: 0, bytesRead: 0 };
  };

  while (offset < buf.length) {
    const keyVarint = readVarint(buf, offset);
    if (keyVarint.bytesRead === 0 || offset + keyVarint.bytesRead > buf.length) break;

    const key = typeof keyVarint.value === 'bigint' ? Number(keyVarint.value) : keyVarint.value;
    offset += keyVarint.bytesRead;

    const tag = key >>> 3;
    const wireType = key & 0x07;

    if (tag === 0 || tag > 536870911) break;

    if (wireType === 0) {
      // Varint
      const valVarint = readVarint(buf, offset);
      fields.push({ tag, wireType, value: valVarint.value });
      offset += valVarint.bytesRead;
    } else if (wireType === 1) {
      // 64-bit fixed (double / uint64)
      if (offset + 8 > buf.length) break;
      const dbl = buf.readDoubleLE(offset);
      const raw = buf.subarray(offset, offset + 8);
      fields.push({ tag, wireType, value: dbl, rawBytes: raw });
      offset += 8;
    } else if (wireType === 2) {
      // Length-delimited (sub-message, string, or byte array)
      const lenVarint = readVarint(buf, offset);
      offset += lenVarint.bytesRead;
      const length = typeof lenVarint.value === 'bigint' ? Number(lenVarint.value) : lenVarint.value;

      if (offset + length > buf.length || length < 0) break;
      const slice = buf.subarray(offset, offset + length);
      offset += length;

      // Probe if slice is printable text first before attempting sub-message decoding
      const str = slice.toString('utf8');
      const isPrintable = /^[\x20-\x7E]*$/.test(str) && str.length > 0;

      if (isPrintable) {
        fields.push({
          tag,
          wireType,
          value: str,
          rawBytes: slice
        });
      } else if (slice.length >= 2) {
        // Probe if slice can be decoded as an embedded Protobuf sub-message
        let isSubMessage = false;
        try {
          const sub = decodeProtobufWire(slice);
          if (sub.length > 0) {
            fields.push({ tag, wireType, value: sub, rawBytes: slice });
            isSubMessage = true;
          }
        } catch {
          isSubMessage = false;
        }

        if (!isSubMessage) {
          fields.push({
            tag,
            wireType,
            value: slice.toString('hex'),
            rawBytes: slice
          });
        }
      } else {
        fields.push({
          tag,
          wireType,
          value: slice.toString('hex'),
          rawBytes: slice
        });
      }
    } else if (wireType === 5) {
      // 32-bit fixed (float / uint32)
      if (offset + 4 > buf.length) break;
      const flt = buf.readFloatLE(offset);
      const raw = buf.subarray(offset, offset + 4);
      fields.push({ tag, wireType, value: flt, rawBytes: raw });
      offset += 4;
    } else {
      // Wire types 3 and 4 are deprecated groups, stop if encountered
      break;
    }
  }

  return fields;
}

/**
 * Recursively searches Protobuf field tree for string/numeric values matching criteria.
 */
function walkProtobufValues(fields: ProtobufField[], visitor: (val: any) => void): void {
  for (const f of fields) {
    if (Array.isArray(f.value)) {
      walkProtobufValues(f.value, visitor);
    } else {
      visitor(f.value);
    }
  }
}

// ============================================================================
// 2. PhonePe Deep Parser (com.phonepe.app)
// ============================================================================

export class PhonePeDeepParser {
  /**
   * Ingests TransactionsStore.sqlite, core.db, and FoxtrotEventsDB.sqlite
   * (both active B-Trees and unallocated/WAL frames).
   */
  public static parse(
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
      const activeAndCarvedRows = carver.carveEntireDatabase();

      let walRows: CarvedSqliteRow[] = [];
      if (walBuffer && walBuffer.length > 32) {
        try {
          const walCarver = new WalCarver(walBuffer, carver.getHeader().pageSize, activeAndCarvedRows);
          walRows = walCarver.carveAllWalRows('phonepe_wal');
        } catch {
          // Continue with available rows
        }
      }

      const allRows = [...activeAndCarvedRows, ...walRows];
      const lowerPath = vfsInternalPath.toLowerCase();
      const isFoxtrot = lowerPath.includes('foxtrot');
      const isCore = lowerPath.includes('core.db');

      for (const row of allRows) {
        const tx = PhonePeDeepParser.mapRowToTransaction(
          row,
          evidenceId,
          archivePath,
          vfsInternalPath,
          isFoxtrot,
          isCore
        );
        if (tx) {
          transactions.push(tx);
        }
      }
    } catch {
      // Fallback for truncated database
    }

    return transactions;
  }

  private static mapRowToTransaction(
    row: CarvedSqliteRow,
    evidenceId: string,
    archivePath: string,
    vfsPath: string,
    isFoxtrot: boolean,
    isCore: boolean
  ): UnifiedUPITransaction | null {
    const vals = row.values;
    if (!vals || vals.length < 2) return null;

    let appTxId: string | null = null;
    let utrNumber: string | null = null;
    let payerVpa: string | null = null;
    let payeeVpa: string | null = null;
    let accountMask: string | null = null;
    let ifscCode: string | null = null;
    let amountInr = 0;
    let rawDateVal: any = null;
    let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
    let status: 'SUCCESS' | 'FAILED' | 'PENDING' | 'ABANDONED_INTENT' = 'SUCCESS';
    let isDelinkedAccount = false;

    // Scan values
    for (const val of vals) {
      if (typeof val === 'string') {
        const trimmed = val.trim();

        // 1. PhonePe TxID Pattern check (T261014..., P261014..., T1...)
        if (!appTxId && (trimmed.startsWith('T2') || trimmed.startsWith('T1') || trimmed.startsWith('P2')) && trimmed.length >= 13) {
          appTxId = trimmed;
        }

        // 2. 12-digit UTR
        if (!utrNumber) {
          const u = extractUtrFromText(trimmed);
          if (u && u !== appTxId) utrNumber = u;
        }

        // 3. VPA
        if (!payeeVpa || !payerVpa) {
          const v = extractVpaFromText(trimmed);
          if (v) {
            if (!payeeVpa) payeeVpa = v;
            else if (!payerVpa && v !== payeeVpa) payerVpa = v;
          }
        }

        // 4. Account Mask & IFSC
        if (!accountMask) {
          const acc = extractAccountMask(trimmed);
          if (acc) accountMask = acc;
        }
        if (!ifscCode) {
          const ifscMatch = INDIAN_LEA_REGEX.IFSC_CODE.exec(trimmed);
          if (ifscMatch) ifscCode = ifscMatch[1];
        }

        // 5. Ghost Intents / Status & Direction Analysis
        const lower = trimmed.toLowerCase();
        if (
          lower.includes('ghost') ||
          lower.includes('abandoned') ||
          lower.includes('intent_abandoned') ||
          lower.includes('interrupted') ||
          lower.includes('cancelled_by_user') ||
          isFoxtrot && (lower.includes('drop') || lower.includes('cancel'))
        ) {
          direction = 'GHOST_INTENT';
          status = 'ABANDONED_INTENT';
        } else if (lower.includes('credit') || lower.includes('received')) {
          direction = 'CREDIT';
        } else if (lower.includes('collect') || lower.includes('request_money')) {
          direction = 'COLLECT_REQUEST';
        }

        if (lower.includes('failed') || lower.includes('declined')) {
          status = 'FAILED';
        } else if (lower.includes('pending') || lower.includes('initiated')) {
          status = 'PENDING';
        }

        // 6. Delinked / Removed Bank Accounts in core.db
        if (isCore && (lower.includes('delink') || lower.includes('unlink') || lower.includes('archived') || lower.includes('removed'))) {
          isDelinkedAccount = true;
        }
      } else if (typeof val === 'number') {
        // Timestamp candidate (epoch ms: > 100000000000)
        if (val > 100000000000 && val < 2500000000000) {
          if (!rawDateVal) rawDateVal = val;
        } else if (val > 0 && val < 100000000 && amountInr === 0) {
          // PhonePe often stores amounts in paise (multiply by 100)
          amountInr = (val >= 100 && Number.isInteger(val) && val % 10 === 0) ? val / 100 : val;
        }
      }
    }

    // Must have at least a TxID, UTR, VPA, account mask, or non-zero amount to qualify
    if (!appTxId && !utrNumber && !payeeVpa && !accountMask && amountInr === 0) {
      return null;
    }

    const timestamp = normalizeTimestamp(rawDateVal || Date.now(), 'UNIX_MS');

    // Decode embedded TxID timestamp to detect clock manipulation
    let embeddedIdTimestamp;
    let clockTamperDetected = false;

    if (appTxId && appTxId.startsWith('T') && appTxId.length >= 13) {
      embeddedIdTimestamp = normalizeTimestamp(appTxId, 'PHONEPE_TXID');
      clockTamperDetected = detectClockTampering(timestamp, embeddedIdTimestamp);
    }

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsPath}-wal` : vfsPath,
      containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
      tableName: row.tableName || (isFoxtrot ? 'foxtrot_events' : 'transactions'),
      pageNumber: row.pageNumber,
      rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
      byteOffset: row.byteOffset,
      byteLength: row.byteLength,
      recoveryState: row.recoveryState,
      rawPayloadHex: row.rawHex
    };

    let notes: string | undefined;
    if (isDelinkedAccount) {
      notes = `[DELINKED BANK ACCOUNT RECOVERED] Account Mask: ${accountMask || 'N/A'}, IFSC: ${ifscCode || 'N/A'}`;
    } else if (direction === 'GHOST_INTENT') {
      notes = `[GHOST_INTENT] Abandoned UPI Payment Session detected in PhonePe ${isFoxtrot ? 'Foxtrot telemetry' : 'TransactionsStore'}`;
    }

    return {
      id: utrNumber || appTxId || `PHONEPE_${row.pageNumber}_${row.byteOffset.toString(16)}`,
      utrNumber,
      appTransactionId: appTxId,
      sourceApp: 'PhonePe',
      payerVpa,
      payeeVpa,
      accountMask,
      ifscCode,
      amountInr,
      currency: 'INR',
      direction,
      status,
      timestamp,
      embeddedIdTimestamp,
      clockTamperDetected,
      corroboratedSources: [row.recoveryState === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
      provenance,
      notes
    };
  }
}

// ============================================================================
// 3. Google Pay India Deep Parser (com.google.android.apps.nbu.paisa.user)
// ============================================================================

export class GPayIndiaDeepParser {
  /**
   * Deeply parses Google Pay Tez (paisa.db) by extracting B-Tree records and
   * decoding nested Protobuf BLOB columns for VPAs, 12-digit UTRs, and amounts.
   */
  public static parse(
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
      const activeAndCarved = carver.carveEntireDatabase();

      let walRows: CarvedSqliteRow[] = [];
      if (walBuffer && walBuffer.length > 32) {
        try {
          const walCarver = new WalCarver(walBuffer, carver.getHeader().pageSize, activeAndCarved);
          walRows = walCarver.carveAllWalRows('gpay_wal');
        } catch {}
      }

      const allRows = [...activeAndCarved, ...walRows];

      for (const row of allRows) {
        const tx = GPayIndiaDeepParser.mapRowToTransaction(row, evidenceId, archivePath, vfsInternalPath);
        if (tx) {
          transactions.push(tx);
        }
      }
    } catch {
      // Continue gracefully on corrupt files
    }

    return transactions;
  }

  private static mapRowToTransaction(
    row: CarvedSqliteRow,
    evidenceId: string,
    archivePath: string,
    vfsPath: string
  ): UnifiedUPITransaction | null {
    const vals = row.values;
    if (!vals || vals.length === 0) return null;

    let appTxId: string | null = null;
    let utrNumber: string | null = null;
    let payerVpa: string | null = null;
    let payeeVpa: string | null = null;
    let accountMask: string | null = null;
    let amountInr = 0;
    let rawDateVal: any = null;
    let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';
    let status: 'SUCCESS' | 'FAILED' | 'PENDING' | 'ABANDONED_INTENT' = 'SUCCESS';

    for (const val of vals) {
      if (Buffer.isBuffer(val) && val.length > 4) {
        // Parse nested Protobuf BLOB column
        try {
          const protoFields = decodeProtobufWire(val);
          walkProtobufValues(protoFields, (pv) => {
            if (typeof pv === 'string') {
              if (!appTxId && (pv.startsWith('CICAg') || pv.length >= 16)) {
                appTxId = pv;
              }
              if (!utrNumber) {
                const u = extractUtrFromText(pv);
                if (u && u !== appTxId) utrNumber = u;
              }
              const v = extractVpaFromText(pv);
              if (v) {
                if (!payeeVpa) payeeVpa = v;
                else if (!payerVpa && v !== payeeVpa) payerVpa = v;
              }
              const acc = extractAccountMask(pv);
              if (acc && !accountMask) accountMask = acc;
            } else if (typeof pv === 'number') {
              if (pv > 100000000000 && !rawDateVal) {
                rawDateVal = pv > 1000000000000000 ? Math.floor(pv / 1000) : pv;
              } else if (pv > 0 && amountInr === 0) {
                // GPay protobuf currency values frequently represented in micro-units (10^6)
                if (pv >= 1000000 && pv % 10000 === 0) {
                  amountInr = pv / 1000000;
                } else if (pv >= 100 && pv % 10 === 0) {
                  amountInr = pv / 100;
                } else if (pv < 5000000) {
                  amountInr = pv;
                }
              }
            }
          });
        } catch {
          // Continue to scalar parsing
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
        if (lower.includes('collect') || lower.includes('request')) direction = 'COLLECT_REQUEST';
        if (lower.includes('failed')) status = 'FAILED';
      } else if (typeof val === 'number') {
        if (val > 100000000000 && !rawDateVal) {
          rawDateVal = val;
        } else if (val > 0 && val < 5000000 && amountInr === 0) {
          amountInr = (val >= 100 && val % 10 === 0) ? val / 100 : val;
        }
      }
    }

    if (!appTxId && !utrNumber && !payeeVpa && amountInr === 0) {
      return null;
    }

    const timestamp = normalizeTimestamp(rawDateVal || Date.now(), 'UNIX_MS');

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsPath}-wal` : vfsPath,
      containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
      tableName: row.tableName || 'paisa_transactions',
      pageNumber: row.pageNumber,
      rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
      byteOffset: row.byteOffset,
      byteLength: row.byteLength,
      recoveryState: row.recoveryState,
      rawPayloadHex: row.rawHex
    };

    return {
      id: utrNumber || appTxId || `GPAY_${row.pageNumber}_${row.byteOffset.toString(16)}`,
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
      corroboratedSources: [row.recoveryState === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
      provenance
    };
  }
}

// ============================================================================
// 4. Paytm & BHIM Deep Parser
// ============================================================================

export class PaytmBhimDeepParser {
  /**
   * Parses Paytm passbook.db SQLite database & binary MMKV key-value stores.
   */
  public static parsePaytm(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    const lower = vfsInternalPath.toLowerCase();

    // Check if buffer is MMKV binary format
    const isMmkv = lower.includes('mmkv') || (dbBuffer.length >= 8 && !dbBuffer.toString('utf8', 0, 16).startsWith('SQLite'));

    if (isMmkv) {
      return PaytmBhimDeepParser.parseMmkvBuffer(evidenceId, archivePath, vfsInternalPath, dbBuffer);
    }

    // Otherwise parse as SQLite database
    try {
      const carver = new SqliteBinaryCarver(dbBuffer);
      const rows = carver.carveEntireDatabase();

      let walRows: CarvedSqliteRow[] = [];
      if (walBuffer && walBuffer.length > 32) {
        try {
          const walCarver = new WalCarver(walBuffer, carver.getHeader().pageSize, rows);
          walRows = walCarver.carveAllWalRows('paytm_wal');
        } catch {}
      }

      for (const row of [...rows, ...walRows]) {
        const tx = PaytmBhimDeepParser.mapPaytmRow(row, evidenceId, archivePath, vfsInternalPath);
        if (tx) transactions.push(tx);
      }
    } catch {}

    return transactions;
  }

  /**
   * Parses binary MMKV key-value entries.
   */
  private static parseMmkvBuffer(
    evidenceId: string,
    archivePath: string,
    vfsPath: string,
    buf: Buffer
  ): UnifiedUPITransaction[] {
    const transactions: UnifiedUPITransaction[] = [];
    if (buf.length < 8) return transactions;

    // MMKV files start with 4-byte CRC, followed by variable length records
    let offset = 4;
    while (offset < buf.length - 4) {
      try {
        const keyLen = buf.readUInt16LE(offset);
        offset += 2;
        if (keyLen <= 0 || offset + keyLen > buf.length) break;

        const key = buf.toString('utf8', offset, offset + keyLen);
        offset += keyLen;

        const valLen = buf.readUInt32LE(offset);
        offset += 4;
        if (valLen <= 0 || offset + valLen > buf.length) break;

        const valSlice = buf.subarray(offset, offset + valLen);
        const valStr = valSlice.toString('utf8');
        offset += valLen;

        const utr = extractUtrFromText(valStr);
        const vpa = extractVpaFromText(valStr);
        const mask = extractAccountMask(valStr);
        const amount = extractAmountInr(valStr);

        if (utr || vpa || (amount && amount > 0)) {
          transactions.push({
            id: utr || `PAYTM_MMKV_${key}_${offset.toString(16)}`,
            utrNumber: utr,
            appTransactionId: key,
            sourceApp: 'Paytm',
            payerVpa: null,
            payeeVpa: vpa,
            accountMask: mask,
            ifscCode: null,
            amountInr: amount || 0,
            currency: 'INR',
            direction: 'DEBIT',
            status: 'SUCCESS',
            timestamp: normalizeTimestamp(Date.now(), 'UNIX_MS'),
            corroboratedSources: ['APP_DB'],
            provenance: {
              evidenceId,
              archivePath,
              vfsInternalPath: vfsPath,
              containerType: 'MMKV',
              byteOffset: offset - valLen,
              byteLength: valLen,
              recoveryState: 'ACTIVE',
              rawPayloadHex: valSlice.subarray(0, Math.min(valSlice.length, 48)).toString('hex')
            }
          });
        }
      } catch {
        offset += 2;
      }
    }

    return transactions;
  }

  private static mapPaytmRow(
    row: CarvedSqliteRow,
    evidenceId: string,
    archivePath: string,
    vfsPath: string
  ): UnifiedUPITransaction | null {
    const vals = row.values;
    if (!vals || vals.length < 2) return null;

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

    if (!utr && !vpa && (!orderId || amount === 0)) return null;

    return {
      id: utr || orderId || `PAYTM_${row.pageNumber}_${row.byteOffset.toString(16)}`,
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
      corroboratedSources: [row.recoveryState === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
      provenance: {
        evidenceId,
        archivePath,
        vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsPath}-wal` : vfsPath,
        containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
        tableName: row.tableName || 'passbook',
        pageNumber: row.pageNumber,
        rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
        byteOffset: row.byteOffset,
        byteLength: row.byteLength,
        recoveryState: row.recoveryState,
        rawPayloadHex: row.rawHex
      }
    };
  }

  /**
   * Parses BHIM UPI application (bhim.db) databases.
   */
  public static parseBhim(
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
          walRows = walCarver.carveAllWalRows('bhim_wal');
        } catch {}
      }

      for (const row of [...rows, ...walRows]) {
        const vals = row.values;
        if (!vals || vals.length < 2) continue;

        let utr: string | null = null;
        let npciTxId: string | null = null;
        let vpa: string | null = null;
        let amount = 0;
        let dateVal: any = null;
        let direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' = 'DEBIT';

        for (const val of vals) {
          if (typeof val === 'string') {
            if (!utr) utr = extractUtrFromText(val);
            if (!vpa && (val.includes('@upi') || extractVpaFromText(val))) {
              vpa = extractVpaFromText(val) || val;
            }
            if (val.startsWith('BHIM') || val.startsWith('NPCI')) npciTxId = val;

            const lower = val.toLowerCase();
            if (lower.includes('collect') || lower.includes('request') || row.tableName?.includes('collect')) {
              direction = 'COLLECT_REQUEST';
            } else if (lower.includes('credit') || lower.includes('received')) {
              direction = 'CREDIT';
            }
          } else if (typeof val === 'number') {
            if (val > 100000000000 && !dateVal) dateVal = val;
            else if (val > 0 && val < 5000000 && amount === 0) amount = val;
          }
        }

        if (utr || vpa || amount > 0) {
          transactions.push({
            id: utr || npciTxId || `BHIM_${row.pageNumber}_${row.byteOffset.toString(16)}`,
            utrNumber: utr,
            appTransactionId: npciTxId,
            sourceApp: 'BHIM',
            payerVpa: direction === 'COLLECT_REQUEST' ? vpa : null,
            payeeVpa: direction === 'COLLECT_REQUEST' ? null : vpa,
            accountMask: null,
            ifscCode: null,
            amountInr: amount,
            currency: 'INR',
            direction,
            status: 'SUCCESS',
            timestamp: normalizeTimestamp(dateVal || Date.now(), 'UNIX_MS'),
            corroboratedSources: [row.recoveryState === 'WAL_RECOVERED' ? 'WAL_LOG' : 'APP_DB'],
            provenance: {
              evidenceId,
              archivePath,
              vfsInternalPath: row.recoveryState === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
              containerType: row.recoveryState === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
              tableName: row.tableName || 'transactions',
              pageNumber: row.pageNumber,
              rowId: typeof row.rowId === 'bigint' ? row.rowId.toString() : row.rowId,
              byteOffset: row.byteOffset,
              byteLength: row.byteLength,
              recoveryState: row.recoveryState,
              rawPayloadHex: row.rawHex
            }
          });
        }
      }
    } catch {}

    return transactions;
  }
}
