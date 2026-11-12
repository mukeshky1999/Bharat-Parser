export type RecoveryState = 'ACTIVE' | 'WAL_RECOVERED' | 'CARVED_UNALLOCATED' | 'OS_SPILLOVER';

export type TimestampFormat = 'UNIX_SEC' | 'UNIX_MS' | 'UNIX_US' | 'WEBKIT_US' | 'COCOA_SEC' | 'PHONEPE_TXID' | 'ISO_8601';

export interface TimestampTriplet {
  rawValue: string | number;
  sourceFormat: TimestampFormat;
  utcIso: string;           // e.g. "2026-10-14T08:52:01.000Z"
  istFormatted: string;     // e.g. "2026-10-14 14:22:01.000 IST (+05:30)"
  epochMs: number;
}

export interface ForensicProvenance {
  evidenceId: string;
  archivePath: string;      // e.g. "D:/Cases/Case09/dump.tar"
  vfsInternalPath: string;  // e.g. "/data/data/com.phonepe.app/databases/TransactionsStore.sqlite"
  containerType: 'SQLITE' | 'SQLITE_WAL' | 'PROTOBUF' | 'LEVELDB' | 'MMKV' | 'XML' | 'RAW_CARVED' | 'OCR_IMAGE';
  tableName?: string;
  pageNumber?: number;
  rowId?: number | string;
  byteOffset: number;       // Exact physical byte offset inside the internal file (render as 0x hex in UI)
  byteLength: number;       // Exact byte length of record payload for Hex Viewer highlighting
  recoveryState: RecoveryState;
  rawPayloadHex: string;    // Hex preview of raw bytes
}

export interface UnifiedUPITransaction {
  id: string;
  utrNumber: string | null;           // 12-digit NPCI UTR / RRN
  appTransactionId: string | null;    // e.g., PhonePe "T261014..." or GPay "CICAg..."
  sourceApp: 'PhonePe' | 'GPay' | 'Paytm' | 'BHIM' | 'CRED' | 'WhatsAppPay' | 'BankApp' | 'SMS_DLT' | 'Notif_Log' | 'OCR_Receipt';
  payerVpa: string | null;            // e.g., "suspect@ybl"
  payeeVpa: string | null;            // e.g., "mule.account@okaxis"
  accountMask: string | null;         // e.g., "SBI XX4921"
  ifscCode: string | null;
  amountInr: number;
  currency: 'INR' | string;
  direction: 'DEBIT' | 'CREDIT' | 'COLLECT_REQUEST' | 'GHOST_INTENT' | 'UNKNOWN';
  status: 'SUCCESS' | 'FAILED' | 'PENDING' | 'ABANDONED_INTENT' | 'UNKNOWN';
  timestamp: TimestampTriplet;
  embeddedIdTimestamp?: TimestampTriplet; // Decoded from PhonePe TxID to detect device clock manipulation
  clockTamperDetected?: boolean;
  corroboratedSources: ('APP_DB' | 'WAL_LOG' | 'SMS_DLT' | 'NOTIFICATION_LOG' | 'OCR_SCREENSHOT')[];
  provenance: ForensicProvenance;
  notes?: string;
}

export interface ChatArtifact {
  id: string;
  threadId: string;
  sourceApp:
    | 'WhatsApp'
    | 'WhatsApp Business'
    | 'Telegram'
    | 'Telegram X'
    | 'Signal'
    | 'Zangi'
    | 'Element'
    | 'Session'
    | 'Threema'
    | 'Briar'
    | 'SimpleX'
    | 'Snapchat'
    | 'Instagram'
    | 'Tinder'
    | 'Bumble'
    | 'Hinge'
    | 'Grindr'
    | 'GPay'
    | 'SMS_DLT'
    | string;
  senderJid: string;
  senderName: string;
  recipientJid?: string;
  recipientName?: string;
  body: string;
  isFromMe: boolean;
  /** UNKNOWN when the source table has no sent/received flag; never defaulted to INCOMING. */
  direction?: 'INCOMING' | 'OUTGOING' | 'UNKNOWN';
  timestamp: TimestampTriplet;
  messageStatus?: 'SENT' | 'DELIVERED' | 'READ' | 'PENDING' | 'FAILED' | 'PLAYED';
  ephemeralDuration?: number; // Disappearing message duration in seconds
  ephemeralExpireAt?: TimestampTriplet;
  forwardingScore?: number;
  isForwarded?: boolean;
  isStarred?: boolean;
  latitude?: number;
  longitude?: number;
  locationName?: string;
  mediaType?: 'PHOTO' | 'VIDEO' | 'AUDIO' | 'VOICE_NOTE' | 'DOCUMENT' | 'STICKER' | 'LOCATION' | 'CONTACT';
  mediaFileSize?: number;
  mediaMimeType?: string;
  mediaSha256?: string;
  mediaPath?: string;
  durationSeconds?: number;
  editTimestamp?: TimestampTriplet;
  replyToId?: string;
  quotedMessageText?: string;
  chatType?: 'DIRECT_1ON1' | 'GROUP_CHAT' | 'CHANNEL' | 'CHANNEL_BROADCAST' | string;
  threadTitle?: string;
  isViewOnce?: boolean;
  isDeleted: boolean;
  paymentAttachment?: {
    amountInr: number;
    utrNumber?: string;
    vpa?: string;
    status: string;
  };
  provenance: ForensicProvenance;
}

export interface CallLogArtifact {
  id: string;
  callType: 'CELLULAR_CDR' | 'VOIP_APP';
  sourceApp: 'Cellular' | 'WhatsApp' | 'Telegram' | 'Zangi' | 'Signal' | 'Instagram' | string;
  callerNumberOrId: string;
  callerName?: string;
  calleeNumberOrId: string;
  calleeName?: string;
  direction: 'INCOMING' | 'OUTGOING' | 'MISSED' | 'REJECTED' | 'UNKNOWN';
  callResult?: string;
  durationSeconds: number;
  timestamp: TimestampTriplet;
  provenance: ForensicProvenance;
}

export interface ContactArtifact {
  id: string;
  sourceApp: 'Device' | 'WhatsApp' | 'Telegram' | 'Signal' | 'Zangi' | 'Tinder' | 'Bumble' | 'Hinge' | 'Grindr' | 'UPI' | string;
  identifier: string; // phone, JID, username, Zangi ID (10 digits), Session ID (66 hex), VPA
  displayName: string;
  rawName?: string;
  bioOrStatus?: string; // Dating bio, WhatsApp status, Telegram about
  profilePhotoVfsPath?: string;
  datingMetadata?: {
    age?: number;
    gender?: string;
    distanceKm?: number;
    matchTimestamp?: TimestampTriplet;
    occupation?: string;
    location?: string;
  };
  lastActive?: TimestampTriplet;
  provenance: ForensicProvenance;
}

export interface OsSpilloverArtifact {
  id: string;
  category: 'NOTIFICATION_LOG' | 'KEYBOARD_CACHE' | 'CLIPBOARD' | 'APP_SWITCHER_SNAPSHOT' | 'TIMELINE_USAGE';
  sourceApp?: string; // package name e.g. com.zangi.mobile
  title?: string;
  snippet: string;
  targetData?: string; // Extracted VPA, TRC-20, Zangi ID, OTP, phone
  timestamp: TimestampTriplet;
  filePath?: string;
  provenance: ForensicProvenance;
}

// Backward compatibility alias
export type ChatMessage = ChatArtifact;

export interface MaliciousApkFinding {
  packageName: string;
  apkVfsPath: string;
  appName?: string;
  sha256: string;
  dangerousPermissions: string[];     // e.g., ['android.permission.RECEIVE_SMS', 'android.permission.READ_SMS']
  extractedTelegramBotTokens: string[]; // Matches /bot[0-9]{8,10}:[A-Za-z0-9_-]{35}/
  extractedTelegramChatIds: string[];
  extractedC2Urls: string[];
  isSideloaded: boolean;
  riskScore: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  provenance: ForensicProvenance;
}

export interface VfsNode {
  vfsPath: string;
  name: string;
  size: number;
  isDirectory: boolean;
  archiveByteOffset: number;
  isCompressed: boolean;
  compressionMethod?: number;
  parentPath: string;
  children?: VfsNode[];
}

// Compatibility alias for previous entry structure
export interface VfsEntry {
  path: string;
  name: string;
  sizeBytes: number;
  isDirectory: boolean;
  mimeType?: string;
  archiveByteOffset: number;
  archiveByteLength: number;
  parentPath: string;
  children?: VfsEntry[];
}

export interface CaseManifest {
  caseId: string;
  caseNumber: string;
  firNumber: string;
  policeStation: string;
  district: string;
  examinerName: string;
  evidencePath: string;
  evidenceFileName: string;
  fileSizeBytes: number;
  preIngestionHashes: {
    md5: string;
    sha256: string;
    calculatedAt: string;
  };
  postIngestionHashes?: {
    md5: string;
    sha256: string;
    calculatedAt: string;
    matchConfirmed: boolean;
  };
  indexedAt: TimestampTriplet;
  totalFilesIndexed: number;
}

export interface DualHashResult {
  md5: string;
  sha256: string;
  fileSizeBytes: number;
  verified: boolean;
  calculatedAt: string;
}

export interface DeviceMetadata {
  model: string;
  manufacturer: string;
  androidVersion: string;
  buildNumber: string;
  imei1?: string;
  imei2?: string;
  serialNumber: string;
  timezone: string;
  extractionType: 'PHYSICAL_TAR' | 'LOGICAL_ZIP' | 'ANDROID_BACKUP_AB' | 'UFED_UFD' | 'FILESYSTEM_FOLDER';
  evidenceSourcePath: string;
  hashes: DualHashResult;
  acquisitionTimestamp: TimestampTriplet;
}

export interface RemoteAccessSession {
  id: string;
  tool: 'AnyDesk' | 'TeamViewer' | 'RustDesk';
  remoteClientId: string;
  remoteAlias?: string;
  incoming: boolean;
  connectedAt: TimestampTriplet;
  disconnectedAt?: TimestampTriplet;
  durationSeconds?: number;
  sourceIp?: string;
  provenance: ForensicProvenance;
}

export interface CryptoWalletTransaction {
  id: string;
  walletApp: 'Binance' | 'TrustWallet' | 'TronLink' | 'MetaMask';
  coin: 'USDT_TRC20' | 'BTC' | 'ETH' | 'TRX';
  address: string;
  txHash: string;
  amount: number;
  direction: 'IN' | 'OUT';
  timestamp: TimestampTriplet;
  status: 'CONFIRMED' | 'PENDING';
  isMuleOffRamp: boolean;
  provenance: ForensicProvenance;
}

export interface MuleGraphNode {
  id: string;
  label: string;
  type: 'VPA' | 'BANK_ACCOUNT' | 'CRYPTO_WALLET' | 'PHONE' | 'SUSPECT_DEVICE' | 'TELEGRAM_BOT';
  riskScore: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  details: Record<string, any>;
}

export interface MuleGraphEdge {
  id: string;
  source: string;
  target: string;
  amountInr: number;
  utrNumber?: string;
  timestamp: string;
  app: string;
  channel: 'UPI' | 'NEFT' | 'IMPS' | 'CRYPTO_TRANSFER' | 'SMS_FORWARD';
}

export interface MuleGraphData {
  nodes: MuleGraphNode[];
  edges: MuleGraphEdge[];
  totalMuleHops: number;
  totalTransferredInr: number;
  cryptoOffRampsCount: number;
}

export interface Section63BsaCertificate {
  certificateId: string;
  firNumber: string;
  policeStation: string;
  district: string;
  courtName: string;
  caseTitle: string;
  actSections: string;
  examinerName: string;
  examinerDesignation: string;
  examinerCadre: string;
  fslLaboratory: string;
  deviceDetails: DeviceMetadata;
  targetArtifactCounts: {
    upiTransactions: number;
    recoveredWalRows: number;
    carvedUnallocatedRows: number;
    maliciousApks: number;
    remoteAccessSessions: number;
    chatMessages: number;
  };
  partA: {
    custodianName: string;
    seizureDate: string;
    custodyChainSummary: string;
    declarationSigned: boolean;
  };
  partB: {
    hashAlgorithm: string;
    dualHashMatchConfirmed: boolean;
    softwareName: string;
    softwareVersion: string;
    softwareHash: string;
    byteOffsetAccuracyAffidavit: boolean;
    declarationDate: string;
  };
  generatedAt: TimestampTriplet;
}

/**
 * Parses backend timestamp strings without depending on the examiner's machine timezone:
 *   "2024-01-15 10:30:00 UTC", "2024-01-15 16:00:00 IST (+05:30)", "2024-01-15T10:30:00+05:30",
 *   "2024-01-15 10:30:00" (unlabelled: treated as UTC, never as local time).
 * Returns NaN when the text is not a date.
 */
export function parseLabelledTimestamp(text: string): number {
  const t = text.trim();
  const m = t.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?\s*(UTC|Z|IST(?:\s*\(\+05:30\))?|[+-]\d{2}:?\d{2})?$/i);
  if (!m) {
    const fallback = Date.parse(t);
    return isNaN(fallback) ? NaN : fallback;
  }
  const [, y, mo, d, h, mi, sec, frac, zone] = m;
  const ms = frac ? Math.floor(parseFloat('0.' + frac) * 1000) : 0;
  let epoch = Date.UTC(+y, +mo - 1, +d, +h, +mi, sec ? +sec : 0, ms);
  const z = (zone || 'UTC').toUpperCase();
  if (z.startsWith('IST')) {
    epoch -= 5.5 * 3600 * 1000;
  } else if (/^[+-]\d{2}:?\d{2}$/.test(z)) {
    const sign = z[0] === '-' ? -1 : 1;
    const hh = +z.slice(1, 3);
    const mm = +z.slice(-2);
    epoch -= sign * (hh * 60 + mm) * 60 * 1000;
  }
  return epoch;
}

/**
 * Universal Dual-Timezone Timestamp Normalizer.
 * Converts:
 * - Unix Seconds (10 digits)
 * - Unix Milliseconds (13 digits)
 * - Unix Microseconds (16 digits)
 * - WebKit Microseconds (epoch 1601-01-01 00:00:00 UTC)
 * - iOS Cocoa Seconds (epoch 2001-01-01 00:00:00 UTC)
 * - PhonePe TYYMMDDHHmmss ID format
 * into: { rawValue, sourceFormat, utcIso, istFormatted, epochMs }
 * IST is strictly UTC+05:30.
 */
export function normalizeTimestamp(
  rawVal: string | number,
  format?: TimestampFormat
): TimestampTriplet {
  let detectedFormat: TimestampFormat = format || 'UNIX_MS';
  let epochMs = 0;

  // 1. PhonePe TxID Pattern check: T + YY(2) + MM(2) + DD(2) + HH(2) + mm(2) + ss(2)
  if (typeof rawVal === 'string' && rawVal.startsWith('T') && rawVal.length >= 13) {
    const candidateDigits = rawVal.substring(1, 13);
    if (/^\d{12}$/.test(candidateDigits)) {
      detectedFormat = 'PHONEPE_TXID';
    }
  }

  if (detectedFormat === 'PHONEPE_TXID' && typeof rawVal === 'string') {
    const yy = parseInt(rawVal.substring(1, 3), 10);
    const mm = parseInt(rawVal.substring(3, 5), 10) - 1;
    const dd = parseInt(rawVal.substring(5, 7), 10);
    const hh = parseInt(rawVal.substring(7, 9), 10);
    const min = parseInt(rawVal.substring(9, 11), 10);
    const ss = parseInt(rawVal.substring(11, 13), 10);
    const fullYear = 2000 + yy;

    // PhonePe encodes client timestamp in local IST (UTC+05:30)
    const istOffsetMs = 5.5 * 60 * 60 * 1000;
    const dateUtcAssumed = new Date(Date.UTC(fullYear, mm, dd, hh, min, ss));
    epochMs = dateUtcAssumed.getTime() - istOffsetMs;
  } else if (typeof rawVal === 'string' && (rawVal.includes('-') || rawVal.includes(':') || format === 'ISO_8601')) {
    const parsed = parseLabelledTimestamp(rawVal);
    if (!isNaN(parsed)) {
      detectedFormat = 'ISO_8601';
      epochMs = parsed;
    } else {
      epochMs = 0;
    }
  } else {
    const numericVal = typeof rawVal === 'number' ? rawVal : parseFloat(rawVal);

    if (isNaN(numericVal) || numericVal <= 0) {
      epochMs = 0;
      detectedFormat = format || 'UNIX_MS';
    } else if (!format) {
      // Auto-detection based on numeric magnitude
      if (numericVal > 11644473600000000) {
        // WebKit timestamp (microseconds since 1601-01-01)
        detectedFormat = 'WEBKIT_US';
        epochMs = Math.floor((numericVal - 11644473600000000) / 1000);
      } else if (numericVal > 1000000000000000) {
        // Unix microseconds (16 digits)
        detectedFormat = 'UNIX_US';
        epochMs = Math.floor(numericVal / 1000);
      } else if (numericVal > 100000000000) {
        // Unix milliseconds (13 digits)
        detectedFormat = 'UNIX_MS';
        epochMs = Math.floor(numericVal);
      } else if (numericVal > 0 && numericVal < 2500000000) {
        // Could be Unix seconds (10 digits) or Cocoa seconds
        detectedFormat = 'UNIX_SEC';
        epochMs = Math.floor(numericVal * 1000);
      } else {
        detectedFormat = 'UNIX_MS';
        epochMs = Math.floor(numericVal);
      }
    } else {
      detectedFormat = format;
      switch (format) {
        case 'UNIX_SEC':
          epochMs = Math.floor(numericVal * 1000);
          break;
        case 'UNIX_MS':
          epochMs = Math.floor(numericVal);
          break;
        case 'UNIX_US':
          epochMs = Math.floor(numericVal / 1000);
          break;
        case 'WEBKIT_US':
          // Epoch 1601-01-01 in microseconds to 1970 Unix epoch
          epochMs = Math.floor((numericVal - 11644473600000000) / 1000);
          break;
        case 'COCOA_SEC':
          // Apple Cocoa core data epoch: seconds since 2001-01-01 00:00:00 UTC (978307200 seconds offset)
          epochMs = Math.floor((numericVal + 978307200) * 1000);
          break;
        default:
          epochMs = Math.floor(numericVal);
          break;
      }
    }
  }

  // An empty or unparseable input is "unknown", never 1970-01-01.
  if (!epochMs || isNaN(epochMs)) {
    return { rawValue: rawVal, sourceFormat: detectedFormat, utcIso: '', istFormatted: 'Unknown', epochMs: 0 };
  }

  const d = new Date(epochMs);
  const utcIso = isNaN(d.getTime()) ? '' : d.toISOString();

  // Strictly compute IST: UTC + 05:30
  const istOffsetMs = 5.5 * 60 * 60 * 1000;
  const istDate = new Date(d.getTime() + istOffsetMs);

  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  const year = istDate.getUTCFullYear();
  const month = pad(istDate.getUTCMonth() + 1);
  const day = pad(istDate.getUTCDate());
  const hours = pad(istDate.getUTCHours());
  const minutes = pad(istDate.getUTCMinutes());
  const seconds = pad(istDate.getUTCSeconds());
  const millis = pad(istDate.getUTCMilliseconds(), 3);

  const istFormatted = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${millis} IST (+05:30)`;

  return {
    rawValue: rawVal,
    sourceFormat: detectedFormat,
    utcIso,
    istFormatted,
    epochMs
  };
}

/**
 * Compares database row timestamp with embedded TxID timestamp to detect clock manipulation.
 */
export function detectClockTampering(
  dbTimestamp: TimestampTriplet,
  embeddedTxIdTimestamp: TimestampTriplet,
  toleranceMs: number = 300000 // 5 minutes tolerance
): boolean {
  if (!dbTimestamp.epochMs || !embeddedTxIdTimestamp.epochMs) return false;
  const diff = Math.abs(dbTimestamp.epochMs - embeddedTxIdTimestamp.epochMs);
  return diff > toleranceMs;
}
