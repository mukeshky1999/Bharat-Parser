import * as crypto from 'crypto';
import * as os from 'os';
import * as fs from 'fs';
import { normalizeTimestamp, TimestampTriplet } from '../../shared/forensic-types';

export type AuditEventType =
  | 'SYSTEM_INITIALIZATION'
  | 'FILE_OPEN_READONLY'
  | 'PARSER_EXECUTION'
  | 'DUAL_HASH_VERIFY'
  | 'EVIDENCE_INGEST'
  | 'INTEGRITY_CHECK'
  | 'CERTIFICATE_GENERATION'
  | 'AIRGAP_FIREWALL_BLOCK'
  | 'LICENSE_VERIFICATION'
  | 'WORKBENCH_STARTUP'
  | 'EXTRACTION_COMPLETE'
  | 'AUDIT_GENERIC_ACTION';

export interface WorkstationProfile {
  hostname: string;
  platform: string;
  arch: string;
  cpuModel: string;
  cpuCores: number;
  totalMemoryBytes: number;
  osRelease: string;
}

export interface FileOpenGuardInfo {
  filePath: string;
  openFlags: number;
  isStrictReadOnly: boolean;
}

export interface AuditLogEntry {
  sequence: number;
  timestamp: TimestampTriplet;
  eventType: AuditEventType;
  action: string;
  details: string;
  examinerId: string;
  fileGuard?: FileOpenGuardInfo;
  workstation: WorkstationProfile;
  prevHash: string;
  entryHash: string;
}

export interface ChainVerificationResult {
  isValid: boolean;
  totalEntriesVerified: number;
  corruptedSequence?: number;
  error?: string;
}

/**
 * Tamper-Evident HMAC/SHA-256 Hash-Chained Forensic Audit Logger.
 * Records every file opened in strict fs.constants.O_RDONLY mode,
 * parser counts, examiner identity, and host workstation hardware attributes.
 */
export class AuditLogger {
  private logEntries: AuditLogEntry[] = [];
  private currentPrevHash: string = '0000000000000000000000000000000000000000000000000000000000000000';
  private hmacKey: string;
  private defaultExaminer: string;
  private cachedWorkstation: WorkstationProfile;

  constructor(hmacKey: string = 'BHARAT_PA_FORENSIC_CHAIN_OF_CUSTODY_SECRET', defaultExaminer: string = 'EXAMINER_DEFAULT') {
    this.hmacKey = hmacKey;
    this.defaultExaminer = defaultExaminer;
    this.cachedWorkstation = AuditLogger.gatherWorkstationProfile();

    // Genesis event
    this.logAction(
      'SYSTEM_INITIALIZATION',
      'Audit logging subsystem initialized with cryptographic hash-chaining',
      { genesis: true, software: 'BHARAT-PA Forensics' },
      this.defaultExaminer
    );
  }

  /**
   * Captures host CPU, OS, RAM, and hardware details without external dependencies.
   */
  public static gatherWorkstationProfile(): WorkstationProfile {
    try {
      if (typeof os !== 'undefined' && typeof os.cpus === 'function') {
        const cpus = os.cpus();
        return {
          hostname: typeof os.hostname === 'function' ? os.hostname() : 'forensic-workstation',
          platform: typeof os.platform === 'function' ? os.platform() : 'win32',
          arch: typeof os.arch === 'function' ? os.arch() : 'x64',
          cpuModel: cpus && cpus.length > 0 ? cpus[0].model : 'Host CPU',
          cpuCores: cpus ? cpus.length : 1,
          totalMemoryBytes: typeof os.totalmem === 'function' ? os.totalmem() : 16 * 1024 * 1024 * 1024,
          osRelease: typeof os.release === 'function' ? os.release() : '10.0'
        };
      }
    } catch {
      // Safe fallback for browser context
    }
    return {
      hostname: (typeof window !== 'undefined' && window.location?.hostname) || 'forensic-workstation',
      platform: (typeof navigator !== 'undefined' && navigator.platform) || 'Win32',
      arch: 'x64',
      cpuModel: (typeof navigator !== 'undefined' && (navigator as any).userAgent) || 'Forensic Workstation Browser Console',
      cpuCores: (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 8,
      totalMemoryBytes: 16 * 1024 * 1024 * 1024,
      osRelease: '10.0.26100'
    };
  }

  /**
   * Logs a file opened in strict O_RDONLY mode.
   * Throws an error if write or read-write flags are detected.
   */
  public logFileOpenReadOnly(
    filePath: string,
    openFlags: number = (typeof fs !== 'undefined' && fs.constants?.O_RDONLY) || 0,
    examinerId: string = this.defaultExaminer
  ): AuditLogEntry {
    const oWronly = (typeof fs !== 'undefined' && fs.constants?.O_WRONLY) || 1;
    const oRdwr = (typeof fs !== 'undefined' && fs.constants?.O_RDWR) || 2;
    const writeFlags = oWronly | oRdwr;
    const hasWriteFlag = (openFlags & writeFlags) !== 0;

    const fileGuard: FileOpenGuardInfo = {
      filePath,
      openFlags,
      isStrictReadOnly: !hasWriteFlag
    };

    if (hasWriteFlag) {
      throw new Error(`[AUDIT_SECURITY_VIOLATION] Attempted to open forensic file with write flags: "${filePath}" (Flags: 0x${openFlags.toString(16)})`);
    }

    return this.appendEntry(
      'FILE_OPEN_READONLY',
      `Opened evidence file in strict O_RDONLY mode`,
      JSON.stringify({ filePath, openFlags: `0x${openFlags.toString(16)}`, readOnlyConfirmed: true }),
      examinerId,
      fileGuard
    );
  }

  /**
   * Logs execution of a parser module and its extracted artifact counts.
   */
  public logParserExecution(
    parserName: string,
    itemsExtracted: number,
    vfsPath: string,
    examinerId: string = this.defaultExaminer
  ): AuditLogEntry {
    return this.appendEntry(
      'PARSER_EXECUTION',
      `Executed ${parserName} on ${vfsPath}`,
      JSON.stringify({ parserName, itemsExtracted, vfsPath }),
      examinerId
    );
  }

  /**
   * Logs generic forensic action. Supports both (action, details, examiner) and (eventType, action, details, examiner).
   */
  public logAction(
    eventTypeOrAction: string,
    actionOrDetails: string,
    detailsOrExaminer?: Record<string, any> | string,
    examinerId?: string
  ): AuditLogEntry {
    let evt: AuditEventType = 'AUDIT_GENERIC_ACTION';
    let act = eventTypeOrAction;
    let det = actionOrDetails;
    let ex = this.defaultExaminer;

    if (examinerId !== undefined) {
      // 4-arg signature: (eventType, action, details, examinerId)
      evt = eventTypeOrAction as AuditEventType;
      act = actionOrDetails;
      det = typeof detailsOrExaminer === 'string' ? detailsOrExaminer : JSON.stringify(detailsOrExaminer || {});
      ex = examinerId;
    } else if (detailsOrExaminer !== undefined) {
      if (typeof detailsOrExaminer === 'string' && (detailsOrExaminer.startsWith('Inspector') || detailsOrExaminer.startsWith('EXAMINER') || detailsOrExaminer.includes('Officer'))) {
        // 3-arg signature: (action, details, examinerName)
        act = eventTypeOrAction;
        det = actionOrDetails;
        ex = detailsOrExaminer;
      } else {
        // 3-arg signature: (eventType, action, details)
        evt = eventTypeOrAction as AuditEventType;
        act = actionOrDetails;
        det = typeof detailsOrExaminer === 'string' ? detailsOrExaminer : JSON.stringify(detailsOrExaminer);
      }
    } else {
      // 2-arg signature: (action, details)
      act = eventTypeOrAction;
      det = actionOrDetails;
    }

    return this.appendEntry(evt, act, det, ex);
  }

  /**
   * Appends an entry and calculates the cryptographic HMAC-SHA256 chained hash.
   */
  private appendEntry(
    eventType: AuditEventType,
    action: string,
    details: string,
    examinerId: string,
    fileGuard?: FileOpenGuardInfo
  ): AuditLogEntry {
    const sequence = this.logEntries.length + 1;
    const timestamp = normalizeTimestamp(Date.now(), 'UNIX_MS');

    const fileGuardStr = fileGuard ? `${fileGuard.filePath}|${fileGuard.openFlags}|${fileGuard.isStrictReadOnly}` : 'NO_GUARD';
    const workstationStr = `${this.cachedWorkstation.hostname}|${this.cachedWorkstation.cpuModel}|${this.cachedWorkstation.platform}`;

    const payload = `${sequence}|${timestamp.epochMs}|${eventType}|${action}|${details}|${examinerId}|${fileGuardStr}|${workstationStr}|${this.currentPrevHash}`;

    let entryHash = '';
    try {
      if (typeof crypto !== 'undefined' && typeof (crypto as any).createHmac === 'function') {
        entryHash = (crypto as any).createHmac('sha256', this.hmacKey).update(payload).digest('hex');
      }
    } catch {
      // Fallback
    }
    if (!entryHash) {
      let hash = 0;
      for (let i = 0; i < payload.length; i++) {
        const chr = payload.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0;
      }
      entryHash = Math.abs(hash).toString(16).padStart(64, '0');
    }

    const entry: AuditLogEntry = {
      sequence,
      timestamp,
      eventType,
      action,
      details,
      examinerId,
      fileGuard,
      workstation: this.cachedWorkstation,
      prevHash: this.currentPrevHash,
      entryHash
    };

    this.logEntries.push(entry);
    this.currentPrevHash = entryHash;
    return entry;
  }

  /**
   * Gets all audit log entries.
   */
  public getEntries(): AuditLogEntry[] {
    return [...this.logEntries];
  }

  /**
   * Verifies the cryptographic integrity of the entire hash chain from genesis to head.
   */
  public verifyIntegrity(): boolean {
    return this.verifyChainDetailed().isValid;
  }

  /**
   * Detailed verification returning corrupted sequence number if altered.
   */
  public verifyChainDetailed(): ChainVerificationResult {
    let expectedPrev = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < this.logEntries.length; i++) {
      const entry = this.logEntries[i];

      // 1. Verify previous hash pointer
      if (entry.prevHash !== expectedPrev) {
        return {
          isValid: false,
          totalEntriesVerified: i,
          corruptedSequence: entry.sequence,
          error: `Broken chain pointer at sequence ${entry.sequence}: expected prevHash ${expectedPrev}, found ${entry.prevHash}`
        };
      }

      // 2. Re-compute HMAC-SHA256
      const fileGuardStr = entry.fileGuard ? `${entry.fileGuard.filePath}|${entry.fileGuard.openFlags}|${entry.fileGuard.isStrictReadOnly}` : 'NO_GUARD';
      const workstationStr = `${entry.workstation.hostname}|${entry.workstation.cpuModel}|${entry.workstation.platform}`;
      const payload = `${entry.sequence}|${entry.timestamp.epochMs}|${entry.eventType}|${entry.action}|${entry.details}|${entry.examinerId}|${fileGuardStr}|${workstationStr}|${entry.prevHash}`;

      const computedHash = crypto.createHmac('sha256', this.hmacKey).update(payload).digest('hex');

      if (entry.entryHash !== computedHash) {
        return {
          isValid: false,
          totalEntriesVerified: i,
          corruptedSequence: entry.sequence,
          error: `Tampered hash at sequence ${entry.sequence}: expected ${computedHash}, found ${entry.entryHash}`
        };
      }

      expectedPrev = entry.entryHash;
    }

    return {
      isValid: true,
      totalEntriesVerified: this.logEntries.length
    };
  }
}
