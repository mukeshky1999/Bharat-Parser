import {
  DeviceMetadata,
  ForensicProvenance,
  MuleGraphData,
  UnifiedUPITransaction
} from '../../shared/forensic-types';
import { AuditLogger } from './audit_logger';
import { ForensicExtractionResult } from '../parsers/registry';
import { MuleGraphEngine } from '../intelligence/mule_graph_engine';
import { normalizeTimestamp } from './timestamp_engine';

export interface CaseSessionState {
  caseId: string;
  caseNumber: string;
  firNumber: string;
  policeStation: string;
  district: string;
  examinerName: string;
  openedAt: string;
  deviceMetadata?: DeviceMetadata;
  extractionResult?: ForensicExtractionResult;
  muleGraph?: MuleGraphData;
  auditLogger: AuditLogger;
}

/**
 * In-Memory Forensic Case Manager & State Repository.
 */
export class CaseManager {
  private static instance: CaseManager | null = null;
  private state: CaseSessionState;

  private constructor() {
    const logger = new AuditLogger();
    logger.logAction('WORKBENCH_STARTUP', 'Bharat-PA Forensic Workbench initialized in strict read-only mode.');

    this.state = {
      caseId: `CASE-${Date.now()}`,
      caseNumber: 'CASE-2026-CYB-09',
      firNumber: 'FIR-402/2026',
      policeStation: 'Cyber Crime Police Station, Bengaluru',
      district: 'Bengaluru Urban',
      examinerName: 'Inspector Rajesh Kumar (Digital Forensic Examiner)',
      openedAt: new Date().toISOString(),
      auditLogger: logger
    };
  }

  public static getInstance(): CaseManager {
    if (!CaseManager.instance) {
      CaseManager.instance = new CaseManager();
    }
    return CaseManager.instance;
  }

  public getState(): CaseSessionState {
    return this.state;
  }

  public setExtractionResult(result: ForensicExtractionResult, deviceMeta: DeviceMetadata): void {
    this.state.deviceMetadata = deviceMeta;
    this.state.extractionResult = result;
    this.state.muleGraph = MuleGraphEngine.buildGraph(
      result.upiTransactions,
      result.cryptoTransactions,
      result.maliciousApks
    );

    this.state.auditLogger.logAction(
      'EXTRACTION_COMPLETE',
      `Parsed ${result.parsedFilesCount} files. Recovered ${result.upiTransactions.length} UPI txs, ${result.chatMessages.length} msgs, ${result.maliciousApks.length} suspicious APKs.`,
      this.state.examinerName
    );
  }

  /**
   * Generates a fully populated reference forensic dataset demonstrating
   * all recovery states [ACTIVE, WAL_RECOVERED, CARVED_UNALLOCATED], clock tamper alerts,
   * SMS DLT correlation, Mule APK detection, AnyDesk logs, and TRC-20 crypto off-ramps.
   */
  public loadReferenceGoldenDataset(): void {
    const dummyProvenance = (
      vfsPath: string,
      table: string,
      page: number,
      offset: number,
      len: number,
      state: 'ACTIVE' | 'WAL_RECOVERED' | 'CARVED_UNALLOCATED',
      container: any = 'SQLITE'
    ): ForensicProvenance => ({
      evidenceId: 'REF_EVIDENCE_DUMP_01',
      archivePath: '/evidence/case_evidence.tar',
      vfsInternalPath: vfsPath,
      containerType: container,
      tableName: table,
      pageNumber: page,
      byteOffset: offset,
      byteLength: len,
      recoveryState: state,
      rawPayloadHex: '3938323733303139323833340000000000450000'
    });

    const upiTransactions: UnifiedUPITransaction[] = [
      {
        id: 'TX_982730192834',
        utrNumber: '982730192834',
        appTransactionId: 'T261014142201991203',
        sourceApp: 'PhonePe',
        payerVpa: 'victim.anand@okhdfcbank',
        payeeVpa: 'target.account1@ybl',
        accountMask: 'SBI XX4921',
        ifscCode: 'SBIN0001234',
        amountInr: 45000,
        currency: 'INR',
        direction: 'DEBIT',
        status: 'SUCCESS',
        timestamp: normalizeTimestamp('1760432521000', 'UNIX_MS'),
        embeddedIdTimestamp: normalizeTimestamp('T261014142201', 'PHONEPE_TXID'),
        clockTamperDetected: false,
        corroboratedSources: ['APP_DB', 'SMS_DLT', 'NOTIFICATION_LOG'],
        provenance: dummyProvenance(
          '/data/data/com.phonepe.app/databases/TransactionsStore.sqlite',
          'transactions',
          42,
          0x000a4f20,
          96,
          'ACTIVE'
        )
      },
      {
        id: 'TX_628719991023',
        utrNumber: '628719991023',
        appTransactionId: 'CICAgPD8391741',
        sourceApp: 'GPay',
        payerVpa: 'target.account1@ybl',
        payeeVpa: 'mule.layer2@okaxis',
        accountMask: 'HDFC XX8812',
        ifscCode: 'HDFC0000412',
        amountInr: 44500,
        currency: 'INR',
        direction: 'DEBIT',
        status: 'SUCCESS',
        timestamp: normalizeTimestamp('1760432719000', 'UNIX_MS'),
        corroboratedSources: ['WAL_LOG', 'NOTIFICATION_LOG'],
        provenance: dummyProvenance(
          '/data/data/com.google.android.apps.nbu.paisa.user/databases/paisa.db-wal',
          'events',
          18,
          0x00012e80,
          112,
          'WAL_RECOVERED',
          'SQLITE_WAL'
        ),
        notes: 'Recovered from uncheckpointed GPay WAL frame after suspect cleared app cache.'
      },
      {
        id: 'TX_628720114920',
        utrNumber: '628720114920',
        appTransactionId: 'T261014142900881244',
        sourceApp: 'PhonePe',
        payerVpa: 'mule.layer2@okaxis',
        payeeVpa: 'p2p.merchant@ibl',
        accountMask: 'AXIS XX1092',
        ifscCode: 'UTIB0000192',
        amountInr: 44000,
        currency: 'INR',
        direction: 'DEBIT',
        status: 'SUCCESS',
        // Clock tampering simulated: Row date says 14:15, but TxID embeds 14:29:00
        timestamp: normalizeTimestamp('1760431500000', 'UNIX_MS'),
        embeddedIdTimestamp: normalizeTimestamp('T261014142900', 'PHONEPE_TXID'),
        clockTamperDetected: true,
        corroboratedSources: ['APP_DB', 'SMS_DLT'],
        provenance: dummyProvenance(
          '/data/data/com.phonepe.app/databases/TransactionsStore.sqlite',
          'transactions',
          45,
          0x000b1200,
          96,
          'CARVED_UNALLOCATED',
          'RAW_CARVED'
        ),
        notes: 'ALERT: Device clock set back by 14 minutes prior to transaction execution!'
      },
      {
        id: 'TX_GHOST_998124',
        utrNumber: null,
        appTransactionId: 'T261014143500112233',
        sourceApp: 'PhonePe',
        payerVpa: 'mule.layer2@okaxis',
        payeeVpa: 'fast.cash@upi',
        accountMask: 'SBI XX4921',
        ifscCode: null,
        amountInr: 95000,
        currency: 'INR',
        direction: 'GHOST_INTENT',
        status: 'ABANDONED_INTENT',
        timestamp: normalizeTimestamp('1760433300000', 'UNIX_MS'),
        embeddedIdTimestamp: normalizeTimestamp('T261014143500', 'PHONEPE_TXID'),
        clockTamperDetected: false,
        corroboratedSources: ['APP_DB'],
        provenance: dummyProvenance(
          '/data/data/com.phonepe.app/databases/foxtrot.db',
          'intents',
          8,
          0x00008400,
          80,
          'ACTIVE'
        ),
        notes: 'Ghost Payment Intent: Initiated collect request cancelled before PIN submission.'
      },
      {
        id: 'TX_SMS_DLT_09182',
        utrNumber: '982730192834',
        appTransactionId: null,
        sourceApp: 'SMS_DLT',
        payerVpa: null,
        payeeVpa: 'target.account1@ybl',
        accountMask: 'XX4921',
        ifscCode: null,
        amountInr: 45000,
        currency: 'INR',
        direction: 'DEBIT',
        status: 'SUCCESS',
        timestamp: normalizeTimestamp('1760432525000', 'UNIX_MS'),
        corroboratedSources: ['SMS_DLT'],
        provenance: dummyProvenance(
          '/data/data/com.android.providers.telephony/databases/mmssms.db',
          'sms',
          3,
          0x00003180,
          144,
          'ACTIVE'
        ),
        notes: 'TRAI DLT Sender: VK-SBIINB'
      }
    ];

    const maliciousApks = [
      {
        packageName: 'com.sbi.reward.secureapp',
        appName: 'SBI Yono Rewards OTP Verify',
        apkVfsPath: '/data/app/~~sbi_fake~~/base.apk',
        sha256: '9f24e410b0e5124192bce9049182390a18293810239120491209381203912039',
        dangerousPermissions: [
          'android.permission.RECEIVE_SMS',
          'android.permission.READ_SMS',
          'android.permission.SEND_SMS',
          'android.permission.RECEIVE_BOOT_COMPLETED',
          'android.permission.BIND_ACCESSIBILITY_SERVICE'
        ],
        extractedTelegramBotTokens: ['bot7192834012:AAH92kLmOPq19482710385918274019283'],
        extractedTelegramChatIds: ['-1002938192834', '819283741'],
        extractedC2Urls: [
          'https://api.telegram.org',
          'https://fast-otp-forwarder.duckdns.org/api/sms/push'
        ],
        isSideloaded: true,
        riskScore: 'CRITICAL' as const,
        provenance: dummyProvenance('/data/app/base.apk', 'classes.dex', 0, 0x0001f000, 2048, 'ACTIVE', 'RAW_CARVED')
      }
    ];

    const remoteAccessSessions = [
      {
        id: 'ANYDESK_928371948_1',
        tool: 'AnyDesk' as const,
        remoteClientId: '928371948',
        remoteAlias: 'desk-operator-cyber',
        incoming: true,
        connectedAt: normalizeTimestamp('1760431800000', 'UNIX_MS'),
        disconnectedAt: normalizeTimestamp('1760433600000', 'UNIX_MS'),
        durationSeconds: 1800,
        sourceIp: '185.220.101.45',
        provenance: dummyProvenance(
          '/data/data/com.anydesk.anydeskandroid/files/ad_svc.trace',
          'connection_trace',
          1,
          0x00000210,
          128,
          'ACTIVE',
          'RAW_CARVED'
        )
      }
    ];

    const cryptoTransactions = [
      {
        id: 'CRYPTO_TRON_TX_01',
        walletApp: 'Binance' as const,
        coin: 'USDT_TRC20' as const,
        address: '0x71C8360938A9184B918274910284729184719283',
        txHash: '0x9fa1827361928371928371928371928371928371928371928371928371928371',
        amount: 500, // 500 USDT = ~44,000 INR
        direction: 'OUT' as const,
        timestamp: normalizeTimestamp('1760433200000', 'UNIX_MS'),
        status: 'CONFIRMED' as const,
        isMuleOffRamp: true,
        provenance: dummyProvenance(
          '/data/data/com.binance.dev/databases/p2p_trade.db',
          'order_history',
          14,
          0x0000e400,
          72,
          'ACTIVE',
          'LEVELDB'
        )
      }
    ];

    const chatMessages = [
      {
        id: 'WA_MSG_01',
        threadId: '919876543210@s.whatsapp.net',
        sourceApp: 'WhatsApp' as const,
        senderJid: '919876543210@s.whatsapp.net',
        senderName: 'Primary Contact',
        body: 'Send 45000 to target.account1@ybl immediately, then proceed with transfer.',
        isFromMe: false,
        timestamp: normalizeTimestamp('1760432400000', 'UNIX_MS'),
        isDeleted: false,
        paymentAttachment: {
          amountInr: 45000,
          utrNumber: '982730192834',
          vpa: 'target.account1@ybl',
          status: 'SUCCESS'
        },
        provenance: dummyProvenance(
          '/data/data/com.whatsapp/databases/msgstore.db',
          'messages',
          102,
          0x00066000,
          160,
          'ACTIVE'
        )
      },
      {
        id: 'WA_MSG_02_DEL',
        threadId: '919876543210@s.whatsapp.net',
        sourceApp: 'WhatsApp' as const,
        senderJid: 'me@s.whatsapp.net',
        senderName: 'Subject',
        body: 'Done, transferred 45000. UTR is 982730192834. Now deleting transaction log.',
        isFromMe: true,
        timestamp: normalizeTimestamp('1760432580000', 'UNIX_MS'),
        isDeleted: true,
        provenance: dummyProvenance(
          '/data/data/com.whatsapp/databases/msgstore.db-wal',
          'messages',
          102,
          0x00066450,
          120,
          'WAL_RECOVERED',
          'SQLITE_WAL'
        )
      }
    ];

    const deviceMetadata: DeviceMetadata = {
      model: 'Redmi Note 12 5G (Sunstone)',
      manufacturer: 'Xiaomi Communications Ltd.',
      androidVersion: '14.0 (HyperOS 1.0.4.0)',
      buildNumber: 'UKQ1.230917.001',
      imei1: '862910058291048',
      imei2: '862910058291055',
      serialNumber: 'd8a7c2901bfa',
      timezone: 'Asia/Kolkata (IST +05:30)',
      extractionType: 'PHYSICAL_TAR',
      evidenceSourcePath: '/evidence/case_evidence.tar',
      hashes: {
        md5: '7d56e9c13b28490a1827461928374610',
        sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        fileSizeBytes: 52428800000, // 50 GB
        verified: true,
        calculatedAt: '2026-10-31T16:00:00.000Z'
      },
      acquisitionTimestamp: normalizeTimestamp('1760430000000', 'UNIX_MS')
    };

    const extractionResult: ForensicExtractionResult = {
      deviceMetadata,
      upiTransactions,
      chatMessages,
      maliciousApks,
      remoteAccessSessions,
      cryptoTransactions,
      harvestedKeys: [
        {
          alias: 'WhatsApp Crypt14/15 Master Key',
          keyType: 'AES',
          value: '4a9b2c8f1e0d3a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b',
          sourceFile: '/data/data/com.whatsapp/files/key'
        },
        {
          alias: 'PhonePe Room DB SQLCipher Key',
          keyType: 'SQLCIPHER_PASS',
          value: 'phn_sec_room_9281749102847102',
          sourceFile: '/data/data/com.phonepe.app/shared_prefs/com.phonepe.app_preferences.xml'
        }
      ],
      parsedFilesCount: 84210
    };

    this.setExtractionResult(extractionResult, deviceMetadata);
  }
}
