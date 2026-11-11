import {
  ChatMessage,
  CryptoWalletTransaction,
  DeviceMetadata,
  MaliciousApkFinding,
  RemoteAccessSession,
  UnifiedUPITransaction
} from '../../shared/forensic-types';
import { IVirtualFileSystem } from '../vfs/vfs_reader';
import { PhonePeParser } from './indian_upi/phonepe.parser';
import { GPayIndiaParser } from './indian_upi/gpay_india.parser';
import { PaytmParser } from './indian_upi/paytm.parser';
import { SmsDltLedgerParser } from './indian_banking/sms_dlt_ledger';
import { NotifSpilloverParser } from './indian_banking/notif_spillover';
import { UpiCorrelator } from './indian_banking/upi_correlator';
import { SmsForwarderApkScanner } from './cybercrime_apps/sms_forwarder_apk';
import { RemoteAccessParser } from './cybercrime_apps/remote_access.parser';
import { CryptoWalletsParser } from './cybercrime_apps/crypto_wallets';
import { WhatsAppParser } from './messengers/whatsapp.parser';
import { TelegramParser } from './messengers/telegram.parser';
import { WhatsAppKeyHarvester } from './keystore/whatsapp_key';
import { SharedPrefsKeyHarvester, HarvestedKeyItem } from './keystore/shared_prefs_keys';
import { SqlcipherCrypto } from '../sqlite_carver/sqlcipher_crypto';

export interface ForensicExtractionResult {
  deviceMetadata?: DeviceMetadata;
  upiTransactions: UnifiedUPITransaction[];
  chatMessages: ChatMessage[];
  maliciousApks: MaliciousApkFinding[];
  remoteAccessSessions: RemoteAccessSession[];
  cryptoTransactions: CryptoWalletTransaction[];
  harvestedKeys: HarvestedKeyItem[];
  parsedFilesCount: number;
}

/**
 * Modular Forensic Parser Registry & Orchestrator.
 * Traverses VFS, matches paths and magic signatures, and runs deep decoders.
 */
export class ForensicParserRegistry {
  public static async executeFullExtraction(
    vfs: IVirtualFileSystem,
    evidenceId: string
  ): Promise<ForensicExtractionResult> {
    const rawUpiList: UnifiedUPITransaction[] = [];
    const chatMessages: ChatMessage[] = [];
    const maliciousApks: MaliciousApkFinding[] = [];
    const remoteAccessSessions: RemoteAccessSession[] = [];
    const cryptoTransactions: CryptoWalletTransaction[] = [];
    const harvestedKeys: HarvestedKeyItem[] = [];

    const archivePath = vfs.getPhysicalArchivePath();
    const allEntries = vfs.getAllEntries();

    let whatsappKey: Buffer | null = null;

    // Pass 1: Harvest keys (WhatsApp key, shared_prefs keys)
    for (const entry of allEntries) {
      if (entry.isDirectory || entry.sizeBytes === 0) continue;
      const p = entry.path.toLowerCase();

      if (p.endsWith('/files/key') && p.includes('com.whatsapp')) {
        try {
          const keyBuf = await vfs.readFile(entry.path);
          const hk = WhatsAppKeyHarvester.harvestKey(keyBuf);
          if (hk) {
            whatsappKey = hk.keyBuffer;
            harvestedKeys.push({
              alias: 'WhatsApp Crypt14/15 Key',
              keyType: 'AES',
              value: hk.keyHex,
              sourceFile: entry.path
            });
          }
        } catch {
          // Continue
        }
      } else if (p.endsWith('.xml') && p.includes('shared_prefs')) {
        try {
          const xmlBuf = await vfs.readFile(entry.path);
          const keys = SharedPrefsKeyHarvester.harvestXml(xmlBuf, entry.path);
          harvestedKeys.push(...keys);
        } catch {
          // Continue
        }
      }
    }

    // Pass 2: Ingest all applications and databases
    for (const entry of allEntries) {
      if (entry.isDirectory || entry.sizeBytes === 0) continue;
      const p = entry.path.toLowerCase();

      // 1. PhonePe
      if (p.includes('com.phonepe.app') && (p.endsWith('.sqlite') || p.endsWith('.db')) && !p.endsWith('-wal') && !p.endsWith('-journal')) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const txs = PhonePeParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          rawUpiList.push(...txs);
        } catch {
          // Skip
        }
      }

      // 2. Google Pay (paisa.db)
      else if (p.includes('paisa.db') && !p.endsWith('-wal') && !p.endsWith('-journal')) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const txs = GPayIndiaParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          rawUpiList.push(...txs);
        } catch {
          // Skip
        }
      }

      // 3. Paytm
      else if (p.includes('net.one97.paytm') && (p.endsWith('passbook.db') || p.endsWith('order_history.db') || p.includes('mmkv'))) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const txs = PaytmParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          rawUpiList.push(...txs);
        } catch {
          // Skip
        }
      }

      // 4. TRAI DLT SMS Ledger (mmssms.db)
      else if (p.endsWith('mmssms.db') || p.endsWith('telephony.db')) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const txs = SmsDltLedgerParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          rawUpiList.push(...txs);
        } catch {
          // Skip
        }
      }

      // 5. Notification Log Spillover
      else if (p.includes('notification_log.db') || p.endsWith('notification_log.db')) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const txs = NotifSpilloverParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          rawUpiList.push(...txs);
        } catch {
          // Skip
        }
      }

      // 6. WhatsApp
      else if (p.includes('com.whatsapp') && (p.endsWith('msgstore.db') || p.endsWith('msgstore.db.crypt14') || p.endsWith('msgstore.db.crypt15'))) {
        try {
          let dbBuf = await vfs.readFile(entry.path);
          if (p.includes('.crypt14') || p.includes('.crypt15')) {
            if (whatsappKey) {
              const dec = SqlcipherCrypto.decryptWhatsAppCrypt14(dbBuf, whatsappKey);
              if (dec.success && dec.decryptedBuffer) {
                dbBuf = dec.decryptedBuffer;
              }
            }
          }
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const msgs = WhatsAppParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          chatMessages.push(...msgs);
        } catch {
          // Skip
        }
      }

      // 7. Telegram
      else if (p.includes('org.telegram') && p.endsWith('cache4.db')) {
        try {
          const dbBuf = await vfs.readFile(entry.path);
          let walBuf: Buffer | undefined;
          const walEntry = vfs.getEntry(`${entry.path}-wal`);
          if (walEntry) {
            walBuf = await vfs.readFile(walEntry.path);
          }
          const msgs = TelegramParser.parse(evidenceId, archivePath, entry.path, dbBuf, walBuf);
          chatMessages.push(...msgs);
        } catch {
          // Skip
        }
      }

      // 8. Mule APK Scanner
      else if (p.endsWith('.apk')) {
        try {
          const apkBuf = await vfs.readFile(entry.path);
          const apkFinding = await SmsForwarderApkScanner.scanApkBuffer(evidenceId, archivePath, entry.path, apkBuf);
          if (apkFinding) {
            maliciousApks.push(apkFinding);
          }
        } catch {
          // Skip
        }
      }

      // 9. Remote Access Logs (AnyDesk / TeamViewer / RustDesk)
      else if (p.includes('ad_svc.trace') || p.includes('connection_trace.txt') || p.includes('connections_incoming.txt') || p.includes('rustdesk.log')) {
        try {
          const logBuf = await vfs.readFile(entry.path);
          const sessions = RemoteAccessParser.parse(evidenceId, archivePath, entry.path, logBuf);
          remoteAccessSessions.push(...sessions);
        } catch {
          // Skip
        }
      }

      // 10. Crypto Wallets (Binance / Trust / Tron)
      else if (p.includes('binance') || p.includes('trustwallet') || p.includes('tronlink')) {
        if (p.endsWith('.ldb') || p.endsWith('.log') || p.endsWith('.db')) {
          try {
            const buf = await vfs.readFile(entry.path);
            const cryptoTxs = CryptoWalletsParser.parse(evidenceId, archivePath, entry.path, buf);
            cryptoTransactions.push(...cryptoTxs);
          } catch {
            // Skip
          }
        }
      }
    }

    // Correlate UPI transactions across App DB, WAL, SMS DLT, and Notifications
    const upiTransactions = UpiCorrelator.correlate(rawUpiList);

    return {
      upiTransactions,
      chatMessages,
      maliciousApks,
      remoteAccessSessions,
      cryptoTransactions,
      harvestedKeys,
      parsedFilesCount: allEntries.length
    };
  }
}
