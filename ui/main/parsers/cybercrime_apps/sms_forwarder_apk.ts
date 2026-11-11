import * as crypto from 'crypto';
import {
  ForensicProvenance,
  MaliciousApkFinding
} from '../../../shared/forensic-types';
import { ZipIndexer } from '../../vfs/zip_indexer';
import { AxmlParser } from '../../binary_decoders/axml_parser';
import { DexScanner } from '../../binary_decoders/dex_scanner';

/**
 * Malicious Mule APK & SMS Forwarder Triage Scanner.
 * Detects OTP-stealing banking malware and harvests embedded Telegram Bot C2 tokens.
 */
export class SmsForwarderApkScanner {
  public static async scanApkBuffer(
    evidenceId: string,
    archivePath: string,
    apkVfsPath: string,
    apkBuffer: Buffer
  ): Promise<MaliciousApkFinding | null> {
    const sha256 = crypto.createHash('sha256').update(apkBuffer).digest('hex');

    // APK is a ZIP container: search for AndroidManifest.xml and classes.dex
    // We can use a lightweight zip unpacker on the memory buffer
    let manifestBuf: Buffer | null = null;
    const dexBuffers: Buffer[] = [];

    try {
      const eocdOffset = SmsForwarderApkScanner.findEocd(apkBuffer);
      if (eocdOffset !== -1) {
        const cdCount = apkBuffer.readUInt16LE(eocdOffset + 10);
        const cdSize = apkBuffer.readUInt32LE(eocdOffset + 12);
        const cdOffset = apkBuffer.readUInt32LE(eocdOffset + 16);

        let offset = cdOffset;
        for (let i = 0; i < cdCount && offset + 46 <= apkBuffer.length; i++) {
          if (apkBuffer.readUInt32LE(offset) !== 0x02014b50) break;
          const method = apkBuffer.readUInt16LE(offset + 10);
          const compSize = apkBuffer.readUInt32LE(offset + 20);
          const uncompSize = apkBuffer.readUInt32LE(offset + 24);
          const nameLen = apkBuffer.readUInt16LE(offset + 28);
          const extraLen = apkBuffer.readUInt16LE(offset + 30);
          const commentLen = apkBuffer.readUInt16LE(offset + 32);
          const locOffset = apkBuffer.readUInt32LE(offset + 42);

          const fileName = apkBuffer.toString('utf8', offset + 46, offset + 46 + nameLen);

          // Locate data offset from local header
          let dataOffset = locOffset + 30 + nameLen + extraLen;
          if (locOffset + 30 <= apkBuffer.length) {
            const locNameLen = apkBuffer.readUInt16LE(locOffset + 26);
            const locExtraLen = apkBuffer.readUInt16LE(locOffset + 28);
            dataOffset = locOffset + 30 + locNameLen + locExtraLen;
          }

          if (fileName === 'AndroidManifest.xml' || fileName.endsWith('classes.dex')) {
            const rawSlice = apkBuffer.subarray(dataOffset, dataOffset + compSize);
            let decompressed = rawSlice;
            if (method === 8) {
              const zlib = await import('zlib');
              decompressed = zlib.inflateRawSync(rawSlice);
            }

            if (fileName === 'AndroidManifest.xml') {
              manifestBuf = decompressed;
            } else if (fileName.endsWith('.dex')) {
              dexBuffers.push(decompressed);
            }
          }

          offset += 46 + nameLen + extraLen + commentLen;
        }
      }
    } catch {
      // Fallback: direct buffer scans
    }

    // Parse manifest
    const manifest = manifestBuf ? AxmlParser.parse(manifestBuf) : { packageName: 'unknown.sideload', permissions: [] as string[] };
    const dangerousPermissions = manifest.permissions.filter((p) =>
      p.includes('RECEIVE_SMS') ||
      p.includes('READ_SMS') ||
      p.includes('SEND_SMS') ||
      p.includes('RECEIVE_BOOT_COMPLETED') ||
      p.includes('BIND_ACCESSIBILITY_SERVICE') ||
      p.includes('REQUEST_INSTALL_PACKAGES')
    );

    // Scan DEX files
    const botTokens: string[] = [];
    const chatIds: string[] = [];
    const c2Urls: string[] = [];

    for (const dex of dexBuffers) {
      const findings = DexScanner.scan(dex);
      for (const t of findings.telegramBotTokens) if (!botTokens.includes(t)) botTokens.push(t);
      for (const c of findings.telegramChatIds) if (!chatIds.includes(c)) chatIds.push(c);
      for (const u of findings.c2Urls) if (!c2Urls.includes(u)) c2Urls.push(u);
    }

    // Also scan the whole APK buffer directly for any missed tokens
    const wholeScan = DexScanner.scan(apkBuffer);
    for (const t of wholeScan.telegramBotTokens) if (!botTokens.includes(t)) botTokens.push(t);
    for (const c of wholeScan.telegramChatIds) if (!chatIds.includes(c)) chatIds.push(c);
    for (const u of wholeScan.c2Urls) if (!c2Urls.includes(u)) c2Urls.push(u);

    // If no suspicious indicators found, return null
    if (dangerousPermissions.length === 0 && botTokens.length === 0 && c2Urls.length === 0) {
      return null;
    }

    let riskScore: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (botTokens.length > 0 || (dangerousPermissions.includes('android.permission.RECEIVE_SMS') && c2Urls.length > 0)) {
      riskScore = 'CRITICAL';
    } else if (dangerousPermissions.length >= 2) {
      riskScore = 'HIGH';
    } else {
      riskScore = 'MEDIUM';
    }

    const provenance: ForensicProvenance = {
      evidenceId,
      archivePath,
      vfsInternalPath: apkVfsPath,
      containerType: 'RAW_CARVED',
      byteOffset: 0,
      byteLength: apkBuffer.length,
      recoveryState: 'ACTIVE',
      rawPayloadHex: apkBuffer.subarray(0, Math.min(apkBuffer.length, 64)).toString('hex')
    };

    return {
      packageName: manifest.packageName || 'org.mule.forwarder',
      apkVfsPath,
      sha256,
      dangerousPermissions,
      extractedTelegramBotTokens: botTokens,
      extractedTelegramChatIds: chatIds,
      extractedC2Urls: c2Urls,
      isSideloaded: true,
      riskScore,
      provenance
    };
  }

  private static findEocd(buf: Buffer): number {
    const searchLen = Math.min(buf.length, 65536 + 22);
    const start = buf.length - searchLen;
    for (let i = searchLen - 22; i >= 0; i--) {
      if (
        buf[start + i] === 0x50 &&
        buf[start + i + 1] === 0x4b &&
        buf[start + i + 2] === 0x05 &&
        buf[start + i + 3] === 0x06
      ) {
        return start + i;
      }
    }
    return -1;
  }
}
