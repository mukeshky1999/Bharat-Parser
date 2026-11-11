import * as fs from 'fs';
import * as zlib from 'zlib';
import { DeviceMetadata } from '../../shared/forensic-types';
import { normalizeTimestamp } from '../case_manager/timestamp_engine';

export interface AbHeaderInfo {
  magic: string;
  backupVersion: number;
  compressed: boolean;
  encryptionAlgorithm: string;
  isEncrypted: boolean;
  dataOffset: number;
}

export interface UfdMetadataInfo {
  deviceModel?: string;
  manufacturer?: string;
  serialNumber?: string;
  imei?: string;
  androidVersion?: string;
  buildNumber?: string;
  extractionType?: string;
  examinerName?: string;
  rawParams: Record<string, string>;
}

/**
 * Android Backup (.ab) Header and Deflate Stream Handler.
 */
export class AbUnpacker {
  public static parseHeader(filePath: string): AbHeaderInfo {
    const fd = fs.openSync(filePath, fs.constants.O_RDONLY);
    try {
      const headerBuf = Buffer.alloc(1024);
      fs.readSync(fd, headerBuf, 0, 1024, 0);

      const headerText = headerBuf.toString('utf8');
      const lines = headerText.split('\n');

      const magic = lines[0]?.trim() || '';
      if (!magic.startsWith('ANDROID BACKUP')) {
        throw new Error(`[AB_UNPACKER] Not a valid Android Backup file. Magic: "${magic}"`);
      }

      const backupVersion = parseInt(lines[1]?.trim() || '1', 10);
      const compressed = (lines[2]?.trim() || '1') === '1';
      const encryptionAlgorithm = lines[3]?.trim() || 'none';
      const isEncrypted = encryptionAlgorithm.toLowerCase() !== 'none';

      let offset = 0;
      let lineCount = 0;
      const targetLines = isEncrypted ? 9 : 4;

      for (let i = 0; i < headerBuf.length; i++) {
        if (headerBuf[i] === 0x0A) {
          lineCount++;
          if (lineCount === targetLines) {
            offset = i + 1;
            break;
          }
        }
      }

      return {
        magic,
        backupVersion,
        compressed,
        encryptionAlgorithm,
        isEncrypted,
        dataOffset: offset
      };
    } finally {
      fs.closeSync(fd);
    }
  }
}

/**
 * Cellebrite UFED (.ufd) XML/INI metadata parser.
 */
export class UfdParser {
  public static parseUfd(filePath: string): UfdMetadataInfo {
    const fd = fs.openSync(filePath, fs.constants.O_RDONLY);
    try {
      const stat = fs.fstatSync(fd);
      const buf = Buffer.alloc(stat.size);
      fs.readSync(fd, buf, 0, stat.size, 0);
      const text = buf.toString('utf8');

      const params: Record<string, string> = {};
      const lines = text.split(/\r?\n/);

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[') || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx !== -1) {
          const k = trimmed.substring(0, eqIdx).trim().toLowerCase();
          const v = trimmed.substring(eqIdx + 1).trim();
          params[k] = v;
        }
      }

      return {
        deviceModel: params['model'] || params['device model'] || params['devicemodel'],
        manufacturer: params['vendor'] || params['manufacturer'] || params['make'],
        serialNumber: params['serial no'] || params['serialnumber'] || params['device serial number'],
        imei: params['imei'] || params['imei 1'] || params['imei1'],
        androidVersion: params['os version'] || params['android version'] || params['os'],
        buildNumber: params['build number'] || params['build'],
        extractionType: params['extraction type'] || params['extractiontype'],
        examinerName: params['examiner name'] || params['examiner'],
        rawParams: params
      };
    } finally {
      fs.closeSync(fd);
    }
  }
}
