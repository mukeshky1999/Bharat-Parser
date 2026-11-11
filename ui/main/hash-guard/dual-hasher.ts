import * as fs from 'fs';
import * as crypto from 'crypto';
import { DualHashResult } from '../../shared/forensic-types';

export interface VerificationReport {
  preIngestionHash: DualHashResult;
  postIngestionHash: DualHashResult;
  matchConfirmed: boolean;
  verifiedAt: string;
}

/**
 * Dual-Hash Guard for strict forensic integrity verification.
 * Simultaneously calculates SHA-256 and MD5 using streaming with O_RDONLY file descriptors.
 * Proves zero byte alteration before and after forensic analysis.
 */
export class DualHasher {
  /**
   * Computes SHA-256 and MD5 hashes simultaneously over a file stream in O_RDONLY mode.
   */
  public static async calculateStreamDualHash(filePath: string): Promise<DualHashResult> {
    return new Promise((resolve, reject) => {
      fs.open(filePath, fs.constants.O_RDONLY, (openErr, fd) => {
        if (openErr) {
          return reject(
            new Error(`[DUAL_HASHER] Failed to open evidence file in O_RDONLY mode: ${openErr.message}`)
          );
        }

        const md5Hash = crypto.createHash('md5');
        const sha256Hash = crypto.createHash('sha256');
        let totalBytes = 0;

        const stream = fs.createReadStream('', {
          fd,
          autoClose: true,
          highWaterMark: 1024 * 1024 // 1MB streaming buffer
        });

        stream.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          md5Hash.update(chunk);
          sha256Hash.update(chunk);
        });

        stream.on('end', () => {
          const md5 = md5Hash.digest('hex');
          const sha256 = sha256Hash.digest('hex');

          resolve({
            md5,
            sha256,
            fileSizeBytes: totalBytes,
            verified: true,
            calculatedAt: new Date().toISOString()
          });
        });

        stream.on('error', (streamErr) => {
          reject(new Error(`[DUAL_HASHER] Stream error during dual-hash calculation: ${streamErr.message}`));
        });
      });
    });
  }

  /**
   * Computes dual hashes for an in-memory buffer slice.
   */
  public static calculateBufferDualHash(buffer: Buffer): DualHashResult {
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    return {
      md5,
      sha256,
      fileSizeBytes: buffer.length,
      verified: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Performs post-ingestion verification against a known pre-ingestion seal.
   */
  public static async verifyPostIngestion(
    filePath: string,
    preIngestion: DualHashResult
  ): Promise<VerificationReport> {
    const postIngestion = await DualHasher.calculateStreamDualHash(filePath);

    const matchConfirmed =
      preIngestion.sha256 === postIngestion.sha256 &&
      preIngestion.md5 === postIngestion.md5 &&
      preIngestion.fileSizeBytes === postIngestion.fileSizeBytes;

    return {
      preIngestionHash: preIngestion,
      postIngestionHash: postIngestion,
      matchConfirmed,
      verifiedAt: new Date().toISOString()
    };
  }
}

// Convenience export aliases matching function signatures
export const calculateEvidenceDualHash = DualHasher.calculateStreamDualHash;
export const calculateBufferDualHash = DualHasher.calculateBufferDualHash;
export const verifyHashMatch = (before: DualHashResult, after: DualHashResult): boolean =>
  before.sha256 === after.sha256 && before.md5 === after.md5 && before.fileSizeBytes === after.fileSizeBytes;
