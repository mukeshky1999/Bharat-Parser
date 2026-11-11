import * as crypto from 'crypto';

export interface DecryptionResult {
  success: boolean;
  decryptedBuffer?: Buffer;
  error?: string;
  isKeyMissing?: boolean;
}

/**
 * SQLCipher and Crypt14/15 Offline Decryptor using Node Crypto.
 * Supports AES-256-CBC (SQLCipher default) and AES-256-GCM.
 */
export class SqlcipherCrypto {
  /**
   * Attempts SQLCipher page-by-page decryption using raw key or passphrase.
   * Default SQLCipher: 4096-byte page, 16-byte salt at start of Page 1, AES-256-CBC, PBKDF2 with 256,000 or 64,000 iterations.
   */
  public static decryptSqlCipher(
    encryptedBuf: Buffer,
    rawKeyOrPass: Buffer | string,
    pageSize: number = 4096,
    kdfIter: number = 256000
  ): DecryptionResult {
    if (!rawKeyOrPass) {
      return {
        success: false,
        isKeyMissing: true,
        error: '[ENCRYPTED - KEY NOT IN DUMP]'
      };
    }

    try {
      if (encryptedBuf.length < pageSize) {
        return { success: false, error: 'Database buffer is smaller than one page.' };
      }

      // First 16 bytes of Page 1 is the salt in SQLCipher
      const salt = encryptedBuf.subarray(0, 16);
      let encKey: Buffer;

      if (Buffer.isBuffer(rawKeyOrPass) && rawKeyOrPass.length === 32) {
        encKey = rawKeyOrPass;
      } else {
        const passBuf = typeof rawKeyOrPass === 'string' ? Buffer.from(rawKeyOrPass, 'utf8') : rawKeyOrPass;
        encKey = crypto.pbkdf2Sync(passBuf, salt, kdfIter, 32, 'sha512');
      }

      const totalPages = Math.floor(encryptedBuf.length / pageSize);
      const outBuf = Buffer.alloc(totalPages * pageSize);

      // Decrypt page by page
      for (let p = 0; p < totalPages; p++) {
        const pageOffset = p * pageSize;
        const pageEnc = encryptedBuf.subarray(pageOffset, pageOffset + pageSize);

        // SQLCipher reserve area is 48 bytes at the end of each page (IV is last 16 bytes before HMAC or reserve)
        const ivOffset = pageSize - 48;
        if (ivOffset <= 0) continue;
        const iv = pageEnc.subarray(ivOffset, ivOffset + 16);
        const dataToDecrypt = pageEnc.subarray(p === 0 ? 16 : 0, ivOffset);

        const decipher = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
        decipher.setAutoPadding(false);

        const decryptedPart = Buffer.concat([
          decipher.update(dataToDecrypt),
          decipher.final()
        ]);

        if (p === 0) {
          // Put SQLite format magic in Page 1 header
          Buffer.from('SQLite format 3\0').copy(outBuf, 0);
          decryptedPart.copy(outBuf, 16);
        } else {
          decryptedPart.copy(outBuf, pageOffset);
        }
      }

      return {
        success: true,
        decryptedBuffer: outBuf
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Decryption failed: ${err.message}`
      };
    }
  }

  /**
   * Decrypts WhatsApp crypt14 / crypt15 message store using harvested 32-byte AES key.
   */
  public static decryptWhatsAppCrypt14(
    encryptedBuf: Buffer,
    aesKey: Buffer
  ): DecryptionResult {
    if (!aesKey || aesKey.length < 32) {
      return {
        success: false,
        isKeyMissing: true,
        error: '[ENCRYPTED - KEY NOT IN DUMP]'
      };
    }

    try {
      // WhatsApp crypt14 format: 190 bytes header, IV at offset 67 (16 bytes), ciphertext follows
      if (encryptedBuf.length < 190) {
        return { success: false, error: 'WhatsApp crypt file is too small.' };
      }

      const iv = encryptedBuf.subarray(67, 83);
      const cipherText = encryptedBuf.subarray(190);

      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey.subarray(0, 32), iv);
      // Last 16 bytes of encrypted file is the GCM auth tag
      const tag = cipherText.subarray(cipherText.length - 16);
      const payload = cipherText.subarray(0, cipherText.length - 16);

      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([
        decipher.update(payload),
        decipher.final()
      ]);

      return {
        success: true,
        decryptedBuffer: decrypted
      };
    } catch (err: any) {
      return {
        success: false,
        error: `WhatsApp Crypt14/15 decryption failed: ${err.message}`
      };
    }
  }
}
