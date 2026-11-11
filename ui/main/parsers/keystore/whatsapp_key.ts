export interface WhatsAppHarvestedKey {
  keyBuffer: Buffer;
  keyHex: string;
  keyOffset: number;
}

/**
 * WhatsApp Crypt14/15 /files/key Harvester.
 * Extracts the 32-byte AES cipher key from Android /data/data/com.whatsapp/files/key.
 */
export class WhatsAppKeyHarvester {
  public static harvestKey(keyFileBuffer: Buffer): WhatsAppHarvestedKey | null {
    // WhatsApp key file is typically 158 bytes. Key resides in the last 32 bytes (offset 126..158).
    if (keyFileBuffer.length < 158) {
      if (keyFileBuffer.length === 32) {
        return {
          keyBuffer: keyFileBuffer,
          keyHex: keyFileBuffer.toString('hex'),
          keyOffset: 0
        };
      }
      return null;
    }

    const keySlice = keyFileBuffer.subarray(126, 158);
    return {
      keyBuffer: keySlice,
      keyHex: keySlice.toString('hex'),
      keyOffset: 126
    };
  }
}
