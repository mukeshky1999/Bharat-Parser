export interface TelegramDecodedMessage {
  msgId: number;
  fromId: number;
  peerId: number;
  dateEpoch: number;
  messageText: string;
  hasMedia: boolean;
  mediaType?: string;
  flags: number;
}

/**
 * Telegram Type Language (TL) Binary Deserializer.
 * Decodes MTProto / Telegram serialized message buffers stored in cache4.db.
 */
export class TelegramTlDecoder {
  public static decodeMessage(buf: Buffer): TelegramDecodedMessage | null {
    if (buf.length < 24) return null;

    try {
      // Telegram TL constructors start with 4-byte constructor ID
      const constructorId = buf.readUInt32LE(0);
      let offset = 4;

      const flags = buf.readUInt32LE(offset);
      offset += 4;

      const msgId = buf.readUInt32LE(offset);
      offset += 4;

      let fromId = 0;
      if (flags & 0x100) {
        // from_id peer
        const peerType = buf.readUInt32LE(offset);
        fromId = buf.readUInt32LE(offset + 4);
        offset += 8;
      }

      // peer_id
      const peerType = buf.readUInt32LE(offset);
      const peerId = buf.readUInt32LE(offset + 4);
      offset += 8;

      // date (Unix epoch seconds)
      const dateEpoch = buf.readUInt32LE(offset);
      offset += 4;

      // Extract message string: Telegram TL string format:
      // If len < 254: 1 byte len, followed by bytes, padded to 4-byte boundary
      // If len >= 254: byte 0xFE, followed by 3-byte len LE, followed by bytes, padded to 4-byte boundary
      let messageText = '';
      if (offset < buf.length) {
        let strLen = buf[offset];
        offset += 1;

        if (strLen === 0xFE) {
          strLen = buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16);
          offset += 3;
        }

        if (strLen > 0 && offset + strLen <= buf.length) {
          messageText = buf.toString('utf8', offset, offset + strLen);
          // Padding to 4-byte boundary
          const pad = (4 - ((strLen + (strLen >= 254 ? 4 : 1)) % 4)) % 4;
          offset += strLen + pad;
        }
      }

      // If messageText is empty, do a fallback string search in the buffer
      if (!messageText) {
        const rawStr = buf.toString('utf8');
        const match = /[\x20-\x7E\r\n]{4,}/g;
        const matches: string[] = [];
        let m: RegExpExecArray | null;
        while ((m = match.exec(rawStr)) !== null) {
          matches.push(m[0]);
        }
        if (matches.length > 0) {
          messageText = matches.join(' ');
        }
      }

      return {
        msgId,
        fromId,
        peerId,
        dateEpoch,
        messageText,
        hasMedia: (flags & 0x200) !== 0,
        flags
      };
    } catch {
      return null;
    }
  }
}
