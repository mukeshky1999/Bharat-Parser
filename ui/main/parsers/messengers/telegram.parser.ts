import {
  ChatMessage,
  ForensicProvenance
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import { TelegramTlDecoder } from '../../binary_decoders/telegram_tl';

/**
 * Telegram cache4.db TL-Schema Binary Parser.
 */
export class TelegramParser {
  public static parse(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    dbBuffer: Buffer,
    walBuffer?: Buffer
  ): ChatMessage[] {
    const messages: ChatMessage[] = [];
    const parser = new SqliteBinaryParser(dbBuffer);
    const freeCarver = new FreeblockCarver(parser, dbBuffer);

    // Active
    const activeRecords: SqliteDecodedRecord[] = [];
    for (let p = 1; p <= parser.getPageCount(); p++) {
      try {
        activeRecords.push(...parser.parseLeafTablePageCells(p));
      } catch {
        // Skip
      }
    }

    // Carved
    const carvedRecords = freeCarver.carveAllPages();

    // WAL
    let walRecords: SqliteDecodedRecord[] = [];
    if (walBuffer && walBuffer.length > 32) {
      try {
        const walAnalyzer = new WalAnalyzer(walBuffer, parser.getFileHeader().pageSize);
        walRecords = walAnalyzer.recoverAllRecords();
      } catch {
        // Skip
      }
    }

    const allRecords = [...activeRecords, ...walRecords, ...carvedRecords];

    for (const rec of allRecords) {
      const vals = rec.values;
      if (!vals || vals.length === 0) continue;

      let tlMessage = null;

      // Find binary TL-serialized buffer
      for (const val of vals) {
        if (Buffer.isBuffer(val) && val.length > 24) {
          tlMessage = TelegramTlDecoder.decodeMessage(val);
          if (tlMessage) break;
        }
      }

      if (tlMessage && tlMessage.messageText) {
        const provenance: ForensicProvenance = {
          evidenceId,
          archivePath,
          vfsInternalPath: rec.state === 'WAL_RECOVERED' ? `${vfsInternalPath}-wal` : vfsInternalPath,
          containerType: rec.state === 'WAL_RECOVERED' ? 'SQLITE_WAL' : 'SQLITE',
          tableName: 'messages',
          pageNumber: rec.pageNumber,
          rowId: rec.rowId,
          byteOffset: rec.byteOffset,
          byteLength: rec.byteLength,
          recoveryState: rec.state,
          rawPayloadHex: rec.rawPayloadHex
        };

        messages.push({
          id: `TG_${tlMessage.msgId}_${rec.byteOffset.toString(16)}`,
          threadId: `peer_${tlMessage.peerId}`,
          sourceApp: 'Telegram',
          senderJid: `user_${tlMessage.fromId}`,
          senderName: `Telegram User #${tlMessage.fromId}`,
          body: tlMessage.messageText,
          isFromMe: tlMessage.fromId === 0,
          timestamp: normalizeTimestamp(tlMessage.dateEpoch, 'UNIX_SEC'),
          isDeleted: rec.state !== 'ACTIVE',
          provenance
        });
      }
    }

    return messages;
  }
}
