import {
  ChatMessage,
  ForensicProvenance
} from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';
import { SqliteBinaryParser, SqliteDecodedRecord } from '../../sqlite_carver/sqlite_binary';
import { FreeblockCarver } from '../../sqlite_carver/freeblock_carver';
import { WalAnalyzer } from '../../sqlite_carver/wal_analyzer';
import { extractAmountInr, extractUtrFromText, extractVpaFromText } from '../../intelligence/indian_lea_regex';

/**
 * WhatsApp Deep Artifact Parser (msgstore.db, wa.db, pay.db).
 * Recovers active messages, WAL-logged conversations, and carved freeblocks.
 */
export class WhatsAppParser {
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
      if (!vals || vals.length < 2) continue;

      let jid: string | null = null;
      let body: string | null = null;
      let dateVal: any = null;
      let fromMe = false;

      for (const val of vals) {
        if (typeof val === 'string') {
          if (!jid && (val.includes('@s.whatsapp.net') || val.includes('@g.us'))) {
            jid = val;
          } else if (!body && val.length > 0 && !val.includes('@s.whatsapp.net')) {
            body = val;
          }
        } else if (typeof val === 'number') {
          if (val > 100000000000 && !dateVal) {
            dateVal = val;
          } else if (val === 1 && !fromMe) {
            fromMe = true;
          }
        }
      }

      if (body) {
        const utr = extractUtrFromText(body);
        const amount = extractAmountInr(body);
        const vpa = extractVpaFromText(body);

        let paymentAttachment;
        if (amount || utr || vpa) {
          paymentAttachment = {
            amountInr: amount || 0,
            utrNumber: utr || undefined,
            vpa: vpa || undefined,
            status: 'COMPLETED'
          };
        }

        const senderJid = fromMe ? 'me@s.whatsapp.net' : (jid || 'unknown@s.whatsapp.net');
        const senderName = senderJid.split('@')[0];

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
          id: `WA_${rec.pageNumber}_${rec.byteOffset.toString(16)}`,
          threadId: jid || 'chat_unknown',
          sourceApp: 'WhatsApp',
          senderJid,
          senderName,
          body,
          isFromMe: fromMe,
          timestamp: normalizeTimestamp(dateVal || Date.now(), 'UNIX_MS'),
          isDeleted: rec.state !== 'ACTIVE',
          paymentAttachment,
          provenance
        });
      }
    }

    return messages;
  }
}
