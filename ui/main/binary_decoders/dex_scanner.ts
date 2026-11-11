import { readVarint } from '../sqlite_carver/sqlite_binary';

export interface DexScanFindings {
  telegramBotTokens: string[];
  telegramChatIds: string[];
  c2Urls: string[];
  stringsFoundCount: number;
}

/**
 * Dalvik Executable (DEX) Binary Parser & Cybercrime IoC Harvester.
 * Extracts Telegram Bot Tokens, Chat IDs, and C2 URLs embedded in classes.dex.
 */
export class DexScanner {
  public static scan(dexBuffer: Buffer): DexScanFindings {
    const findings: DexScanFindings = {
      telegramBotTokens: [],
      telegramChatIds: [],
      c2Urls: [],
      stringsFoundCount: 0
    };

    if (dexBuffer.length < 112) return findings;

    const magic = dexBuffer.toString('utf8', 0, 8);
    const isDex = magic.startsWith('dex\n');

    const extractedStrings: string[] = [];

    if (isDex) {
      try {
        const stringIdsSize = dexBuffer.readUInt32LE(56);
        const stringIdsOff = dexBuffer.readUInt32LE(60);

        for (let i = 0; i < stringIdsSize; i++) {
          const idOffset = stringIdsOff + i * 4;
          if (idOffset + 4 > dexBuffer.length) break;

          const dataOff = dexBuffer.readUInt32LE(idOffset);
          if (dataOff >= dexBuffer.length) continue;

          // Read ULEB128 string length
          const uleb = readVarint(dexBuffer, dataOff);
          const strStart = dataOff + uleb.length;
          let strEnd = strStart;

          while (strEnd < dexBuffer.length && dexBuffer[strEnd] !== 0) {
            strEnd++;
          }

          if (strEnd <= dexBuffer.length) {
            const strVal = dexBuffer.toString('utf8', strStart, strEnd);
            extractedStrings.push(strVal);
          }
        }
      } catch {
        // Fallback to regex scan
      }
    }

    // Combine strings with raw buffer search to guarantee zero misses
    const fullText = dexBuffer.toString('latin1');

    // 1. Telegram Bot Token Regex: matches bot[0-9]{8,11}:[A-Za-z0-9_-]{34,36} or naked tokens
    const botTokenRegex = /(?:bot)?([0-9]{8,11}:[A-Za-z0-9_\-]{34,36})/g;
    let match: RegExpExecArray | null;

    while ((match = botTokenRegex.exec(fullText)) !== null) {
      const token = match[1];
      if (!findings.telegramBotTokens.includes(token)) {
        findings.telegramBotTokens.push(token);
      }
    }

    // 2. Telegram Chat ID Regex: chat_id=12345678 or "chat_id":"-1001234567"
    const chatIdRegex = /chat_id["']?\s*[:=]\s*["']?(-?[0-9]{7,15})["']?/gi;
    while ((match = chatIdRegex.exec(fullText)) !== null) {
      const chatId = match[1];
      if (!findings.telegramChatIds.includes(chatId)) {
        findings.telegramChatIds.push(chatId);
      }
    }

    // 3. C2 URLs: http/https endpoints, ngrok, duckdns, suspicious endpoints
    const c2Regex = /https?:\/\/[a-zA-Z0-9.-]+(?::[0-9]{2,5})?(?:\/[a-zA-Z0-9_.~!*';:@&=+$,/?%#[\]-]*)?/g;
    while ((match = c2Regex.exec(fullText)) !== null) {
      const url = match[0];
      // Filter benign standard Android / Google namespaces
      if (
        !url.includes('schemas.android.com') &&
        !url.includes('www.w3.org') &&
        !url.includes('apache.org') &&
        !url.includes('github.com/google') &&
        !findings.c2Urls.includes(url)
      ) {
        findings.c2Urls.push(url);
      }
    }

    findings.stringsFoundCount = extractedStrings.length;
    return findings;
  }
}
