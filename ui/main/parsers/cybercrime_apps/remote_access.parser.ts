import { ForensicProvenance, RemoteAccessSession } from '../../../shared/forensic-types';
import { normalizeTimestamp } from '../../case_manager/timestamp_engine';

/**
 * Remote Access Tool Forensic Parser.
 * Ingests AnyDesk (ad_svc.trace), TeamViewer, and RustDesk connection logs.
 */
export class RemoteAccessParser {
  public static parse(
    evidenceId: string,
    archivePath: string,
    vfsInternalPath: string,
    logBuffer: Buffer
  ): RemoteAccessSession[] {
    const sessions: RemoteAccessSession[] = [];
    const text = logBuffer.toString('utf8');
    const lines = text.split(/\r?\n/);

    const isAnyDesk = vfsInternalPath.includes('anydesk') || text.includes('anydesk');
    const isTeamViewer = vfsInternalPath.includes('teamviewer') || text.includes('teamviewer');
    const isRustDesk = vfsInternalPath.includes('rustdesk') || text.includes('rustdesk');

    const toolType = isAnyDesk ? 'AnyDesk' : (isTeamViewer ? 'TeamViewer' : 'RustDesk');
    let lineByteOffset = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineLen = Buffer.byteLength(line, 'utf8') + 1;

      // AnyDesk pattern: "Logged in from 928371948" or "Incoming session from 928 371 948"
      const anydeskMatch = /(?:Incoming session from|Logged in from|Remote client:?)\s*([0-9\s]{9,12})/i.exec(line);
      // TeamViewer pattern: "ID: 1 234 567 890" or "PartnerID: 123456789"
      const tvMatch = /(?:PartnerID|Client ID|Remote ID)[:\s]*([0-9\s]{9,11})/i.exec(line);

      const targetMatch = anydeskMatch || tvMatch;

      if (targetMatch) {
        const rawClientId = targetMatch[1].replace(/\s+/g, '');
        const incoming = line.toLowerCase().includes('incom') || line.toLowerCase().includes('from');

        // Extract date from line if present (e.g. 2026-10-14 14:22:01)
        const dateMatch = /\b(20[2-9][0-9]-[0-1][0-9]-[0-3][0-9][\sT][0-2][0-9]:[0-5][0-9]:[0-5][0-9])/i.exec(line);
        let epochMs = Date.now();
        if (dateMatch) {
          epochMs = new Date(dateMatch[1].replace(' ', 'T') + 'Z').getTime();
        }

        const provenance: ForensicProvenance = {
          evidenceId,
          archivePath,
          vfsInternalPath,
          containerType: 'RAW_CARVED',
          byteOffset: lineByteOffset,
          byteLength: lineLen,
          recoveryState: 'ACTIVE',
          rawPayloadHex: Buffer.from(line).subarray(0, 48).toString('hex')
        };

        sessions.push({
          id: `${toolType}_${rawClientId}_${i}`,
          tool: toolType,
          remoteClientId: rawClientId,
          incoming,
          connectedAt: normalizeTimestamp(epochMs, 'UNIX_MS'),
          provenance
        });
      }

      lineByteOffset += lineLen;
    }

    return sessions;
  }
}
