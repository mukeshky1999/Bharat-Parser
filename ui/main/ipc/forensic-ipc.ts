import { ipcMain, dialog, IpcMainInvokeEvent } from 'electron';
import * as path from 'path';
import { ReadOnlyVFS } from '../vfs/read-only-vfs';
import { DualHasher } from '../hash-guard/dual-hasher';
import { DualHashResult, VfsNode, CaseManifest, normalizeTimestamp } from '../../shared/forensic-types';

export class ForensicIpcManager {
  private static activeVfs: ReadOnlyVFS | null = null;
  private static activeEvidencePath: string | null = null;
  private static preIngestionHashes: DualHashResult | null = null;

  public static registerHandlers(): void {
    // 1. Ingest Offline Forensic Dump (.tar, .zip, .ufd, .ab)
    ipcMain.handle('vfs:open-dump', async (event: IpcMainInvokeEvent, explicitPath?: string) => {
      try {
        let targetPath = explicitPath;

        if (!targetPath) {
          const dialogResult = await dialog.showOpenDialog({
            title: 'Select Offline Forensic Extraction Archive',
            properties: ['openFile'],
            filters: [
              { name: 'Forensic Dumps (*.tar, *.zip, *.ufd, *.ab)', extensions: ['tar', 'zip', 'ufd', 'ab'] },
              { name: 'All Files (*.*)', extensions: ['*'] }
            ]
          });

          if (dialogResult.canceled || dialogResult.filePaths.length === 0) {
            return { success: false, canceled: true };
          }

          targetPath = dialogResult.filePaths[0];
        }

        // Close any previously active VFS
        if (ForensicIpcManager.activeVfs) {
          ForensicIpcManager.activeVfs.close();
          ForensicIpcManager.activeVfs = null;
        }

        // 1. Compute Pre-Ingestion Dual-Hash Seal (SHA-256 + MD5 in strict O_RDONLY)
        const hashes = await DualHasher.calculateStreamDualHash(targetPath);
        ForensicIpcManager.preIngestionHashes = hashes;
        ForensicIpcManager.activeEvidencePath = targetPath;

        // 2. Open and index the archive in strict read-only mode without extracting to disk
        const vfs = new ReadOnlyVFS(targetPath);
        const hierarchy = await vfs.open();
        ForensicIpcManager.activeVfs = vfs;

        const allEntries = vfs.getAllEntries();
        const fileName = path.basename(targetPath);

        const manifest: CaseManifest = {
          caseId: `CASE-${Date.now()}`,
          caseNumber: 'CASE-2026-CYB-09',
          firNumber: 'FIR-402/2026',
          policeStation: 'Cyber Crime Police Station, Bengaluru',
          district: 'Bengaluru Urban',
          examinerName: 'Senior Digital Forensic Examiner',
          evidencePath: targetPath,
          evidenceFileName: fileName,
          fileSizeBytes: hashes.fileSizeBytes,
          preIngestionHashes: hashes,
          indexedAt: normalizeTimestamp(Date.now(), 'UNIX_MS'),
          totalFilesIndexed: allEntries.length
        };

        return {
          success: true,
          manifest,
          hierarchy,
          totalFiles: allEntries.length,
          hashes
        };
      } catch (err: any) {
        return {
          success: false,
          error: `[IPC_VFS_OPEN_FAILED] ${err.message}`
        };
      }
    });

    // 2. Stream Arbitrary Byte Range for Hex Viewer & SQLite Carver
    ipcMain.handle(
      'vfs:read-byte-range',
      async (event: IpcMainInvokeEvent, vfsPath: string, offset: number, length: number) => {
        try {
          if (!ForensicIpcManager.activeVfs) {
            throw new Error('No forensic evidence archive is currently loaded.');
          }

          const buf = await ForensicIpcManager.activeVfs.readByteRange(vfsPath, offset, length);

          // Convert bytes to ASCII string (substitute non-printable with '.')
          const asciiChars: string[] = [];
          for (let i = 0; i < buf.length; i++) {
            const b = buf[i];
            asciiChars.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
          }

          return {
            success: true,
            rawHex: buf.toString('hex'),
            ascii: asciiChars.join(''),
            byteOffset: offset,
            byteLength: buf.length
          };
        } catch (err: any) {
          return {
            success: false,
            error: `[IPC_READ_RANGE_FAILED] ${err.message}`
          };
        }
      }
    );

    // 3. Read Entire File Buffer from VFS
    ipcMain.handle('vfs:read-file', async (event: IpcMainInvokeEvent, vfsPath: string) => {
      try {
        if (!ForensicIpcManager.activeVfs) {
          throw new Error('No forensic evidence archive is currently loaded.');
        }

        const buf = await ForensicIpcManager.activeVfs.readFile(vfsPath);

        return {
          success: true,
          rawHex: buf.toString('hex'),
          sizeBytes: buf.length
        };
      } catch (err: any) {
        return {
          success: false,
          error: `[IPC_READ_FILE_FAILED] ${err.message}`
        };
      }
    });

    // 4. Verify Post-Ingestion Bit-for-Bit Hash Integrity
    ipcMain.handle('vfs:verify-integrity', async () => {
      try {
        if (!ForensicIpcManager.activeEvidencePath || !ForensicIpcManager.preIngestionHashes) {
          throw new Error('No baseline pre-ingestion hashes exist to verify.');
        }

        const report = await DualHasher.verifyPostIngestion(
          ForensicIpcManager.activeEvidencePath,
          ForensicIpcManager.preIngestionHashes
        );

        return {
          success: true,
          report
        };
      } catch (err: any) {
        return {
          success: false,
          error: `[IPC_INTEGRITY_VERIFY_FAILED] ${err.message}`
        };
      }
    });

    // 5. Query Specific Entry Metadata
    ipcMain.handle('vfs:get-entry', async (event: IpcMainInvokeEvent, vfsPath: string) => {
      if (!ForensicIpcManager.activeVfs) return null;
      return ForensicIpcManager.activeVfs.getEntry(vfsPath) || null;
    });

    // 6. Close VFS & Release Handles
    ipcMain.handle('vfs:close', async () => {
      if (ForensicIpcManager.activeVfs) {
        ForensicIpcManager.activeVfs.close();
        ForensicIpcManager.activeVfs = null;
        ForensicIpcManager.activeEvidencePath = null;
        ForensicIpcManager.preIngestionHashes = null;
      }
      return { success: true };
    });
  }

  public static getActiveVfs(): ReadOnlyVFS | null {
    return ForensicIpcManager.activeVfs;
  }
}
