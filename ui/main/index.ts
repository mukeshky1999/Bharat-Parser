import { app, BrowserWindow, ipcMain, dialog, session } from 'electron';
import * as path from 'path';
import { ForensicIpcManager } from './ipc/forensic-ipc';
import { ForensicVfsManager } from './vfs/vfs_reader';
import { calculateEvidenceDualHash } from './hash_guard/dual_hasher';
import { ForensicParserRegistry } from './parsers/registry';
import { CaseManager } from './case_manager/case_db';
import { Sec63BsaGenerator } from './reporting/sec63_bsa_generator';

let mainWindow: BrowserWindow | null = null;
let activeVfs: ForensicVfsManager | null = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: 'BHARAT-PA Forensics — Post-Acquisition Cybercrime Engine',
    backgroundColor: '#020617',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: true
    }
  });

  // Strict Air-Gap Enforcement: Intercept and block all external network traffic
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const url = details.url.toLowerCase();
    if (
      url.startsWith('http://localhost') ||
      url.startsWith('http://127.0.0.1') ||
      url.startsWith('file://') ||
      url.startsWith('devtools://')
    ) {
      callback({ cancel: false });
    } else {
      console.warn(`[AIR_GAP_ENFORCEMENT] Blocked external network request to: ${details.url}`);
      callback({ cancel: true });
    }
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
    if (activeVfs) {
      activeVfs.close();
      activeVfs = null;
    }
  });
}

app.whenReady().then(() => {
  ForensicIpcManager.registerHandlers();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Ingestion Handlers
ipcMain.handle('vfs:open-dump', async (_, filePath?: string) => {
  let targetPath = filePath;
  if (!targetPath) {
    const res = await dialog.showOpenDialog({
      properties: ['openFile', 'openDirectory'],
      filters: [
        { name: 'Forensic Extraction Dumps', extensions: ['tar', 'zip', 'ufd', 'ab'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });
    if (res.canceled || res.filePaths.length === 0) return null;
    targetPath = res.filePaths[0];
  }

  if (activeVfs) {
    activeVfs.close();
  }

  activeVfs = new ForensicVfsManager(targetPath);
  const vfsEntries = await activeVfs.open();
  const hashes = await calculateEvidenceDualHash(targetPath);

  return {
    filePath: targetPath,
    entriesCount: vfsEntries.length,
    hashes
  };
});

ipcMain.handle('vfs:read-slice', async (_, vfsPath: string, offset: number, length: number) => {
  if (!activeVfs) throw new Error('[IPC_VFS] VFS is not opened.');
  const buf = await activeVfs.readSlice(vfsPath, offset, length);
  return buf.toString('hex');
});

ipcMain.handle('parser:run-carving', async (_, evidenceId: string) => {
  if (!activeVfs) throw new Error('[IPC_PARSER] VFS is not opened.');
  const result = await ForensicParserRegistry.executeFullExtraction(activeVfs, evidenceId);
  return result;
});
