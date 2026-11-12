/**
 * BharatAnalyzer — Native Electron Desktop Shell (Main Process)
 * Orchestrates Python FastAPI Forensic Backend Lifecycle, Native Windows OS Dialogs,
 * and React 19 Frontend Workbench with Zero-Zombie Process Termination.
 */

const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require('electron');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');

let mainWindow = null;
let backendProcess = null;
let isShuttingDown = false;

const BACKEND_HOST = '127.0.0.1';
const DEV_FRONTEND_URL = 'http://localhost:3000';

// Per-launch secrets/ports. The shell never reuses a backend it did not start: a process that is
// already listening on a fixed port could be anything, and would receive the evidence paths.
const API_TOKEN = crypto.randomBytes(32).toString('hex');
let backendPort = 0;
const backendBase = () => `http://${BACKEND_HOST}:${backendPort}`;
const healthUrl = () => `${backendBase()}/api/health`;

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, BACKEND_HOST, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// The backend does not need the examiner's whole environment (tokens, proxies, API keys).
const ENV_ALLOW = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT',
  'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'ProgramFiles', 'HOMEDRIVE',
  'HOMEPATH', 'USERNAME', 'LANG', 'LC_ALL'];
function backendEnv() {
  const env = {};
  for (const k of ENV_ALLOW) if (process.env[k] !== undefined) env[k] = process.env[k];
  return {
    ...env,
    PYTHONUNBUFFERED: '1',
    PYTHONIOENCODING: 'utf-8',
    HOST: BACKEND_HOST,
    PORT: String(backendPort),
    BHARAT_API_TOKEN: API_TOKEN,
  };
}

// Only pages we ship may talk to the privileged IPC handlers.
function isTrustedUrl(url) {
  if (typeof url !== 'string') return false;
  if (url === DEV_FRONTEND_URL || url.startsWith(DEV_FRONTEND_URL + '/')) return !app.isPackaged;
  if (!url.startsWith('file://')) return false;
  const dist = path.resolve(PROJECT_ROOT, 'dist');
  try {
    const p = path.resolve(require('url').fileURLToPath(url));
    return p === dist || p.startsWith(dist + path.sep);
  } catch {
    return false;
  }
}
function trustedSender(event) {
  const url = event && event.senderFrame ? event.senderFrame.url : '';
  return isTrustedUrl(url);
}

const PROJECT_ROOT = path.resolve(__dirname, '..');

// -----------------------------------------------------------------------------
// 1. Backend Health Check Utility
// -----------------------------------------------------------------------------
function checkBackendHealth() {
  return new Promise((resolve) => {
    const req = http.get(healthUrl(), { timeout: 1500, headers: { 'X-Bharat-Token': API_TOKEN } }, (res) => {
      if (res.statusCode === 200) {
        resolve(true);
      } else {
        resolve(false);
      }
    });

    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForBackend(maxAttempts = 40, intervalMs = 500) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (isShuttingDown) return false;
    const isHealthy = await checkBackendHealth();
    if (isHealthy) {
      console.log(`[BharatAnalyzer] Backend online and healthy at ${healthUrl()} (Attempt ${attempt})`);
      return true;
    }
    await new Promise((res) => setTimeout(res, intervalMs));
  }
  return false;
}

// -----------------------------------------------------------------------------
// 2. Python Backend Lifecycle Management
// -----------------------------------------------------------------------------
function findPythonExecutable() {
  const venvPython = path.join(PROJECT_ROOT, '.venv', 'Scripts', 'python.exe');
  if (fs.existsSync(venvPython)) return venvPython;

  const parentVenv = path.join(PROJECT_ROOT, '..', '.venv', 'Scripts', 'python.exe');
  if (fs.existsSync(parentVenv)) return parentVenv;

  const standardVenv = path.join(PROJECT_ROOT, 'venv', 'Scripts', 'python.exe');
  if (fs.existsSync(standardVenv)) return standardVenv;

  return process.platform === 'win32' ? 'python' : 'python3';
}

function findProductionBackendExe() {
  const candidatePaths = [
    // Standard electron-builder extraResources path
    path.join(process.resourcesPath, 'backend', 'bharat_backend.exe'),
    path.join(process.resourcesPath, 'backend', 'bharat_backend', 'bharat_backend.exe'),
    // Relative to dev / test build output
    path.join(PROJECT_ROOT, 'dist_backend', 'bharat_backend', 'bharat_backend.exe'),
    path.join(PROJECT_ROOT, 'resources', 'backend', 'bharat_backend.exe'),
    path.join(PROJECT_ROOT, 'resources', 'backend', 'bharat_backend', 'bharat_backend.exe'),
    path.join(app.getAppPath(), '..', 'backend', 'bharat_backend.exe'),
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

async function startBackend() {
  backendPort = await getFreePort();

  if (app.isPackaged) {
    // Packaged Production Mode: Launch bundled PyInstaller executable
    const backendExe = findProductionBackendExe();
    if (!backendExe) {
      console.error('[BharatAnalyzer] FATAL: Bundled backend executable not found in resources/backend!');
      dialog.showErrorBox(
        'Backend Service Missing',
        'Could not locate the bundled Python forensic engine (bharat_backend.exe). Please reinstall BharatAnalyzer.'
      );
      return;
    }

    console.log(`[BharatAnalyzer] Spawning bundled forensic engine: ${backendExe}`);
    try {
      backendProcess = spawn(backendExe, [], {
        cwd: path.dirname(backendExe),
        env: backendEnv(),
        stdio: 'pipe',
        windowsHide: true,
      });

      backendProcess.stdout?.on('data', (d) => console.log(`[Backend-Out] ${d.toString().trim()}`));
      backendProcess.stderr?.on('data', (d) => console.error(`[Backend-Err] ${d.toString().trim()}`));

      backendProcess.on('exit', (code) => {
        console.log(`[BharatAnalyzer] Backend process exited with code ${code}`);
        backendProcess = null;
      });
    } catch (err) {
      console.error('[BharatAnalyzer] Failed to spawn backend process:', err);
    }
  } else {
    // Development Mode: Spawn python -m parsers.api_server from virtualenv
    const pythonExe = findPythonExecutable();
    console.log(`[BharatAnalyzer DEV] Spawning Python server with: ${pythonExe} -m parsers.api_server`);

    try {
      backendProcess = spawn(pythonExe, ['-m', 'parsers.api_server'], {
        cwd: PROJECT_ROOT,
        env: backendEnv(),
        stdio: 'inherit',
      });

      backendProcess.on('exit', (code) => {
        console.log(`[BharatAnalyzer DEV] Python server process exited with code ${code}`);
        backendProcess = null;
      });
    } catch (err) {
      console.error('[BharatAnalyzer DEV] Failed to launch Python server:', err);
    }
  }

  // Wait for health check confirmation
  const isReady = await waitForBackend();
  if (!isReady) {
    console.warn('[BharatAnalyzer] Backend health check timed out. Continuing frontend initialization...');
  }
}

function stopBackend() {
  if (isShuttingDown) return;
  isShuttingDown = true;

  if (backendProcess && backendProcess.pid) {
    const pid = backendProcess.pid;
    console.log(`[BharatAnalyzer] Terminating backend process tree (PID: ${pid})...`);

    if (process.platform === 'win32') {
      try {
        spawnSync('taskkill', ['/pid', String(pid), '/T', '/F']);
      } catch (err) {
        console.error('[BharatAnalyzer] Error executing taskkill:', err);
      }
    }

    try {
      backendProcess.kill('SIGTERM');
      backendProcess.kill('SIGKILL');
    } catch {
      // Process already dead
    }
    backendProcess = null;
  }
}

// -----------------------------------------------------------------------------
// 3. Electron Window Creation & Navigation
// -----------------------------------------------------------------------------
function createWindow() {
  mainWindow = new BrowserWindow({
    title: 'BharatAnalyzer — Digital Forensics & Financial Intelligence Workbench',
    width: 1600,
    height: 960,
    minWidth: 1280,
    minHeight: 720,
    backgroundColor: '#0b1120',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      // Read by preload.cjs: where this launch's backend is and the token it requires.
      additionalArguments: [`--bharat-api=${backendBase()}`, `--bharat-token=${API_TOKEN}`],
    },
  });

  // The window may only ever show our own UI: no navigation away, no new windows, no permissions.
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isTrustedUrl(url)) event.preventDefault();
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.session.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));

  Menu.setApplicationMenu(null);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Load UI
  loadAppUrl();
}

async function loadAppUrl() {
  if (!mainWindow) return;

  const candidateDistPaths = [
    path.join(__dirname, '..', 'dist', 'index.html'),
    path.join(PROJECT_ROOT, 'dist', 'index.html'),
  ];
  const foundDistPath = candidateDistPaths.find((p) => fs.existsSync(p));

  if (!app.isPackaged) {
    // In dev mode, quickly check if Vite dev server is running on port 3000
    let devServerReady = false;
    for (let i = 0; i < 3; i++) {
      try {
        await new Promise((resolve, reject) => {
          const req = http.get(DEV_FRONTEND_URL, (res) => {
            if (res.statusCode === 200) resolve(true);
            else reject(new Error('Vite not ready'));
          });
          req.on('error', reject);
          req.setTimeout(300, () => {
            req.destroy();
            reject(new Error('Timeout'));
          });
        });
        devServerReady = true;
        break;
      } catch {
        await new Promise((res) => setTimeout(res, 200));
      }
    }

    if (devServerReady) {
      mainWindow.loadURL(DEV_FRONTEND_URL);
    } else {
      console.warn('[BharatAnalyzer DEV] Vite dev server not responding on port 3000. Loading built dist/index.html fallback.');
      if (foundDistPath) {
        mainWindow.loadFile(foundDistPath);
      } else {
        mainWindow.loadURL(DEV_FRONTEND_URL);
      }
    }
  } else {
    // Production Mode: Load compiled Vite bundle
    if (foundDistPath) {
      mainWindow.loadFile(foundDistPath);
    } else {
      console.error(`[BharatAnalyzer] Missing compiled UI bundle at: ${path.join(__dirname, '..', 'dist', 'index.html')}`);
      mainWindow.loadURL('data:text/plain,Missing compiled UI bundle (dist/index.html). Run the build.');
    }
  }
}

// -----------------------------------------------------------------------------
// 4. Native Dialog IPC Handlers
// -----------------------------------------------------------------------------
function registerIpcHandlers() {
  // Native Open File Dialog
  ipcMain.handle('dialog:openFile', async (event, customOptions = {}) => {
    if (!mainWindow || !trustedSender(event)) return null;

    const defaultFilters = [
      {
        name: 'Forensic Evidence Containers & Databases',
        extensions: ['ufdr', 'ufd', 'tar', 'gz', 'zip', 'xry', 'ofb', 'ab', 'db', 'sqlite', 'csv', 'xlsx'],
      },
      { name: 'All Evidence Files', extensions: ['*'] },
    ];

    const result = await dialog.showOpenDialog(mainWindow, {
      title: customOptions.title || 'Select Forensic Evidence Container or File',
      defaultPath: customOptions.defaultPath || undefined,
      buttonLabel: 'Select Evidence',
      properties: ['openFile'],
      filters: customOptions.filters || defaultFilters,
    });

    if (result.canceled || !result.filePaths.length) {
      return null;
    }
    return result.filePaths[0];
  });

  // Native Open Directory / Folder Dialog
  ipcMain.handle('dialog:openDirectory', async (event, customOptions = {}) => {
    if (!mainWindow || !trustedSender(event)) return null;

    const result = await dialog.showOpenDialog(mainWindow, {
      title: customOptions.title || 'Select Extracted Forensic Dump Folder',
      defaultPath: customOptions.defaultPath || undefined,
      buttonLabel: 'Select Folder',
      properties: ['openDirectory', 'createDirectory'],
    });

    if (result.canceled || !result.filePaths.length) {
      return null;
    }
    return result.filePaths[0];
  });

  // Native Save File Dialog (Court Certificates, NCRP CSV, BNSS Bundles)
  ipcMain.handle('dialog:saveFile', async (event, customOptions = {}) => {
    if (!mainWindow || !trustedSender(event)) return null;

    const result = await dialog.showSaveDialog(mainWindow, {
      title: customOptions.title || 'Save Court Evidence Report / Requisition',
      defaultPath: customOptions.defaultPath || 'Section_63_BSA_Certificate.html',
      buttonLabel: customOptions.buttonLabel || 'Save Report',
      filters: customOptions.filters || [
        { name: 'HTML Court Reports (*.html)', extensions: ['html'] },
        { name: '1930 NCRP Freeze CSV (*.csv)', extensions: ['csv'] },
        { name: 'All Files (*.*)', extensions: ['*'] },
      ],
    });

    if (result.canceled || !result.filePath) {
      return null;
    }
    return result.filePath;
  });

  // Native Open/Reveal File in Explorer
  ipcMain.handle('shell:showItemInFolder', async (event, fullPath) => {
    // Reveal only: a local absolute path that exists. No UNC/network paths, no relative paths.
    const isUnc = typeof fullPath === 'string' && fullPath.slice(0, 2) === String.fromCharCode(92, 92);
    if (!trustedSender(event) || typeof fullPath !== 'string' || !path.isAbsolute(fullPath) || isUnc) return false;
    if (fs.existsSync(fullPath)) {
      shell.showItemInFolder(fullPath);
      return true;
    }
    return false;
  });

  // App Metadata Handlers
  ipcMain.handle('app:getVersion', () => app.getVersion());
  ipcMain.handle('app:isPackaged', () => app.isPackaged);

  // Fallback IPC handler for tree counts if needed
  ipcMain.handle('api:getTreeCounts', async (event) => {
    try {
      if (!trustedSender(event)) return null;
      return await new Promise((resolve) => {
        http.get(`${backendBase()}/api/case/tree-counts`, { headers: { 'X-Bharat-Token': API_TOKEN } }, (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.counts || null);
            } catch {
              resolve(null);
            }
          });
        }).on('error', () => resolve(null));
      });
    } catch {
      return null;
    }
  });
}

// -----------------------------------------------------------------------------
// 5. App Lifecycle & Process Termination
// -----------------------------------------------------------------------------
app.whenReady().then(async () => {
  registerIpcHandlers();
  await startBackend();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopBackend();
});

app.on('will-quit', () => {
  stopBackend();
});

process.on('SIGINT', () => {
  stopBackend();
  process.exit(0);
});

process.on('SIGTERM', () => {
  stopBackend();
  process.exit(0);
});
