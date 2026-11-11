/**
 * BharatAnalyzer — Secure Electron Preload Script
 * Safely exposes native OS dialogs and app metadata to the renderer window via contextBridge.
 * Follows strict Electron security practices: contextIsolation enabled, nodeIntegration disabled.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Native Windows File Dialog
  openFileDialog: async (options) => {
    try {
      return await ipcRenderer.invoke('dialog:openFile', options);
    } catch (err) {
      console.error('[electronAPI] openFileDialog error:', err);
      return null;
    }
  },

  // Native Windows Folder / Directory Dialog
  openFolderDialog: async (options) => {
    try {
      return await ipcRenderer.invoke('dialog:openDirectory', options);
    } catch (err) {
      console.error('[electronAPI] openFolderDialog error:', err);
      return null;
    }
  },

  // Native Windows Save File Dialog
  saveFileDialog: async (options) => {
    try {
      return await ipcRenderer.invoke('dialog:saveFile', options);
    } catch (err) {
      console.error('[electronAPI] saveFileDialog error:', err);
      return null;
    }
  },

  // Reveal File / Item in Windows Explorer
  showItemInFolder: async (path) => {
    try {
      return await ipcRenderer.invoke('shell:showItemInFolder', path);
    } catch (err) {
      console.error('[electronAPI] showItemInFolder error:', err);
      return false;
    }
  },

  // Direct helper aliases
  pickFile: async (options) => {
    try {
      return await ipcRenderer.invoke('dialog:openFile', options);
    } catch (err) {
      return null;
    }
  },

  pickFolder: async (options) => {
    try {
      return await ipcRenderer.invoke('dialog:openDirectory', options);
    } catch (err) {
      return null;
    }
  },

  // App Metadata & State
  getAppVersion: async () => {
    try {
      return await ipcRenderer.invoke('app:getVersion');
    } catch {
      return '2.0.0';
    }
  },

  isPackaged: async () => {
    try {
      return await ipcRenderer.invoke('app:isPackaged');
    } catch {
      return false;
    }
  },

  // Tree counts IPC fallback if implemented
  getTreeCounts: async () => {
    try {
      return await ipcRenderer.invoke('api:getTreeCounts');
    } catch {
      return null;
    }
  }
});
