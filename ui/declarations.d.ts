declare module '*.css' {
  const content: any;
  export default content;
}

interface ElectronAPI {
  openFileDialog: (options?: {
    title?: string;
    defaultPath?: string;
    filters?: Array<{ name: string; extensions: string[] }>;
  }) => Promise<string | null>;
  openFolderDialog: (options?: {
    title?: string;
    defaultPath?: string;
  }) => Promise<string | null>;
  saveFileDialog: (options?: {
    title?: string;
    defaultPath?: string;
    buttonLabel?: string;
    filters?: Array<{ name: string; extensions: string[] }>;
  }) => Promise<string | null>;
  showItemInFolder: (path: string) => Promise<boolean>;
  pickFile: (options?: any) => Promise<string | null>;
  pickFolder: (options?: any) => Promise<string | null>;
  getAppVersion: () => Promise<string>;
  isPackaged: () => Promise<boolean>;
  getTreeCounts: () => Promise<any>;
}

interface Window {
  electronAPI?: ElectronAPI;
  electron?: {
    ipcRenderer?: any;
  };
}
