import * as fs from 'fs';
import * as path from 'path';
import { VfsEntry } from '../../shared/forensic-types';
import { TarIndexer } from './tar_indexer';
import { ZipIndexer } from './zip_indexer';
import { FolderVfs } from './folder_vfs';

export interface IVirtualFileSystem {
  open(): Promise<VfsEntry[]>;
  close(): void;
  getEntry(vfsPath: string): VfsEntry | undefined;
  getAllEntries(): VfsEntry[];
  readFile(vfsPath: string): Promise<Buffer>;
  readSlice(vfsPath: string, offset: number, length: number): Promise<Buffer>;
  getPhysicalArchivePath(): string;
  getExactArchiveByteOffset(vfsPath: string, internalOffset: number): number;
}

/**
 * Universal Forensic VFS Manager.
 * Seamlessly interfaces .tar, .zip, .ab, .ufd, and physical dump directories.
 * Strictly read-only (fs.constants.O_RDONLY).
 */
export class ForensicVfsManager implements IVirtualFileSystem {
  private backend: TarIndexer | ZipIndexer | FolderVfs | null = null;
  private backendType: 'TAR' | 'ZIP' | 'FOLDER' = 'FOLDER';

  constructor(private evidencePath: string) {}

  public async open(): Promise<VfsEntry[]> {
    const stat = fs.statSync(this.evidencePath);

    if (stat.isDirectory()) {
      this.backendType = 'FOLDER';
      this.backend = new FolderVfs(this.evidencePath);
      return (this.backend as FolderVfs).indexDirectory();
    }

    const ext = path.extname(this.evidencePath).toLowerCase();

    // Check magic bytes
    const fd = fs.openSync(this.evidencePath, fs.constants.O_RDONLY);
    const magicBuf = Buffer.alloc(16);
    fs.readSync(fd, magicBuf, 0, 16, 0);
    fs.closeSync(fd);

    if (ext === '.zip' || (magicBuf[0] === 0x50 && magicBuf[1] === 0x4B)) {
      this.backendType = 'ZIP';
      this.backend = new ZipIndexer(this.evidencePath);
      return (this.backend as ZipIndexer).indexArchive();
    } else {
      // Default to Tar indexer for .tar, .tar.gz (decompressed), or raw Android data tar
      this.backendType = 'TAR';
      this.backend = new TarIndexer(this.evidencePath);
      return (this.backend as TarIndexer).indexArchive();
    }
  }

  public getEntry(vfsPath: string): VfsEntry | undefined {
    if (!this.backend) throw new Error('[VFS] VFS is not opened.');
    return this.backend.getEntry(vfsPath);
  }

  public getAllEntries(): VfsEntry[] {
    if (!this.backend) throw new Error('[VFS] VFS is not opened.');
    return this.backend.getAllEntries();
  }

  public async readFile(vfsPath: string): Promise<Buffer> {
    if (!this.backend) throw new Error('[VFS] VFS is not opened.');
    return this.backend.readFile(vfsPath);
  }

  public async readSlice(vfsPath: string, offset: number, length: number): Promise<Buffer> {
    if (!this.backend) throw new Error('[VFS] VFS is not opened.');
    return this.backend.readSlice(vfsPath, offset, length);
  }

  public getPhysicalArchivePath(): string {
    return this.evidencePath;
  }

  public getExactArchiveByteOffset(vfsPath: string, internalOffset: number): number {
    const entry = this.getEntry(vfsPath);
    if (!entry) return 0;
    return entry.archiveByteOffset + internalOffset;
  }

  public close(): void {
    if (this.backend) {
      this.backend.close();
      this.backend = null;
    }
  }
}
