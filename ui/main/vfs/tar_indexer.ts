import * as fs from 'fs';
import { VfsEntry } from '../../shared/forensic-types';

export interface TarIndexedEntry extends VfsEntry {
  headerOffset: number;
  dataOffset: number;
}

/**
 * Strict Read-Only Tar Indexer that scans POSIX / UStar tar archives without disk extraction.
 * Uses fs.constants.O_RDONLY.
 */
export class TarIndexer {
  private fd: number | null = null;
  private entries: Map<string, TarIndexedEntry> = new Map();
  private rootEntries: VfsEntry[] = [];

  constructor(private archivePath: string) {}

  public async indexArchive(): Promise<VfsEntry[]> {
    return new Promise((resolve, reject) => {
      fs.open(this.archivePath, fs.constants.O_RDONLY, (err, fd) => {
        if (err) {
          return reject(new Error(`[TAR_INDEXER] Failed to open tar archive in O_RDONLY: ${err.message}`));
        }
        this.fd = fd;

        try {
          const stats = fs.fstatSync(fd);
          const totalSize = stats.size;
          let currentOffset = 0;
          const headerBuf = Buffer.alloc(512);

          let nextLongName: string | null = null;

          while (currentOffset + 512 <= totalSize) {
            fs.readSync(fd, headerBuf, 0, 512, currentOffset);

            // If header is all zeroes, check next block (tar ends with two 512-byte blocks of zeroes)
            let isZeroBlock = true;
            for (let i = 0; i < 512; i++) {
              if (headerBuf[i] !== 0) {
                isZeroBlock = false;
                break;
              }
            }

            if (isZeroBlock) {
              currentOffset += 512;
              continue;
            }

            // Parse file name (offset 0, 100 bytes)
            let fileName = headerBuf.toString('utf8', 0, 100).replace(/\0.*$/g, '').trim();
            // Parse file size in octal (offset 124, 12 bytes)
            const sizeStr = headerBuf.toString('utf8', 124, 136).replace(/\0.*$/g, '').trim();
            const fileSize = parseInt(sizeStr, 8) || 0;

            // Typeflag (offset 156, 1 byte)
            const typeFlag = String.fromCharCode(headerBuf[156]);

            // Prefix for UStar (offset 345, 155 bytes)
            const prefix = headerBuf.toString('utf8', 345, 500).replace(/\0.*$/g, '').trim();
            if (prefix.length > 0) {
              fileName = `${prefix}/${fileName}`;
            }

            const dataOffset = currentOffset + 512;

            if (typeFlag === 'L') {
              // GNU Long Name header
              const nameBuf = Buffer.alloc(fileSize);
              fs.readSync(fd, nameBuf, 0, fileSize, dataOffset);
              nextLongName = nameBuf.toString('utf8').replace(/\0.*$/g, '').trim();
            } else {
              if (nextLongName) {
                fileName = nextLongName;
                nextLongName = null;
              }

              // Normalize path with leading slash
              const normalizedPath = fileName.startsWith('/') ? fileName : `/${fileName}`;
              const isDir = typeFlag === '5' || normalizedPath.endsWith('/');

              const cleanPath = isDir && normalizedPath.endsWith('/') && normalizedPath.length > 1
                ? normalizedPath.slice(0, -1)
                : normalizedPath;

              const pathSegments = cleanPath.split('/').filter(Boolean);
              const entryName = pathSegments[pathSegments.length - 1] || '/';
              const parentPath = pathSegments.length > 1
                ? '/' + pathSegments.slice(0, -1).join('/')
                : '/';

              const entry: TarIndexedEntry = {
                path: cleanPath,
                name: entryName,
                sizeBytes: fileSize,
                isDirectory: isDir,
                archiveByteOffset: dataOffset,
                archiveByteLength: fileSize,
                parentPath,
                headerOffset: currentOffset,
                dataOffset
              };

              this.entries.set(cleanPath, entry);
            }

            // Calculate next block boundary (512-byte aligned)
            const paddedSize = Math.ceil(fileSize / 512) * 512;
            currentOffset = dataOffset + paddedSize;
          }

          this.buildHierarchy();
          resolve(this.rootEntries);
        } catch (scanErr: any) {
          reject(new Error(`[TAR_INDEXER] Error indexing tar structure: ${scanErr.message}`));
        }
      });
    });
  }

  private buildHierarchy(): void {
    const map = new Map<string, VfsEntry>();
    for (const [path, entry] of this.entries.entries()) {
      map.set(path, { ...entry, children: [] });
    }

    const roots: VfsEntry[] = [];
    for (const entry of map.values()) {
      if (entry.parentPath === '/' || !map.has(entry.parentPath)) {
        roots.push(entry);
      } else {
        const parent = map.get(entry.parentPath);
        if (parent) {
          parent.children = parent.children || [];
          parent.children.push(entry);
        }
      }
    }
    this.rootEntries = roots;
  }

  public getEntry(vfsPath: string): TarIndexedEntry | undefined {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    return this.entries.get(clean);
  }

  public getAllEntries(): TarIndexedEntry[] {
    return Array.from(this.entries.values());
  }

  public async readSlice(vfsPath: string, internalOffset: number, length: number): Promise<Buffer> {
    if (!this.fd) throw new Error('[TAR_INDEXER] Archive is not opened.');
    const entry = this.getEntry(vfsPath);
    if (!entry) throw new Error(`[TAR_INDEXER] Path not found in index: ${vfsPath}`);

    if (internalOffset >= entry.sizeBytes) {
      return Buffer.alloc(0);
    }

    const readLen = Math.min(length, entry.sizeBytes - internalOffset);
    const targetBuffer = Buffer.alloc(readLen);
    const physicalOffset = entry.dataOffset + internalOffset;

    fs.readSync(this.fd, targetBuffer, 0, readLen, physicalOffset);
    return targetBuffer;
  }

  public async readFile(vfsPath: string): Promise<Buffer> {
    const entry = this.getEntry(vfsPath);
    if (!entry) throw new Error(`[TAR_INDEXER] Path not found in index: ${vfsPath}`);
    return this.readSlice(vfsPath, 0, entry.sizeBytes);
  }

  public close(): void {
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        // Safe close ignore
      }
      this.fd = null;
    }
  }
}
