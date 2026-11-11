import * as fs from 'fs';
import * as zlib from 'zlib';
import { VfsEntry } from '../../shared/forensic-types';

export interface ZipIndexedEntry extends VfsEntry {
  localHeaderOffset: number;
  dataOffset: number;
  compressionMethod: number;
  compressedSize: number;
  crc32: number;
}

/**
 * Strict Read-Only ZIP Indexer that scans ZIP Central Directory structures.
 * Supports direct byte-slice streaming for Stored entries and in-memory raw inflation for Deflated entries.
 * Strictly uses fs.constants.O_RDONLY.
 */
export class ZipIndexer {
  private fd: number | null = null;
  private entries: Map<string, ZipIndexedEntry> = new Map();
  private rootEntries: VfsEntry[] = [];

  constructor(private archivePath: string) {}

  public async indexArchive(): Promise<VfsEntry[]> {
    return new Promise((resolve, reject) => {
      fs.open(this.archivePath, fs.constants.O_RDONLY, (err, fd) => {
        if (err) {
          return reject(new Error(`[ZIP_INDEXER] Failed to open zip archive in O_RDONLY: ${err.message}`));
        }
        this.fd = fd;

        try {
          const stats = fs.fstatSync(fd);
          const totalSize = stats.size;
          if (totalSize < 22) {
            return reject(new Error('[ZIP_INDEXER] File is too small to be a valid ZIP archive.'));
          }

          // Locate End of Central Directory (EOCD) signature 0x06054b50 in the last 65KB
          const searchLen = Math.min(totalSize, 65536 + 22);
          const searchBuf = Buffer.alloc(searchLen);
          const searchStart = totalSize - searchLen;
          fs.readSync(fd, searchBuf, 0, searchLen, searchStart);

          let eocdOffset = -1;
          for (let i = searchLen - 22; i >= 0; i--) {
            if (
              searchBuf[i] === 0x50 &&
              searchBuf[i + 1] === 0x4b &&
              searchBuf[i + 2] === 0x05 &&
              searchBuf[i + 3] === 0x06
            ) {
              eocdOffset = searchStart + i;
              break;
            }
          }

          if (eocdOffset === -1) {
            return reject(new Error('[ZIP_INDEXER] Valid EOCD signature not found in archive.'));
          }

          const eocdBuf = Buffer.alloc(22);
          fs.readSync(fd, eocdBuf, 0, 22, eocdOffset);

          const totalEntries = eocdBuf.readUInt16LE(10);
          const cdSize = eocdBuf.readUInt32LE(12);
          const cdOffset = eocdBuf.readUInt32LE(16);

          // Read Central Directory
          const cdBuf = Buffer.alloc(cdSize);
          fs.readSync(fd, cdBuf, 0, cdSize, cdOffset);

          let offset = 0;
          for (let i = 0; i < totalEntries && offset + 46 <= cdSize; i++) {
            const sig = cdBuf.readUInt32LE(offset);
            if (sig !== 0x02014b50) {
              break; // Not central directory header
            }

            const method = cdBuf.readUInt16LE(offset + 10);
            const crc32 = cdBuf.readUInt32LE(offset + 16);
            const compSize = cdBuf.readUInt32LE(offset + 20);
            const uncompSize = cdBuf.readUInt32LE(offset + 24);
            const nameLen = cdBuf.readUInt16LE(offset + 28);
            const extraLen = cdBuf.readUInt16LE(offset + 30);
            const commentLen = cdBuf.readUInt16LE(offset + 32);
            const localHeaderOffset = cdBuf.readUInt32LE(offset + 42);

            const rawName = cdBuf.toString('utf8', offset + 46, offset + 46 + nameLen);
            const isDir = rawName.endsWith('/') || (cdBuf.readUInt8(offset + 38) & 0x10) !== 0;

            const normalizedPath = rawName.startsWith('/') ? rawName : `/${rawName}`;
            const cleanPath = isDir && normalizedPath.endsWith('/') && normalizedPath.length > 1
              ? normalizedPath.slice(0, -1)
              : normalizedPath;

            const pathSegments = cleanPath.split('/').filter(Boolean);
            const entryName = pathSegments[pathSegments.length - 1] || '/';
            const parentPath = pathSegments.length > 1
              ? '/' + pathSegments.slice(0, -1).join('/')
              : '/';

            // Resolve exact data offset by reading local header
            let dataOffset = localHeaderOffset + 30 + nameLen + extraLen;
            if (localHeaderOffset + 30 <= totalSize) {
              const localHdr = Buffer.alloc(30);
              fs.readSync(fd, localHdr, 0, 30, localHeaderOffset);
              if (localHdr.readUInt32LE(0) === 0x04034b50) {
                const locNameLen = localHdr.readUInt16LE(26);
                const locExtraLen = localHdr.readUInt16LE(28);
                dataOffset = localHeaderOffset + 30 + locNameLen + locExtraLen;
              }
            }

            const entry: ZipIndexedEntry = {
              path: cleanPath,
              name: entryName,
              sizeBytes: uncompSize,
              isDirectory: isDir,
              archiveByteOffset: dataOffset,
              archiveByteLength: compSize,
              parentPath,
              localHeaderOffset,
              dataOffset,
              compressionMethod: method,
              compressedSize: compSize,
              crc32
            };

            this.entries.set(cleanPath, entry);
            offset += 46 + nameLen + extraLen + commentLen;
          }

          this.buildHierarchy();
          resolve(this.rootEntries);
        } catch (scanErr: any) {
          reject(new Error(`[ZIP_INDEXER] Error indexing zip central directory: ${scanErr.message}`));
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

  public getEntry(vfsPath: string): ZipIndexedEntry | undefined {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    return this.entries.get(clean);
  }

  public getAllEntries(): ZipIndexedEntry[] {
    return Array.from(this.entries.values());
  }

  public async readFile(vfsPath: string): Promise<Buffer> {
    if (!this.fd) throw new Error('[ZIP_INDEXER] Archive is not opened.');
    const entry = this.getEntry(vfsPath);
    if (!entry) throw new Error(`[ZIP_INDEXER] Path not found in index: ${vfsPath}`);

    if (entry.isDirectory || entry.sizeBytes === 0) {
      return Buffer.alloc(0);
    }

    const rawCompressed = Buffer.alloc(entry.compressedSize);
    fs.readSync(this.fd, rawCompressed, 0, entry.compressedSize, entry.dataOffset);

    if (entry.compressionMethod === 0) {
      // Stored (no compression)
      return rawCompressed;
    } else if (entry.compressionMethod === 8) {
      // Deflate
      return zlib.inflateRawSync(rawCompressed);
    } else {
      throw new Error(`[ZIP_INDEXER] Unsupported compression method: ${entry.compressionMethod}`);
    }
  }

  public async readSlice(vfsPath: string, internalOffset: number, length: number): Promise<Buffer> {
    const fullBuffer = await this.readFile(vfsPath);
    if (internalOffset >= fullBuffer.length) {
      return Buffer.alloc(0);
    }
    const end = Math.min(internalOffset + length, fullBuffer.length);
    return fullBuffer.subarray(internalOffset, end);
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
