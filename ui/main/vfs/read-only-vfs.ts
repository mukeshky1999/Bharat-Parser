import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { VfsNode } from '../../shared/forensic-types';

export interface VfsIndexRecord {
  vfsPath: string;
  name: string;
  archiveByteOffset: number;  // Physical byte offset in evidence archive where raw data begins
  size: number;               // Uncompressed byte size
  isCompressed: boolean;      // True if deflated/compressed
  compressionMethod?: number; // 0 = Stored, 8 = Deflated
  compressedSize?: number;    // Compressed byte size in archive
  isDirectory: boolean;
  dataOffset: number;         // Direct pointer to data stream in archive
  parentPath: string;
}

/**
 * Strict Read-Only Virtual File System (VFS) Indexer.
 * Scans .tar (POSIX USTAR) and .zip (Central Directory) dumps using fs.constants.O_RDONLY.
 * Indexes archive structures without disk extraction and exposes sub-millisecond arbitrary byte-range streaming.
 */
export class ReadOnlyVFS {
  private fd: number | null = null;
  private archiveType: 'TAR' | 'ZIP' = 'TAR';
  private index: Map<string, VfsIndexRecord> = new Map();
  private rootNodes: VfsNode[] = [];

  constructor(private archivePath: string) {}

  public async open(): Promise<VfsNode[]> {
    return new Promise((resolve, reject) => {
      // Enforce strict read-only mode at kernel level
      fs.open(this.archivePath, fs.constants.O_RDONLY, (err, fd) => {
        if (err) {
          return reject(
            new Error(`[READ_ONLY_VFS] Failed to open evidence source with O_RDONLY: ${err.message}`)
          );
        }

        this.fd = fd;

        try {
          const stats = fs.fstatSync(fd);
          const totalSize = stats.size;

          if (totalSize === 0) {
            return reject(new Error('[READ_ONLY_VFS] Evidence file has 0 bytes length.'));
          }

          // Read initial magic bytes
          const magicBuf = Buffer.alloc(16);
          fs.readSync(fd, magicBuf, 0, 16, 0);

          const isZip =
            (magicBuf[0] === 0x50 && magicBuf[1] === 0x4b) ||
            path.extname(this.archivePath).toLowerCase() === '.zip';

          if (isZip) {
            this.archiveType = 'ZIP';
            this.indexZipArchive(totalSize);
          } else {
            this.archiveType = 'TAR';
            this.indexTarArchive(totalSize);
          }

          this.buildHierarchy();
          resolve(this.rootNodes);
        } catch (scanErr: any) {
          this.close();
          reject(new Error(`[READ_ONLY_VFS] Indexing failed: ${scanErr.message}`));
        }
      });
    });
  }

  /**
   * Scans 512-byte POSIX USTAR tar blocks sequentially without extracting data.
   */
  private indexTarArchive(totalSize: number): void {
    if (!this.fd) return;

    let currentOffset = 0;
    const headerBuf = Buffer.alloc(512);
    let nextLongName: string | null = null;

    while (currentOffset + 512 <= totalSize) {
      fs.readSync(this.fd, headerBuf, 0, 512, currentOffset);

      // Check if block is null terminator (tar ends with two 512-byte zero blocks)
      let isZero = true;
      for (let i = 0; i < 512; i++) {
        if (headerBuf[i] !== 0) {
          isZero = false;
          break;
        }
      }

      if (isZero) {
        currentOffset += 512;
        continue;
      }

      // POSIX Tar Header parsing
      let fileName = headerBuf.toString('utf8', 0, 100).replace(/\0.*$/g, '').trim();
      const sizeStr = headerBuf.toString('utf8', 124, 136).replace(/\0.*$/g, '').trim();
      const fileSize = parseInt(sizeStr, 8) || 0;
      const typeFlag = String.fromCharCode(headerBuf[156]);

      // USTAR Prefix (bytes 345..500)
      const prefix = headerBuf.toString('utf8', 345, 500).replace(/\0.*$/g, '').trim();
      if (prefix.length > 0) {
        fileName = `${prefix}/${fileName}`;
      }

      const dataOffset = currentOffset + 512;

      if (typeFlag === 'L') {
        // GNU Long Link name
        const nameBuf = Buffer.alloc(fileSize);
        fs.readSync(this.fd, nameBuf, 0, fileSize, dataOffset);
        nextLongName = nameBuf.toString('utf8').replace(/\0.*$/g, '').trim();
      } else {
        if (nextLongName) {
          fileName = nextLongName;
          nextLongName = null;
        }

        const normalizedPath = fileName.startsWith('/') ? fileName : `/${fileName}`;
        const isDir = typeFlag === '5' || normalizedPath.endsWith('/');

        const cleanPath = isDir && normalizedPath.endsWith('/') && normalizedPath.length > 1
          ? normalizedPath.slice(0, -1)
          : normalizedPath;

        const pathSegments = cleanPath.split('/').filter(Boolean);
        const name = pathSegments[pathSegments.length - 1] || '/';
        const parentPath = pathSegments.length > 1
          ? '/' + pathSegments.slice(0, -1).join('/')
          : '/';

        const record: VfsIndexRecord = {
          vfsPath: cleanPath,
          name,
          archiveByteOffset: dataOffset,
          size: fileSize,
          isCompressed: false,
          compressionMethod: 0,
          compressedSize: fileSize,
          isDirectory: isDir,
          dataOffset,
          parentPath
        };

        this.index.set(cleanPath, record);
      }

      // Next block is 512-byte aligned
      const paddedSize = Math.ceil(fileSize / 512) * 512;
      currentOffset = dataOffset + paddedSize;
    }
  }

  /**
   * Scans ZIP End of Central Directory (EOCD) & Central Directory headers for random access.
   */
  private indexZipArchive(totalSize: number): void {
    if (!this.fd) return;

    if (totalSize < 22) {
      throw new Error('[READ_ONLY_VFS] ZIP archive too small for valid EOCD.');
    }

    // Search last 65KB for EOCD signature 0x06054b50
    const searchLen = Math.min(totalSize, 65536 + 22);
    const searchBuf = Buffer.alloc(searchLen);
    const searchStart = totalSize - searchLen;
    fs.readSync(this.fd, searchBuf, 0, searchLen, searchStart);

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
      throw new Error('[READ_ONLY_VFS] ZIP EOCD record signature not found.');
    }

    const eocdBuf = Buffer.alloc(22);
    fs.readSync(this.fd, eocdBuf, 0, 22, eocdOffset);

    const totalEntries = eocdBuf.readUInt16LE(10);
    const cdSize = eocdBuf.readUInt32LE(12);
    const cdOffset = eocdBuf.readUInt32LE(16);

    const cdBuf = Buffer.alloc(cdSize);
    fs.readSync(this.fd, cdBuf, 0, cdSize, cdOffset);

    let offset = 0;
    for (let i = 0; i < totalEntries && offset + 46 <= cdSize; i++) {
      const sig = cdBuf.readUInt32LE(offset);
      if (sig !== 0x02014b50) break;

      const method = cdBuf.readUInt16LE(offset + 10);
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
      const name = pathSegments[pathSegments.length - 1] || '/';
      const parentPath = pathSegments.length > 1
        ? '/' + pathSegments.slice(0, -1).join('/')
        : '/';

      // Read local header to determine exact data start
      let dataOffset = localHeaderOffset + 30 + nameLen + extraLen;
      if (localHeaderOffset + 30 <= totalSize) {
        const localHdr = Buffer.alloc(30);
        fs.readSync(this.fd, localHdr, 0, 30, localHeaderOffset);
        if (localHdr.readUInt32LE(0) === 0x04034b50) {
          const locNameLen = localHdr.readUInt16LE(26);
          const locExtraLen = localHdr.readUInt16LE(28);
          dataOffset = localHeaderOffset + 30 + locNameLen + locExtraLen;
        }
      }

      const record: VfsIndexRecord = {
        vfsPath: cleanPath,
        name,
        archiveByteOffset: dataOffset,
        size: uncompSize,
        isCompressed: method !== 0,
        compressionMethod: method,
        compressedSize: compSize,
        isDirectory: isDir,
        dataOffset,
        parentPath
      };

      this.index.set(cleanPath, record);
      offset += 46 + nameLen + extraLen + commentLen;
    }
  }

  private buildHierarchy(): void {
    const map = new Map<string, VfsNode>();

    for (const [vPath, record] of this.index.entries()) {
      map.set(vPath, {
        vfsPath: record.vfsPath,
        name: record.name,
        size: record.size,
        isDirectory: record.isDirectory,
        archiveByteOffset: record.archiveByteOffset,
        isCompressed: record.isCompressed,
        compressionMethod: record.compressionMethod,
        parentPath: record.parentPath,
        children: []
      });
    }

    const roots: VfsNode[] = [];
    for (const node of map.values()) {
      if (node.parentPath === '/' || !map.has(node.parentPath)) {
        roots.push(node);
      } else {
        const parent = map.get(node.parentPath);
        if (parent) {
          parent.children = parent.children || [];
          parent.children.push(node);
        }
      }
    }

    this.rootNodes = roots;
  }

  /**
   * Reads an arbitrary byte slice in milliseconds directly from the archive.
   * If entry is uncompressed (tar or zip Stored), directly seeks to physical offset.
   * If deflated, streams and inflates raw bytes.
   */
  public async readByteRange(vfsPath: string, offset: number, length: number): Promise<Buffer> {
    if (!this.fd) throw new Error('[READ_ONLY_VFS] Evidence file descriptor is not open.');

    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    const record = this.index.get(clean);

    if (!record) {
      throw new Error(`[READ_ONLY_VFS] Path not found in index: ${vfsPath}`);
    }

    if (record.isDirectory || record.size === 0 || offset >= record.size) {
      return Buffer.alloc(0);
    }

    const targetReadLen = Math.min(length, record.size - offset);

    if (!record.isCompressed) {
      // Zero-copy direct disk read for uncompressed tar / zip stored entries
      const physicalOffset = record.dataOffset + offset;
      const targetBuffer = Buffer.alloc(targetReadLen);
      fs.readSync(this.fd, targetBuffer, 0, targetReadLen, physicalOffset);
      return targetBuffer;
    } else if (record.compressionMethod === 8 && record.compressedSize) {
      // Deflated entry
      const compressedBuf = Buffer.alloc(record.compressedSize);
      fs.readSync(this.fd, compressedBuf, 0, record.compressedSize, record.dataOffset);
      const decompressed = zlib.inflateRawSync(compressedBuf);
      return decompressed.subarray(offset, offset + targetReadLen);
    } else {
      throw new Error(`[READ_ONLY_VFS] Unsupported compression method: ${record.compressionMethod}`);
    }
  }

  /**
   * Reads an entire file buffer from the VFS.
   */
  public async readFile(vfsPath: string): Promise<Buffer> {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    const record = this.index.get(clean);
    if (!record) {
      throw new Error(`[READ_ONLY_VFS] Path not found in index: ${vfsPath}`);
    }
    return this.readByteRange(vfsPath, 0, record.size);
  }

  public getEntry(vfsPath: string): VfsIndexRecord | undefined {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    return this.index.get(clean);
  }

  public getAllEntries(): VfsIndexRecord[] {
    return Array.from(this.index.values());
  }

  public getHierarchy(): VfsNode[] {
    return this.rootNodes;
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
