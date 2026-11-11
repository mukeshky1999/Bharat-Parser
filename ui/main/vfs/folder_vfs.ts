import * as fs from 'fs';
import * as path from 'path';
import { VfsEntry } from '../../shared/forensic-types';

/**
 * Strict Read-Only Logical Directory VFS Reader.
 * Traverses an offline logical extraction folder using fs.constants.O_RDONLY.
 */
export class FolderVfs {
  private entries: Map<string, VfsEntry> = new Map();
  private rootEntries: VfsEntry[] = [];

  constructor(private basePath: string) {}

  public async indexDirectory(): Promise<VfsEntry[]> {
    this.entries.clear();
    this.traverse(this.basePath, '/');
    this.buildHierarchy();
    return this.rootEntries;
  }

  private traverse(physicalDir: string, vfsDir: string): void {
    const items = fs.readdirSync(physicalDir);
    for (const item of items) {
      const fullPhysical = path.join(physicalDir, item);
      const stat = fs.statSync(fullPhysical);
      const currentVfs = path.posix.join(vfsDir, item);

      const entry: VfsEntry = {
        path: currentVfs,
        name: item,
        sizeBytes: stat.size,
        isDirectory: stat.isDirectory(),
        archiveByteOffset: 0,
        archiveByteLength: stat.size,
        parentPath: vfsDir
      };

      this.entries.set(currentVfs, entry);

      if (stat.isDirectory()) {
        this.traverse(fullPhysical, currentVfs);
      }
    }
  }

  private buildHierarchy(): void {
    const map = new Map<string, VfsEntry>();
    for (const [p, entry] of this.entries.entries()) {
      map.set(p, { ...entry, children: [] });
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

  public getEntry(vfsPath: string): VfsEntry | undefined {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    return this.entries.get(clean);
  }

  public getAllEntries(): VfsEntry[] {
    return Array.from(this.entries.values());
  }

  public async readFile(vfsPath: string): Promise<Buffer> {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    const relativePart = clean.replace(/^\//, '');
    const physicalPath = path.join(this.basePath, relativePart);

    return new Promise((resolve, reject) => {
      fs.open(physicalPath, fs.constants.O_RDONLY, (err, fd) => {
        if (err) return reject(new Error(`[FOLDER_VFS] Cannot open ${physicalPath}: ${err.message}`));
        const stat = fs.fstatSync(fd);
        const buf = Buffer.alloc(stat.size);
        fs.read(fd, buf, 0, stat.size, 0, (readErr) => {
          fs.closeSync(fd);
          if (readErr) return reject(readErr);
          resolve(buf);
        });
      });
    });
  }

  public async readSlice(vfsPath: string, internalOffset: number, length: number): Promise<Buffer> {
    const clean = vfsPath.startsWith('/') ? vfsPath : `/${vfsPath}`;
    const relativePart = clean.replace(/^\//, '');
    const physicalPath = path.join(this.basePath, relativePart);

    return new Promise((resolve, reject) => {
      fs.open(physicalPath, fs.constants.O_RDONLY, (err, fd) => {
        if (err) return reject(new Error(`[FOLDER_VFS] Cannot open ${physicalPath}: ${err.message}`));
        const stat = fs.fstatSync(fd);
        if (internalOffset >= stat.size) {
          fs.closeSync(fd);
          return resolve(Buffer.alloc(0));
        }

        const readLen = Math.min(length, stat.size - internalOffset);
        const buf = Buffer.alloc(readLen);
        fs.read(fd, buf, 0, readLen, internalOffset, (readErr) => {
          fs.closeSync(fd);
          if (readErr) return reject(readErr);
          resolve(buf);
        });
      });
    });
  }

  public close(): void {
    // No persistent file handles
  }
}
