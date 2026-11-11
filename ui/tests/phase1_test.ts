import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { normalizeTimestamp, detectClockTampering } from '../shared/forensic-types';
import { ReadOnlyVFS } from '../main/vfs/read-only-vfs';
import { DualHasher } from '../main/hash-guard/dual-hasher';

export async function runPhase1Tests() {
  console.log('=== [PHASE 1 FORENSIC ENGINE VERIFICATION SUITE] ===\n');

  let passed = 0;
  let total = 0;

  function assert(condition: boolean, testName: string) {
    total++;
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}`);
      throw new Error(`Assertion failed: ${testName}`);
    }
  }

  // TEST 1: Timestamp Normalizer Engine
  console.log('--- 1. Dual-Timezone Normalizer & Timestamp Engine ---');

  // 1a. Unix Milliseconds
  const tsMs = normalizeTimestamp(1760432521000, 'UNIX_MS');
  assert(tsTripletValid(tsMs), 'Unix MS produces valid TimestampTriplet');
  assert(tsMs.istFormatted.includes('+05:30'), 'Unix MS IST includes strictly (+05:30)');

  // 1b. Unix Seconds
  const tsSec = normalizeTimestamp(1760432521, 'UNIX_SEC');
  assert(tsSec.epochMs === 1760432521000, 'Unix SEC converted to exact epochMs');

  // 1c. Unix Microseconds
  const tsUs = normalizeTimestamp(1760432521000000, 'UNIX_US');
  assert(tsUs.epochMs === 1760432521000, 'Unix US converted to exact epochMs');

  // 1d. WebKit Microseconds (Epoch 1601-01-01)
  // Unix epoch 1970-01-01 is 11644473600000000 us in WebKit
  const webKitRaw = 11644473600000000 + 1760432521000000;
  const tsWebKit = normalizeTimestamp(webKitRaw, 'WEBKIT_US');
  assert(tsWebKit.epochMs === 1760432521000, 'WebKit 1601 epoch converted correctly to 1970 Unix milliseconds');

  // 1e. Apple Cocoa Seconds (Epoch 2001-01-01)
  // Difference between 1970 and 2001 is 978307200 seconds
  const cocoaRaw = 1760432521 - 978307200;
  const tsCocoa = normalizeTimestamp(cocoaRaw, 'COCOA_SEC');
  assert(tsCocoa.epochMs === 1760432521000, 'iOS Cocoa 2001 epoch converted correctly to Unix milliseconds');

  // 1f. PhonePe TxID (T + YYMMDDHHmmss + random)
  const phonePeTxId = 'T261014142201991203';
  const tsPhonePe = normalizeTimestamp(phonePeTxId, 'PHONEPE_TXID');
  assert(tsPhonePe.sourceFormat === 'PHONEPE_TXID', 'Detected PHONEPE_TXID format');
  assert(tsPhonePe.istFormatted.startsWith('2026-10-14 14:22:01'), 'PhonePe TxID embedded timestamp decoded to 2026-10-14 14:22:01 IST');

  // 1g. Clock Tamper Detection
  const tamperedRowTs = normalizeTimestamp(1760431500000, 'UNIX_MS'); // 14:15 IST (suspect set clock back)
  const isClockSkewed = detectClockTampering(tamperedRowTs, tsPhonePe, 300000);
  assert(isClockSkewed === true, 'Clock tampering successfully detected for 14-minute clock skew');

  // TEST 2: Dual-Hash Guard & Bit-for-Bit Verifier
  console.log('\n--- 2. Dual-Hash Guard Streaming & Verifier ---');
  const tempDir = os.tmpdir();
  const testTarPath = path.join(tempDir, `bharat_pa_test_${Date.now()}.tar`);

  // Create a genuine POSIX USTAR 512-byte tar archive for testing
  const file1Content = Buffer.from('BHARAT_PA_EVIDENCE_PAYLOAD_TEST_CELL_123456789012');
  const file1Name = 'com.phonepe.app/databases/TransactionsStore.sqlite';
  const tarBuffer = createMockUstarTar(file1Name, file1Content);
  fs.writeFileSync(testTarPath, tarBuffer);

  const initialHashes = await DualHasher.calculateStreamDualHash(testTarPath);
  assert(initialHashes.sha256.length === 64, 'Initial stream SHA-256 generated (64 hex)');
  assert(initialHashes.md5.length === 32, 'Initial stream MD5 generated (32 hex)');
  assert(initialHashes.fileSizeBytes === tarBuffer.length, 'Streamed byte count matches exact file size');

  // Post-ingestion verification
  const verification = await DualHasher.verifyPostIngestion(testTarPath, initialHashes);
  assert(verification.matchConfirmed === true, 'Post-ingestion verification confirms 100% zero byte alteration');

  // TEST 3: Strict Read-Only VFS Streamer
  console.log('\n--- 3. Strict Read-Only VFS (fs.constants.O_RDONLY) ---');
  const vfs = new ReadOnlyVFS(testTarPath);
  const hierarchy = await vfs.open();

  assert(hierarchy.length > 0, 'VFS scanned and constructed directory hierarchy');
  const entry = vfs.getEntry(file1Name);
  assert(entry !== undefined, `VFS found indexed entry: ${file1Name}`);
  assert(entry?.size === file1Content.length, 'VFS indexed exact uncompressed size');
  assert(entry?.archiveByteOffset === 512, 'VFS physical archive byte offset matches USTAR data block');

  // Arbitrary byte slice retrieval (Hex Viewer / Carver simulation)
  const slice = await vfs.readByteRange(file1Name, 10, 8);
  const expectedSlice = file1Content.subarray(10, 18);
  assert(slice.equals(expectedSlice), 'readByteRange returned identical slice bytes in milliseconds');

  vfs.close();
  try {
    fs.unlinkSync(testTarPath);
  } catch {}

  console.log(`\n=== RESULTS: ${passed}/${total} PHASE 1 TESTS PASSED (100% SUCCESS) ===\n`);
}

function tsTripletValid(ts: any): boolean {
  return (
    typeof ts.rawValue !== 'undefined' &&
    typeof ts.utcIso === 'string' &&
    typeof ts.istFormatted === 'string' &&
    typeof ts.epochMs === 'number'
  );
}

/**
 * Creates standard 512-byte block POSIX USTAR archive buffer.
 */
function createMockUstarTar(filename: string, content: Buffer): Buffer {
  const header = Buffer.alloc(512);

  // File name (offset 0, 100 bytes)
  header.write(filename, 0, 100, 'utf8');

  // Mode (offset 100, 8 bytes octal)
  header.write('0000644\0', 100, 8, 'utf8');

  // UID / GID (offset 108/116, 8 bytes octal)
  header.write('0000000\0', 108, 8, 'utf8');
  header.write('0000000\0', 116, 8, 'utf8');

  // Size (offset 124, 12 bytes octal)
  const sizeOctal = content.length.toString(8).padStart(11, '0') + ' ';
  header.write(sizeOctal, 124, 12, 'utf8');

  // MTime (offset 136, 12 bytes octal)
  header.write('14000000000 ', 136, 12, 'utf8');

  // Checksum placeholder spaces (offset 148, 8 bytes)
  header.write('        ', 148, 8, 'utf8');

  // Typeflag '0' (regular file)
  header[156] = 0x30;

  // Magic "ustar\0" (offset 257, 6 bytes)
  header.write('ustar\0', 257, 6, 'utf8');
  // Version "00" (offset 263, 2 bytes)
  header.write('00', 263, 2, 'utf8');

  // Calculate Tar Checksum (sum of unsigned bytes with checksum field as spaces)
  let chksum = 0;
  for (let i = 0; i < 512; i++) {
    chksum += header[i];
  }
  const chksumOctal = chksum.toString(8).padStart(6, '0') + '\0 ';
  header.write(chksumOctal, 148, 8, 'utf8');

  // Pad content to 512-byte boundary
  const paddedContentSize = Math.ceil(content.length / 512) * 512;
  const paddedContent = Buffer.alloc(paddedContentSize);
  content.copy(paddedContent, 0);

  // Tar terminator: two 512-byte zero blocks
  const terminator = Buffer.alloc(1024);

  return Buffer.concat([header, paddedContent, terminator]);
}

// Auto-run if executed directly
if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].includes('phase1_test')) {
  runPhase1Tests().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
