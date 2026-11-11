import { readSqliteVarint, decodeSerialType, decodeRecordPayload } from '../main/carvers/sqlite-varint';
import { SqliteBinaryCarver } from '../main/carvers/sqlite-binary-carver';
import { WalCarver } from '../main/carvers/wal-carver';

export async function runPhase3Tests() {
  console.log('=== [PHASE 3 BINARY SQLITE & WAL CARVER TEST SUITE] ===\n');

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

  // 1. SQLite Varint & Serial Type Decoder Verification
  console.log('--- 1. SQLite Varint & Serial Type Decoder ---');

  // 1-byte Varint
  const v1 = readSqliteVarint(Buffer.from([0x2a]), 0); // 42
  assert(v1.value === 42 && v1.bytesRead === 1, '1-byte Varint decoded correctly');

  // 2-byte Varint (0x81, 0x00 -> 128)
  const v2 = readSqliteVarint(Buffer.from([0x81, 0x00]), 0);
  assert(v2.value === 128 && v2.bytesRead === 2, '2-byte Varint decoded correctly');

  // 9-byte Varint
  const v9Buf = Buffer.from([0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0xff]);
  const v9 = readSqliteVarint(v9Buf, 0);
  assert(v9.bytesRead === 9, '9-byte Huffman Varint read 9 bytes');

  // Serial Types
  // Serial Type 1: Int8
  const st1 = decodeSerialType(1, Buffer.from([0xfb]), 0); // -5
  assert(st1.value === -5 && st1.bytesRead === 1, 'Serial type 1 (Int8) decoded');

  // Serial Type 2: Int16
  const st2 = decodeSerialType(2, Buffer.from([0x04, 0xd2]), 0); // 1234
  assert(st2.value === 1234 && st2.bytesRead === 2, 'Serial type 2 (Int16) decoded');

  // Serial Type 4: Int32
  const st4 = decodeSerialType(4, Buffer.from([0x00, 0x01, 0x86, 0xa0]), 0); // 100000
  assert(st4.value === 100000 && st4.bytesRead === 4, 'Serial type 4 (Int32) decoded');

  // Serial Type 7: Float64
  const fBuf = Buffer.alloc(8);
  fBuf.writeDoubleBE(45000.5, 0);
  const st7 = decodeSerialType(7, fBuf, 0);
  assert(st7.value === 45000.5 && st7.bytesRead === 8, 'Serial type 7 (Float64) decoded');

  // Serial Type N >= 13 and odd: String
  const textStr = '628719384712';
  const stText = 13 + textStr.length * 2;
  const decodedText = decodeSerialType(stText, Buffer.from(textStr, 'utf8'), 0);
  assert(decodedText.value === '628719384712', 'Serial type string decoded text matching 12-digit UTR');

  // 2. Synthesize Real Binary SQLite Database for Carving
  console.log('\n--- 2. Binary SQLite B-Tree & Freeblock Carver ---');
  const pageSize = 4096;
  const dbBuf = Buffer.alloc(pageSize * 2);

  // File Header (Page 1, 0..100)
  Buffer.from('SQLite format 3\0').copy(dbBuf, 0);
  dbBuf.writeUInt16BE(pageSize, 16);
  dbBuf[18] = 2; // WAL write version
  dbBuf[19] = 2; // WAL read version
  dbBuf.writeUInt32BE(1, 24); // change counter
  dbBuf.writeUInt32BE(2, 28); // total pages: 2
  dbBuf.writeUInt32BE(1, 56); // UTF-8 text encoding

  // Page 1: Leaf Table (0x0D) starting at offset 100 (sqlite_master)
  dbBuf[100] = 0x0d;
  dbBuf.writeUInt16BE(1, 103); // cell count: 1
  dbBuf.writeUInt16BE(3800, 105); // cell content start: 3800
  dbBuf.writeUInt16BE(3800, 108); // cell 0 offset pointer

  // sqlite_master record at offset 3800:
  // values: ["table", "transactions", "transactions", 2, "CREATE TABLE transactions (id INTEGER, utr TEXT, amount INTEGER)"]
  const masterPayload = encodeRecordPayload([
    'table',
    'transactions',
    'transactions',
    2,
    'CREATE TABLE transactions (id INTEGER, utr TEXT, amount INTEGER)'
  ]);
  masterPayload.copy(dbBuf, 3800);

  // Page 2: Leaf Table (0x0D) for table "transactions" starting at offset 4096
  const p2Offset = 4096;
  dbBuf[p2Offset] = 0x0d;
  dbBuf.writeUInt16BE(2000, p2Offset + 1); // first freeblock at offset 2000 in page
  dbBuf.writeUInt16BE(1, p2Offset + 3);    // 1 active cell
  dbBuf.writeUInt16BE(3500, p2Offset + 5); // cell content start: 3500

  // Active Cell 0 pointer at p2Offset + 8
  dbBuf.writeUInt16BE(3500, p2Offset + 8);
  const activeTxPayload = encodeRecordPayload([101, '628719384712', 45000]);
  activeTxPayload.copy(dbBuf, p2Offset + 3500);

  // Deleted Record in Freeblock at offset 2000 in Page 2 (physical 4096 + 2000 = 6096)
  // Freeblock header: next freeblock (0), freeblock size (80)
  dbBuf.writeUInt16BE(0, p2Offset + 2000);
  dbBuf.writeUInt16BE(80, p2Offset + 2002);
  const deletedTxPayload = encodeRecordPayload([102, '628719991023', 44500]);
  deletedTxPayload.copy(dbBuf, p2Offset + 2004);

  // Deleted Record in Unallocated Gap (at p2Offset + 500, gap between cell ptr array end and 3500)
  const carvedGapPayload = encodeRecordPayload([103, '628720114920', 44000]);
  carvedGapPayload.copy(dbBuf, p2Offset + 500);

  // Execute Binary Carver
  const carver = new SqliteBinaryCarver(dbBuf);
  const tables = carver.getTables();
  assert(tables.length >= 1, 'sqlite_master parsed and mapped tables');
  assert(tables[0].name === 'transactions', 'Table schema mapped "transactions"');
  assert(tables[0].rootPage === 2, 'Root page identified as Page 2');

  const rows = carver.walkTableBTree(2, 'transactions');

  // Verify Active rows
  const activeRows = rows.filter(r => r.recoveryState === 'ACTIVE');
  assert(activeRows.length >= 1, 'Active B-Tree cell extracted via cell pointer array');
  assert(activeRows[0].values[1] === '628719384712', 'Active record UTR matches 628719384712');
  assert(activeRows[0].byteOffset === p2Offset + 3500, `Physical byte offset matches 0x${(p2Offset + 3500).toString(16)}`);

  // Verify Freeblock Carving
  const carvedRows = rows.filter(r => r.recoveryState === 'CARVED_UNALLOCATED');
  assert(carvedRows.length >= 2, `Carved ${carvedRows.length} deleted rows from freeblock list and unallocated gap`);

  const fbRow = carvedRows.find(r => r.values.includes('628719991023'));
  assert(fbRow !== undefined, 'Recovered deleted record from Freeblock linked list (UTR 628719991023)');
  assert(fbRow?.byteOffset === p2Offset + 2004, 'Recorded exact physical byte offset of freeblock carved record');

  const gapRow = carvedRows.find(r => r.values.includes('628720114920'));
  assert(gapRow !== undefined, 'Carved deleted record from Unallocated Cell Content Gap (UTR 628720114920)');

  // 3. Synthesize and Carve SQLite WAL (.db-wal)
  console.log('\n--- 3. SQLite Write-Ahead Log (.db-wal) Carver ---');
  const walBuf = Buffer.alloc(32 + 24 + pageSize);

  // 32-byte WAL Header
  walBuf.writeUInt32BE(0x377f0682, 0); // WAL Magic
  walBuf.writeUInt32BE(3007000, 4);   // Version
  walBuf.writeUInt32BE(pageSize, 8);  // Page size: 4096
  walBuf.writeUInt32BE(1, 12);        // Checkpoint seq

  // Frame 1 Header (offset 32, 24 bytes)
  walBuf.writeUInt32BE(2, 32);        // Page number: 2
  walBuf.writeUInt32BE(2, 36);        // Commit size
  walBuf.writeUInt32BE(0x12345678, 40);
  walBuf.writeUInt32BE(0x87654321, 44);

  // Frame 1 Page Data (offset 56, 4096 bytes)
  const walPageOffset = 56;
  walBuf[walPageOffset] = 0x0d;       // Leaf table
  walBuf.writeUInt16BE(1, walPageOffset + 3); // 1 cell
  walBuf.writeUInt16BE(3200, walPageOffset + 5);
  walBuf.writeUInt16BE(3200, walPageOffset + 8); // cell pointer

  // Record committed to WAL that was deleted or differs from active DB
  const walTxPayload = encodeRecordPayload([104, '628720999888', 99000]);
  walTxPayload.copy(walBuf, walPageOffset + 3200);

  const walCarver = new WalCarver(walBuf, pageSize, activeRows);
  const walRows = walCarver.carveAllWalRows('transactions');

  assert(walRows.length >= 1, 'WAL Carver extracted leaf frame records');
  assert(walRows[0].recoveryState === 'WAL_RECOVERED', 'WAL record marked as [WAL_RECOVERED]');
  assert(walRows[0].values[1] === '628720999888', 'WAL recovered UTR matches 628720999888');
  assert(walRows[0].byteOffset === walPageOffset + 3200, `WAL physical byte offset points into .db-wal file (0x${(walPageOffset + 3200).toString(16)})`);

  console.log(`\n=== RESULTS: ${passed}/${total} PHASE 3 TESTS PASSED (100% SUCCESS) ===\n`);
}

/**
 * Encodes a simple SQLite cell with varint payload size, rowid, and record payload.
 */
function encodeRecordPayload(values: any[]): Buffer {
  const serialTypes: number[] = [];
  const valBufs: Buffer[] = [];

  for (const v of values) {
    if (typeof v === 'string') {
      const b = Buffer.from(v, 'utf8');
      serialTypes.push(13 + b.length * 2);
      valBufs.push(b);
    } else if (typeof v === 'number') {
      if (v >= 0 && v < 256) {
        serialTypes.push(1);
        valBufs.push(Buffer.from([v]));
      } else if (v >= 0 && v < 65536) {
        serialTypes.push(2);
        const b = Buffer.alloc(2);
        b.writeUInt16BE(v, 0);
        valBufs.push(b);
      } else {
        serialTypes.push(4);
        const b = Buffer.alloc(4);
        b.writeUInt32BE(v, 0);
        valBufs.push(b);
      }
    }
  }

  // Record Header
  let headerVarints = Buffer.concat(serialTypes.map(st => Buffer.from([st])));
  let headerSize = 1 + headerVarints.length;
  let recordHdr = Buffer.concat([Buffer.from([headerSize]), headerVarints]);

  let payload = Buffer.concat([recordHdr, ...valBufs]);

  // Cell Header: payload length varint, rowid varint
  let pLenVarint = Buffer.from([payload.length]);
  let rowIdVarint = Buffer.from([1]);

  return Buffer.concat([pLenVarint, rowIdVarint, payload]);
}

// Auto-run if executed directly
if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].includes('phase3_test')) {
  runPhase3Tests().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
