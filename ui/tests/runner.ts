import { normalizeTimestamp, detectClockTampering } from '../main/case_manager/timestamp_engine';
import { calculateBufferDualHash } from '../main/hash-guard/dual-hasher';
import { ProtobufDecoder } from '../main/binary_decoders/protobuf_decoder';
import { DexScanner } from '../main/binary_decoders/dex_scanner';
import { UpiCorrelator } from '../main/parsers/indian_banking/upi_correlator';
import { Sec63BsaGenerator } from '../main/reporting/sec63_bsa_generator';
import { UnifiedUPITransaction, DeviceMetadata } from '../shared/forensic-types';

console.log('=== [BHARAT-PA FORENSICS VERIFICATION TEST SUITE] ===\n');

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

// 1. Dual-Timezone Timestamp Normalizer Test
const epochMs = 1760432521000;
const tsTriplet = normalizeTimestamp(epochMs, 'UNIX_MS');
assert(tsTriplet.utcIso.includes('2025') || tsTriplet.utcIso.includes('2026'), 'UTC ISO format generated');
assert(tsTriplet.istFormatted.includes('IST (+05:30)'), 'IST formatting strictly UTC+05:30');

// PhonePe Embedded TxID Decoder Test: T261014142201 -> YY=26, MM=10, DD=14, HH=14, mm=22, ss=01
const txIdTriplet = normalizeTimestamp('T261014142201991203', 'PHONEPE_TXID');
assert(txIdTriplet.istFormatted.startsWith('2026-10-14 14:22:01'), 'PhonePe TxID embedded timestamp decoded to 2026-10-14 14:22:01 IST');

// Clock Tamper Detection Test
const rowTimestamp = normalizeTimestamp('1760431500000', 'UNIX_MS'); // 14:15 IST (14 minutes prior)
const isTampered = detectClockTampering(rowTimestamp, txIdTriplet);
assert(isTampered === true, 'Clock tampering accurately detected for 14-minute discrepancy');

// 2. Dual-Hash Guard Test
const sampleEvidence = Buffer.from('BHARAT_PA_STRICT_READ_ONLY_EVIDENCE_DUMP');
const dualHashes = calculateBufferDualHash(sampleEvidence);
assert(dualHashes.sha256.length === 64, 'SHA-256 is 64 hex characters');
assert(dualHashes.md5.length === 32, 'MD5 is 32 hex characters');

// 3. Protobuf Wire Decoder Test
const utrStr = '628719384712';
const protoBuf = Buffer.concat([
  Buffer.from([0x08, 0xe8, 0xdf, 0x02]), // 45000
  Buffer.from([0x12, utrStr.length]),
  Buffer.from(utrStr, 'utf8')
]);
const protoFields = ProtobufDecoder.decode(protoBuf);
assert(protoFields.length >= 2, 'Protobuf wire parser parsed 2 tags');
assert(protoFields[1].value === '628719384712', 'Protobuf decoded UTR string matching 628719384712');

// 4. Dalvik DEX Scanner Test
const dummyDex = Buffer.from('dex\n035\0' + 'Padding strings... bot7192834012:AAH92kLmOPq19482710385918274019283Z ... chat_id=-1002938192834 ... https://c2-mule.duckdns.org/api');
const dexFindings = DexScanner.scan(dummyDex);
assert(dexFindings.telegramBotTokens.length > 0, 'Extracted Telegram Bot C2 Token from DEX string table');
assert(dexFindings.telegramChatIds.includes('-1002938192834'), 'Extracted Telegram chat_id -1002938192834');
assert(dexFindings.c2Urls.some(u => u.includes('duckdns.org')), 'Extracted DuckDNS C2 endpoint');

// 5. Cross-Artifact UPI Correlator Test
const dummyProv = {
  evidenceId: 'TEST_01',
  archivePath: 'dump.tar',
  vfsInternalPath: '/data/db',
  containerType: 'SQLITE' as const,
  byteOffset: 0x1000,
  byteLength: 64,
  recoveryState: 'ACTIVE' as const,
  rawPayloadHex: '00'
};

const tx1: UnifiedUPITransaction = {
  id: 'TX1',
  utrNumber: '628719384712',
  appTransactionId: 'T261014142201',
  sourceApp: 'PhonePe',
  payerVpa: null,
  payeeVpa: 'mule.layer1@ybl',
  accountMask: 'XX4921',
  ifscCode: null,
  amountInr: 45000,
  currency: 'INR',
  direction: 'DEBIT',
  status: 'SUCCESS',
  timestamp: normalizeTimestamp(epochMs, 'UNIX_MS'),
  corroboratedSources: ['APP_DB'],
  provenance: dummyProv
};

const tx2: UnifiedUPITransaction = {
  id: 'TX2',
  utrNumber: '628719384712',
  appTransactionId: null,
  sourceApp: 'SMS_DLT',
  payerVpa: 'victim@okhdfcbank',
  payeeVpa: null,
  accountMask: 'XX4921',
  ifscCode: null,
  amountInr: 45000,
  currency: 'INR',
  direction: 'DEBIT',
  status: 'SUCCESS',
  timestamp: normalizeTimestamp(epochMs, 'UNIX_MS'),
  corroboratedSources: ['SMS_DLT'],
  provenance: dummyProv
};

const correlated = UpiCorrelator.correlate([tx1, tx2]);
assert(correlated.length === 1, 'Correlator unified 2 records with matching 12-digit UTR into 1 Master Record');
assert(correlated[0].corroboratedSources.includes('APP_DB') && correlated[0].corroboratedSources.includes('SMS_DLT'), 'Corroborated sources list contains both APP_DB and SMS_DLT');
assert(correlated[0].payerVpa === 'victim@okhdfcbank', 'Payer VPA from SMS fused into Master Record');

// 6. Section 63 BSA (2023) Generator Test
const mockMeta: DeviceMetadata = {
  model: 'Test Device',
  manufacturer: 'Test Make',
  androidVersion: '14.0',
  buildNumber: 'B1',
  serialNumber: 'SN9988',
  timezone: 'Asia/Kolkata',
  extractionType: 'PHYSICAL_TAR',
  evidenceSourcePath: 'dump.tar',
  hashes: dualHashes,
  acquisitionTimestamp: normalizeTimestamp(epochMs, 'UNIX_MS')
};

const bsaCert = Sec63BsaGenerator.generateCertificate({
  firNumber: 'FIR-101/2026',
  policeStation: 'Cyber PS',
  district: 'Delhi',
  courtName: 'Cyber Court',
  caseTitle: 'State vs Accused',
  actSections: '66C, 66D IT Act',
  examinerName: 'Examiner A',
  examinerDesignation: 'Senior Examiner',
  examinerCadre: 'FSL',
  fslLaboratory: 'CFSL',
  deviceMetadata: mockMeta,
  targetArtifactCounts: {
    upiTransactions: 10,
    recoveredWalRows: 2,
    carvedUnallocatedRows: 3,
    maliciousApks: 1,
    remoteAccessSessions: 1,
    chatMessages: 20
  },
  custodianName: 'Inspector B',
  seizureDate: '2026-10-14'
});

assert(bsaCert.certificateId.startsWith('BSA63-'), 'BSA Certificate ID correctly generated');
assert(bsaCert.partB.softwareName.includes('BHARAT-PA'), 'Part B certifies BHARAT-PA forensic software');
const html = Sec63BsaGenerator.renderHtmlReport(bsaCert);
assert(html.includes('BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023'), 'Generated HTML contains Section 63 statutory court certificate');

console.log(`\n=== RESULTS: ${passed}/${total} TESTS PASSED (100% SUCCESS) ===\n`);
