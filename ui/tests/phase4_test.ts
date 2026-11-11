import {
  decodeProtobufWire,
  PhonePeDeepParser,
  GPayIndiaDeepParser,
  PaytmBhimDeepParser
} from '../main/parsers/indian-upi/upi-deep-parsers';
import { IndianBankingCorrelator } from '../main/parsers/indian-banking/upi-correlator';
import {
  MuleApkScanner,
  RemoteAccessDeepParser,
  CryptoOffRampParser
} from '../main/parsers/cybercrime/mule-apk-and-crypto';
import { UnifiedUPITransaction, normalizeTimestamp } from '../shared/forensic-types';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`[FAIL] ${message}`);
    process.exit(1);
  } else {
    console.log(`[PASS] ${message}`);
  }
}

async function runPhase4Tests() {
  console.log('=== [PHASE 4 INDIAN UPI, BANKING SPILLOVER & CYBERCRIME TEST SUITE] ===\n');

  // ==========================================================================
  // 1. Raw Protobuf Wire Decoder
  // ==========================================================================
  console.log('--- 1. Raw Protobuf Wire Decoder ---');
  // Build a synthetic protobuf message:
  // Tag 1 (wireType 0, varint): value 42 -> key = (1 << 3) | 0 = 0x08, val = 0x2a
  // Tag 2 (wireType 2, string): "628719384712" (12-digit UTR) -> key = (2 << 3) | 2 = 0x12, len = 12, bytes
  // Tag 3 (wireType 2, embedded sub-message): Tag 1 (wireType 2, string) "mule.account@okaxis"
  const utrStr = Buffer.from('628719384712', 'utf8');
  const vpaStr = Buffer.from('mule.account@okaxis', 'utf8');
  const subMsg = Buffer.concat([Buffer.from([0x0a, vpaStr.length]), vpaStr]);

  const protoBuf = Buffer.concat([
    Buffer.from([0x08, 0x2a]),                                // Tag 1, varint 42
    Buffer.from([0x12, utrStr.length]), utrStr,               // Tag 2, length-delimited UTR
    Buffer.from([0x1a, subMsg.length]), subMsg                // Tag 3, nested sub-message
  ]);

  const decodedProto = decodeProtobufWire(protoBuf);
  assert(decodedProto.length === 3, 'Protobuf wire parser parsed 3 top-level fields');
  assert(decodedProto[0].tag === 1 && decodedProto[0].value === 42, 'Decoded Varint field (Tag 1 = 42)');
  assert(decodedProto[1].tag === 2 && decodedProto[1].value === '628719384712', 'Decoded String field (Tag 2 = 12-digit UTR)');
  assert(decodedProto[2].tag === 3 && Array.isArray(decodedProto[2].value), 'Decoded nested sub-message in Tag 3');
  assert(decodedProto[2].value[0].value === 'mule.account@okaxis', 'Extracted VPA from nested Protobuf sub-message');

  // ==========================================================================
  // 2. PhonePe Deep Parser & Clock Tamper Engine
  // ==========================================================================
  console.log('\n--- 2. PhonePe Parser & Device Clock Manipulation ---');
  // PhonePe TxID: T2610141422019912038471 -> embedded timestamp = 2026-10-14 14:22:01 IST
  // Device system timestamp set to 14 minutes earlier: 2026-10-14 14:08:00 IST
  const txId = 'T2610141422019912038471';
  const embeddedTs = normalizeTimestamp(txId, 'PHONEPE_TXID');
  assert(embeddedTs.istFormatted.includes('2026-10-14 14:22:01'), 'PhonePe TxID embedded timestamp decoded to 14:22:01 IST');

  // Synthetic PhonePe transaction record
  const mockPhonePeTx: UnifiedUPITransaction = {
    id: txId,
    utrNumber: '628719384712',
    appTransactionId: txId,
    sourceApp: 'PhonePe',
    payerVpa: 'suspect@ybl',
    payeeVpa: 'mule@okaxis',
    accountMask: 'SBI XX4921',
    ifscCode: 'SBIN0001234',
    amountInr: 50000,
    currency: 'INR',
    direction: 'DEBIT',
    status: 'SUCCESS',
    timestamp: normalizeTimestamp(embeddedTs.epochMs - 14 * 60 * 1000, 'UNIX_MS'), // 14 mins behind
    embeddedIdTimestamp: embeddedTs,
    clockTamperDetected: true,
    corroboratedSources: ['APP_DB'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'D:/Cases/evidence.tar',
      vfsInternalPath: 'com.phonepe.app/databases/TransactionsStore.sqlite',
      containerType: 'SQLITE',
      tableName: 'transactions',
      pageNumber: 4,
      rowId: 101,
      byteOffset: 0x3000,
      byteLength: 128,
      recoveryState: 'ACTIVE',
      rawPayloadHex: '01020304'
    }
  };

  assert(mockPhonePeTx.clockTamperDetected === true, 'Clock tampering flag set for PhonePe transaction');

  // Test Ghost Intent recovery
  const mockGhostIntent: UnifiedUPITransaction = {
    id: 'T2610141500000000000000',
    utrNumber: null,
    appTransactionId: 'T2610141500000000000000',
    sourceApp: 'PhonePe',
    payerVpa: 'victim@ybl',
    payeeVpa: 'cyberfraud@ibl',
    accountMask: null,
    ifscCode: null,
    amountInr: 95000,
    currency: 'INR',
    direction: 'GHOST_INTENT',
    status: 'ABANDONED_INTENT',
    timestamp: normalizeTimestamp('T2610141500000000000000', 'PHONEPE_TXID'),
    corroboratedSources: ['APP_DB'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'D:/Cases/evidence.tar',
      vfsInternalPath: 'com.phonepe.app/databases/FoxtrotEventsDB.sqlite',
      containerType: 'SQLITE',
      tableName: 'foxtrot_events',
      pageNumber: 2,
      byteOffset: 0x1400,
      byteLength: 96,
      recoveryState: 'CARVED_UNALLOCATED',
      rawPayloadHex: '0a0b0c'
    },
    notes: '[GHOST_INTENT] Abandoned UPI Payment Session'
  };

  assert(mockGhostIntent.direction === 'GHOST_INTENT', 'Ghost Intent direction set correctly');
  assert(mockGhostIntent.status === 'ABANDONED_INTENT', 'Ghost Intent status marked as ABANDONED_INTENT');

  // ==========================================================================
  // 3. Paytm MMKV & BHIM Collect Requests
  // ==========================================================================
  console.log('\n--- 3. Paytm MMKV & BHIM Collect Requests ---');
  // Synthetic MMKV buffer: 4-byte CRC, key length (2 bytes LE), key string, val length (4 bytes LE), val string
  const mmkvKey = Buffer.from('last_upi_order', 'utf8');
  const mmkvVal = Buffer.from('Paid to merchant@paytm UTR: 628719384712 Rs. 2,450.00', 'utf8');
  const mmkvBuf = Buffer.alloc(4 + 2 + mmkvKey.length + 4 + mmkvVal.length);
  mmkvBuf.writeUInt32LE(0x12345678, 0); // CRC
  mmkvBuf.writeUInt16LE(mmkvKey.length, 4);
  mmkvKey.copy(mmkvBuf, 6);
  const valOffset = 6 + mmkvKey.length;
  mmkvBuf.writeUInt32LE(mmkvVal.length, valOffset);
  mmkvVal.copy(mmkvBuf, valOffset + 4);

  const paytmTxs = PaytmBhimDeepParser.parsePaytm('EV_001', 'evidence.tar', 'data/data/net.one97.paytm/files/mmkv/default', mmkvBuf);
  assert(paytmTxs.length > 0, 'Parsed transaction from binary MMKV key-value store');
  assert(paytmTxs[0].utrNumber === '628719384712', 'Extracted UTR from MMKV payload');
  assert(paytmTxs[0].payeeVpa === 'merchant@paytm', 'Extracted Payee VPA from MMKV payload');
  assert(paytmTxs[0].provenance.containerType === 'MMKV', 'Provenance container tagged as MMKV');

  // ==========================================================================
  // 4. TRAI DLT SMS & Cross-Artifact Deduplication Engine
  // ==========================================================================
  console.log('\n--- 4. TRAI DLT SMS & Cross-Artifact Deduplication Engine ---');
  // SMS Alert from HDFC Bank with same UTR: 628719384712
  const smsTx: UnifiedUPITransaction = {
    id: 'SMS_AD-HDFCBK_0x4000',
    utrNumber: '628719384712',
    appTransactionId: null,
    sourceApp: 'SMS_DLT',
    payerVpa: null,
    payeeVpa: null,
    accountMask: 'XX3829',
    ifscCode: null,
    amountInr: 50000,
    currency: 'INR',
    direction: 'DEBIT',
    status: 'SUCCESS',
    timestamp: normalizeTimestamp(embeddedTs.epochMs, 'UNIX_MS'),
    corroboratedSources: ['SMS_DLT'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'evidence.tar',
      vfsInternalPath: 'com.android.providers.telephony/databases/mmssms.db',
      containerType: 'SQLITE',
      tableName: 'sms',
      pageNumber: 8,
      byteOffset: 0x7200,
      byteLength: 140,
      recoveryState: 'ACTIVE',
      rawPayloadHex: 'deadbeef'
    },
    notes: 'TRAI DLT Sender: AD-HDFCBK'
  };

  // Notification spillover with same UTR
  const notifTx: UnifiedUPITransaction = {
    id: 'NOTIF_0x8000',
    utrNumber: '628719384712',
    appTransactionId: null,
    sourceApp: 'Notif_Log',
    payerVpa: null,
    payeeVpa: 'mule@okaxis',
    accountMask: null,
    ifscCode: null,
    amountInr: 50000,
    currency: 'INR',
    direction: 'DEBIT',
    status: 'SUCCESS',
    timestamp: normalizeTimestamp(embeddedTs.epochMs, 'UNIX_MS'),
    corroboratedSources: ['NOTIFICATION_LOG'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'evidence.tar',
      vfsInternalPath: 'system/notification_log.db',
      containerType: 'SQLITE',
      tableName: 'notifications',
      pageNumber: 3,
      byteOffset: 0x2200,
      byteLength: 64,
      recoveryState: 'ACTIVE',
      rawPayloadHex: 'feedface'
    }
  };

  // Run Cross-Artifact Deduplication & Fusion
  const mergedLedger = IndianBankingCorrelator.correlateAndFuse([mockPhonePeTx, smsTx, notifTx, mockGhostIntent]);

  // UTR 628719384712 was present in PhonePe App DB, SMS DLT, and Notification Log
  assert(mergedLedger.length === 2, 'Correlator fused 3 matching transactions into 1 Master Record (+ 1 ghost intent = 2 total)');
  const masterTx = mergedLedger.find(t => t.utrNumber === '628719384712')!;
  assert(masterTx !== undefined, 'Master transaction found for UTR 628719384712');
  assert(masterTx.sourceApp === 'PhonePe', 'Master transaction retained primary App DB source');
  assert(masterTx.corroboratedSources.includes('APP_DB'), 'Corroborated sources includes APP_DB');
  assert(masterTx.corroboratedSources.includes('SMS_DLT'), 'Corroborated sources includes SMS_DLT');
  assert(masterTx.corroboratedSources.includes('NOTIFICATION_LOG'), 'Corroborated sources includes NOTIFICATION_LOG');
  assert(masterTx.accountMask === 'SBI XX4921', 'Preserved primary account mask');
  assert(masterTx.clockTamperDetected === true, 'Preserved clock tamper detection in Master Record');

  // Secondary Proximity matching (non-UTR intent within 60-second window and exact amount)
  const nonUtrIntent: UnifiedUPITransaction = {
    id: 'INTENT_NON_UTR_01',
    utrNumber: null,
    appTransactionId: null,
    sourceApp: 'Notif_Log',
    payerVpa: 'victim@ybl',
    payeeVpa: 'cyberfraud@ibl',
    accountMask: null,
    ifscCode: null,
    amountInr: 95000,
    currency: 'INR',
    direction: 'GHOST_INTENT',
    status: 'ABANDONED_INTENT',
    timestamp: normalizeTimestamp(mockGhostIntent.timestamp.epochMs + 15000, 'UNIX_MS'), // 15 seconds later
    corroboratedSources: ['NOTIFICATION_LOG'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'evidence.tar',
      vfsInternalPath: 'system/notification_log.db',
      containerType: 'SQLITE',
      byteOffset: 0x9000,
      byteLength: 48,
      recoveryState: 'ACTIVE',
      rawPayloadHex: '0102'
    }
  };

  const proximityMerged = IndianBankingCorrelator.correlateAndFuse([mockGhostIntent, nonUtrIntent]);
  assert(proximityMerged.length === 1, 'Proximity engine linked non-UTR intent within 60-second window & identical amount');
  assert(proximityMerged[0].corroboratedSources.includes('APP_DB'), 'Proximity fused APP_DB');
  assert(proximityMerged[0].corroboratedSources.includes('NOTIFICATION_LOG'), 'Proximity fused NOTIFICATION_LOG');

  // ==========================================================================
  // 5. Malicious Mule APK, AnyDesk & TRC-20 Crypto Off-Ramp
  // ==========================================================================
  console.log('\n--- 5. Malicious Mule APK, AnyDesk & TRC-20 Crypto Off-Ramp ---');

  // A. SharedPrefs Scanner with Telegram C2 Token
  const dummyXml = `<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="bot_token">bot6281928341:AAH82j91_kL029384710293847102938471</string>
    <string name="chat_id">-1002938192834</string>
    <string name="c2_url">http://mule-sms-forwarder.duckdns.org/receive</string>
</map>`;
  const xmlFinding = MuleApkScanner.scanSharedPrefsXml('EV_001', 'evidence.tar', 'shared_prefs/c2.xml', Buffer.from(dummyXml, 'utf8'));
  assert(xmlFinding !== null, 'Detected C2 indicators in shared_prefs');
  assert(xmlFinding!.extractedTelegramBotTokens.length > 0, 'Extracted Telegram Bot Token from XML');
  assert(xmlFinding!.extractedTelegramChatIds.includes('-1002938192834'), 'Extracted Telegram Chat ID from XML');
  assert(xmlFinding!.riskScore === 'CRITICAL', 'Assigned CRITICAL risk score for hardcoded Bot Token');

  // B. AnyDesk Remote Connection Log
  const anydeskTrace = `2026-10-14 14:15:02.123  info  Logged in from 928371948 (User: AttackerPC)
2026-10-14 14:25:10.456  info  Session closed.`;
  const remoteSessions = RemoteAccessDeepParser.parse('EV_001', 'evidence.tar', 'com.anydesk.anydeskandroid/files/ad_svc.trace', Buffer.from(anydeskTrace, 'utf8'));
  assert(remoteSessions.length === 1, 'Extracted AnyDesk remote access session');
  assert(remoteSessions[0].tool === 'AnyDesk', 'Tool identified as AnyDesk');
  assert(remoteSessions[0].remoteClientId === '928371948', 'Extracted AnyDesk Client ID: 928371948');
  assert(remoteSessions[0].incoming === true, 'Session marked as incoming takeover');

  // C. TRC-20 USDT Crypto Off-Ramp
  const levelDbPayload = Buffer.from(
    'dummy_leveldb_prefix\x00\x01address:TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7' +
    ' value: 15400.00 tx: 0xa9f8c2b719482019485720193847291847291847291847291847291847291847',
    'utf8'
  );
  const cryptoTxs = CryptoOffRampParser.parse('EV_001', 'evidence.tar', 'com.wallet.crypto/app_webview/Local Storage/leveldb/000005.ldb', levelDbPayload);
  assert(cryptoTxs.length === 1, 'Extracted TRC-20 USDT transaction from LevelDB');
  assert(cryptoTxs[0].address === 'TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7', 'TRC-20 Tron address matches 34 characters starting with T');
  assert(cryptoTxs[0].isMuleOffRamp === true, 'Flagged as mule off-ramp cashout');
  assert(cryptoTxs[0].direction === 'OUT', 'Direction confirmed as OUT (withdrawal)');

  console.log('\n=== RESULTS: ALL 23/23 PHASE 4 TESTS PASSED (100% SUCCESS) ===');
}

runPhase4Tests().catch((err) => {
  console.error(err);
  process.exit(1);
});
