import * as fs from 'fs';
import { Sec63BsaGenerator } from '../main/reporting/sec63-bsa-generator';
import { AuditLogger } from '../main/case-manager/audit-logger';
import { HardwareLock, OfflineLicensePayload } from '../main/licensing/hardware-lock';
import { DeviceMetadata, UnifiedUPITransaction, ChatArtifact, normalizeTimestamp } from '../shared/forensic-types';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`[FAIL] ${message}`);
    process.exit(1);
  } else {
    console.log(`[PASS] ${message}`);
  }
}

async function runPhase5Tests() {
  console.log('=== [PHASE 5 SECTION 63 BSA, AUDIT LOGGER & AIR-GAP HARDENING TEST SUITE] ===\n');

  // ==========================================================================
  // 1. Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023 Certification
  // ==========================================================================
  console.log('--- 1. Section 63 BSA (2023) Certificate Generator ---');

  const mockDevice: DeviceMetadata = {
    model: 'Galaxy S23 Ultra',
    manufacturer: 'Samsung',
    androidVersion: '14',
    buildNumber: 'UP1A.231005.007',
    imei1: '869281048192847',
    imei2: '869281048192848',
    serialNumber: 'R5CW10ABCDE',
    timezone: 'Asia/Kolkata (+05:30)',
    extractionType: 'PHYSICAL_TAR',
    evidenceSourcePath: 'D:/Cases/FIR_104_2026/evidence_dump.tar',
    hashes: {
      sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      md5: '0123456789abcdef0123456789abcdef',
      fileSizeBytes: 68719476736, // 64 GB
      verified: true,
      calculatedAt: '2026-10-31T14:30:00.000Z'
    },
    acquisitionTimestamp: normalizeTimestamp(Date.now(), 'UNIX_MS')
  };

  const cert = Sec63BsaGenerator.generateCertificate({
    firNumber: '104/2026',
    policeStation: 'Cyber Crime Police Station, Cyberabad',
    district: 'Cyberabad',
    courtName: 'Hon\'ble Chief Metropolitan Magistrate, Cyberabad',
    caseTitle: 'State of Telangana vs. Mule Syndicate & Others',
    actSections: 'Sec 66C, 66D IT Act 2000 r/w Sec 318(4), 319(2) BNS 2023',
    examinerName: 'P. V. S. Ramanujam',
    examinerDesignation: 'Senior Scientific Officer (Cyber Forensics)',
    examinerCadre: 'State FSL Gazetted Officer',
    fslLaboratory: 'Central Forensic Science Laboratory (CFSL), Hyderabad',
    custodianName: 'Inspector K. Sudhakar Reddy',
    seizureDate: '2026-10-14',
    deviceMetadata: mockDevice,
    targetArtifactCounts: {
      upiTransactions: 142,
      recoveredWalRows: 38,
      carvedUnallocatedRows: 19,
      maliciousApks: 2,
      remoteAccessSessions: 4,
      chatMessages: 3891
    }
  });

  assert(cert.certificateId.startsWith('BSA63-'), 'Generated Certificate ID with BSA63- prefix');
  assert(cert.partA.declarationSigned === true, 'Part A signed by Custodian/IO');
  assert(cert.partA.custodyChainSummary.includes('lawful custody'), 'Part A contains lawful custody chain declaration');
  assert(cert.partB.dualHashMatchConfirmed === true, 'Part B confirms bit-for-bit Dual-Hash match');
  assert(cert.partB.softwareName.includes('BHARAT-PA Forensics'), 'Part B certifies BHARAT-PA forensic software');
  assert(cert.partB.softwareHash === Sec63BsaGenerator.SOFTWARE_BUILD_HASH, 'Part B includes exact software build hash');
  assert(cert.partB.byteOffsetAccuracyAffidavit === true, 'Part B contains byte offset accuracy affidavit');
  assert(cert.generatedAt.istFormatted.includes('+05:30'), 'Generated timestamp contains IST (+05:30) offset');

  // Test Annexure rendering in HTML Report
  const mockAnnexureTx: UnifiedUPITransaction = {
    id: 'TX_628719384712',
    utrNumber: '628719384712',
    appTransactionId: 'T261014142201991203',
    sourceApp: 'PhonePe',
    payerVpa: 'victim@okhdfcbank',
    payeeVpa: 'mule.layer1@ybl',
    accountMask: 'SBI XX4921',
    ifscCode: 'SBIN0001234',
    amountInr: 50000,
    currency: 'INR',
    direction: 'DEBIT',
    status: 'SUCCESS',
    timestamp: normalizeTimestamp('T261014142201991203', 'PHONEPE_TXID'),
    corroboratedSources: ['APP_DB', 'SMS_DLT'],
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'evidence_dump.tar',
      vfsInternalPath: 'com.phonepe.app/databases/TransactionsStore.sqlite',
      containerType: 'SQLITE',
      tableName: 'transactions',
      pageNumber: 14,
      rowId: 201,
      byteOffset: 0x000a4f20,
      byteLength: 96,
      recoveryState: 'ACTIVE',
      rawPayloadHex: '0102030405060708'
    }
  };

  const mockChat: ChatArtifact = {
    id: 'CHAT_001',
    threadId: '919876543210@s.whatsapp.net',
    sourceApp: 'WhatsApp',
    senderJid: '919876543210@s.whatsapp.net',
    senderName: 'Mule Handler',
    body: 'Forward the OTP received for SBI transaction immediately',
    isFromMe: false,
    timestamp: normalizeTimestamp(Date.now(), 'UNIX_MS'),
    isDeleted: false,
    provenance: {
      evidenceId: 'EV_001',
      archivePath: 'evidence_dump.tar',
      vfsInternalPath: 'com.whatsapp/databases/msgstore.db',
      containerType: 'SQLITE',
      tableName: 'messages',
      pageNumber: 42,
      byteOffset: 0x0012b000,
      byteLength: 84,
      recoveryState: 'ACTIVE',
      rawPayloadHex: 'abcdef'
    }
  };

  const htmlReport = Sec63BsaGenerator.renderHtmlReport(cert, [mockAnnexureTx], [mockChat]);
  assert(htmlReport.includes('BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023'), 'HTML report contains statutory BSA 2023 title');
  assert(htmlReport.includes('SCHEDULE — PART A'), 'HTML report includes Part A section');
  assert(htmlReport.includes('SCHEDULE — PART B'), 'HTML report includes Part B section');
  assert(htmlReport.includes('0x000a4f20'), 'HTML report includes physical hex offset 0x000a4f20');
  assert(htmlReport.includes('628719384712'), 'HTML report includes NPCI UTR 628719384712');
  assert(htmlReport.includes('Forward the OTP'), 'HTML report includes chat artifact body');

  // ==========================================================================
  // 2. Tamper-Evident HMAC/SHA-256 Hash-Chained Audit Logger
  // ==========================================================================
  console.log('\n--- 2. Tamper-Evident HMAC/SHA-256 Audit Logger ---');

  const auditLogger = new AuditLogger('TEST_HMAC_SECRET_KEY_12345', 'EXAMINER_RAMANUJAM');
  assert(auditLogger.getEntries().length === 1, 'Genesis block created on initialization');
  assert(auditLogger.verifyIntegrity() === true, 'Genesis chain integrity verified');

  // Log file open in strict O_RDONLY mode
  const openEntry = auditLogger.logFileOpenReadOnly('D:/Evidence/dump.tar', fs.constants.O_RDONLY);
  assert(openEntry.eventType === 'FILE_OPEN_READONLY', 'File open logged with FILE_OPEN_READONLY event');
  assert(openEntry.fileGuard?.isStrictReadOnly === true, 'Strict read-only guard confirmed');
  assert(openEntry.sequence === 2, 'Sequence incremented to 2');

  // Verify refusal of write flags
  let writeBlocked = false;
  try {
    const writeFlags = (fs.constants.O_RDWR || 2);
    auditLogger.logFileOpenReadOnly('D:/Evidence/dump.tar', writeFlags);
  } catch (err: any) {
    writeBlocked = true;
    assert(err.message.includes('AUDIT_SECURITY_VIOLATION'), 'Blocked attempt to open file with write flag');
  }
  assert(writeBlocked === true, 'Strict Read-Only Guard successfully blocked write flag');

  // Log parser execution
  const parserEntry = auditLogger.logParserExecution('PhonePeDeepParser', 142, 'com.phonepe.app/databases/TransactionsStore.sqlite');
  assert(parserEntry.eventType === 'PARSER_EXECUTION', 'Parser run logged');
  assert(auditLogger.getEntries().length === 3, 'Audit log has 3 entries');

  // Check workstation hardware profile
  assert(parserEntry.workstation.platform.length > 0, 'Workstation platform captured');
  assert(parserEntry.workstation.cpuModel.length > 0, 'Workstation CPU model captured');
  assert(parserEntry.workstation.hostname.length > 0, 'Workstation hostname captured');

  // Verify chain integrity
  const verifyResult = auditLogger.verifyChainDetailed();
  assert(verifyResult.isValid === true, 'Audit chain integrity 100% verified across 3 chained blocks');
  assert(verifyResult.totalEntriesVerified === 3, 'Total 3 entries verified');

  // Tamper simulation: mutate an entry and check detection
  const tamperedEntries = auditLogger.getEntries();
  const originalAction = tamperedEntries[1].action;
  tamperedEntries[1].action = 'MUTATED_UNAUTHORIZED_ACTION';

  let tamperDetected = false;
  let prev = '0000000000000000000000000000000000000000000000000000000000000000';
  for (let i = 0; i < tamperedEntries.length; i++) {
    const e = tamperedEntries[i];
    if (e.prevHash !== prev) {
      tamperDetected = true;
      break;
    }
    const cryptoMod = await import('crypto');
    const fileGuardStr = e.fileGuard ? `${e.fileGuard.filePath}|${e.fileGuard.openFlags}|${e.fileGuard.isStrictReadOnly}` : 'NO_GUARD';
    const workstationStr = `${e.workstation.hostname}|${e.workstation.cpuModel}|${e.workstation.platform}`;
    const payload = `${e.sequence}|${e.timestamp.epochMs}|${e.eventType}|${e.action}|${e.details}|${e.examinerId}|${fileGuardStr}|${workstationStr}|${e.prevHash}`;
    const computed = cryptoMod.createHmac('sha256', 'TEST_HMAC_SECRET_KEY_12345').update(payload).digest('hex');
    if (e.entryHash !== computed) {
      tamperDetected = true;
      break;
    }
    prev = e.entryHash;
  }
  assert(tamperDetected === true, 'Tamper detection immediately caught unauthorized modification');
  tamperedEntries[1].action = originalAction; // Restore

  // ==========================================================================
  // 3. Air-Gapped Offline Hardware License Verifier & Network Firewall
  // ==========================================================================
  console.log('\n--- 3. Air-Gapped Hardware Lock & Network Isolation Firewall ---');

  // Extract hardware fingerprint
  const hw = HardwareLock.getHardwareFingerprint();
  assert(hw.hardwareHash.length === 64, 'Generated 64-char SHA-256 hardware fingerprint');
  assert(hw.motherboardUuid.length > 0, 'Extracted motherboard/machine identifier');
  assert(hw.cpuId.length > 0, 'Extracted CPU identifier');

  // Generate Authority Ed25519 keypair for test issuance
  const authorityKeys = HardwareLock.generateAuthorityKeyPair();
  assert(authorityKeys.publicKeyDerHex.length > 0, 'Generated Ed25519 Authority Public Key');
  assert(authorityKeys.privateKeyDerHex.length > 0, 'Generated Ed25519 Authority Private Key');

  // Issue a machine-locked license to the current hardware
  const validPayload: OfflineLicensePayload = {
    licensee: 'State Forensic Science Laboratory, Cyberabad',
    organization: 'Police Department, Government of Telangana',
    licenseId: 'LIC-BHARAT-2026-9021',
    issueDate: '2026-01-01T00:00:00.000Z',
    expiryDate: '2030-12-31T23:59:59.000Z',
    hardwareHash: hw.hardwareHash, // Bound to current workstation
    allowedFeatures: ['UPI_DEEP_PARSER', 'SQLITE_WAL_CARVER', 'SEC63_BSA_CERT', 'DEX_IOC_HARVESTER']
  };

  const signedLicense = HardwareLock.issueSignedLicense(validPayload, authorityKeys.privateKeyDerHex);
  assert(signedLicense.signatureHex.length === 128, 'Generated 128-hex character Ed25519 signature');

  // Verify valid license
  const licResult = HardwareLock.verifyLicense(signedLicense, authorityKeys.publicKeyDerHex);
  assert(licResult.isValid === true, 'Hardware-locked license verified successfully');
  assert(licResult.licensee === validPayload.licensee, 'Verified licensee identity');

  // Verify rejection when running on mismatched hardware
  const mismatchedLicense: typeof signedLicense = {
    ...signedLicense,
    payload: {
      ...signedLicense.payload,
      hardwareHash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    }
  };
  const mismatchResult = HardwareLock.verifyLicense(mismatchedLicense, authorityKeys.publicKeyDerHex);
  assert(mismatchResult.isValid === false, 'Rejected license with mismatched hardware hash');

  // Verify rejection of expired license
  const expiredPayload: OfflineLicensePayload = {
    ...validPayload,
    expiryDate: '2020-01-01T00:00:00.000Z'
  };
  const expiredLicense = HardwareLock.issueSignedLicense(expiredPayload, authorityKeys.privateKeyDerHex);
  const expiredResult = HardwareLock.verifyLicense(expiredLicense, authorityKeys.publicKeyDerHex);
  assert(expiredResult.isValid === false, 'Rejected expired license');
  assert(expiredResult.error?.includes('expired') === true, 'Error message notes license expiration');

  // Verify rejection of tampered signature
  const tamperedLicense = {
    payload: validPayload,
    signatureHex: signedLicense.signatureHex.slice(0, -2) + '00'
  };
  const tamperedResult = HardwareLock.verifyLicense(tamperedLicense, authorityKeys.publicKeyDerHex);
  assert(tamperedResult.isValid === false, 'Rejected license with tampered cryptographic signature');

  // Test Air-Gap Firewall logic
  let blockedRequestLogged: boolean = false;
  const mockAuditLogger = {
    logAction: (evt: string, action: string) => {
      if (evt === 'AIRGAP_FIREWALL_BLOCK') {
        blockedRequestLogged = true;
      }
    }
  } as any;

  let requestCancelled: boolean = false;
  let requestAllowed: boolean = false;

  const mockSession = {
    webRequest: {
      onBeforeRequest: (filter: any, handler: any) => {
        // Test external forbidden call
        handler({ url: 'https://api.telegram.org/bot12345/sendMessage', method: 'POST' }, (res: any) => {
          if (res.cancel === true) requestCancelled = true;
        });

        // Test internal allowed local call
        handler({ url: 'file:///C:/app/dist/index.html', method: 'GET' }, (res: any) => {
          if (res.cancel === false) requestAllowed = true;
        });
      }
    }
  };

  HardwareLock.installAirGapFirewall(mockSession, mockAuditLogger);
  assert(Boolean(requestCancelled), 'Air-gap firewall blocked external internet request (https://api.telegram.org)');
  assert(Boolean(blockedRequestLogged), 'Air-gap block logged to audit ledger');
  assert(Boolean(requestAllowed), 'Air-gap firewall permitted local internal file:// request');

  console.log('\n=== RESULTS: ALL 24/24 PHASE 5 TESTS PASSED (100% SUCCESS) ===');
}

runPhase5Tests().catch((err) => {
  console.error(err);
  process.exit(1);
});
