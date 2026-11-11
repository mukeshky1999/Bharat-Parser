import { useWorkbenchStore } from '../renderer/state/workbenchStore';
import { UnifiedUPITransaction, ForensicProvenance } from '../shared/forensic-types';

export async function runPhase2Tests() {
  console.log('=== [PHASE 2 WORKBENCH UI & STATE VERIFICATION SUITE] ===\n');

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

  const store = useWorkbenchStore.getState();

  // 1. Initial State & Golden Dataset loading
  console.log('--- 1. Zustand Store Initialization & Golden Dataset ---');
  store.loadGoldenDataset();

  const upiTxs = useWorkbenchStore.getState().upiTransactions;
  assert(upiTxs.length >= 5, `Zustand store loaded ${upiTxs.length} golden UPI transactions`);
  assert(useWorkbenchStore.getState().chats.length >= 2, 'Zustand store loaded golden chat transcripts');
  assert(useWorkbenchStore.getState().apkFindings.length >= 1, 'Zustand store loaded malicious APK findings');

  // 2. Dual-Hash Guard verification pill state
  console.log('\n--- 2. Dual-Hash Guard Integrity Pill State ---');
  const hashes = useWorkbenchStore.getState().dualHashes;
  assert(hashes !== null && hashes.verified === true, 'Dual-Hash status pill is VERIFIED (Green)');

  // 3. Artifact Selection & 4KB Hex Window Synchronization
  console.log('\n--- 3. Synchronized Artifact Selection & 4KB Hex Window ---');
  const targetTx = upiTxs[0];
  await useWorkbenchStore.getState().setSelectedArtifact({
    id: targetTx.id,
    provenance: targetTx.provenance,
    timestamp: targetTx.timestamp,
    embeddedIdTimestamp: targetTx.embeddedIdTimestamp,
    clockTamperDetected: targetTx.clockTamperDetected,
    notes: targetTx.notes,
    itemType: 'UPI_TRANSACTION'
  });

  const selected = useWorkbenchStore.getState().selectedArtifact;
  assert(selected?.id === targetTx.id, 'selectedArtifact store updated synchronously');

  const hexWin = useWorkbenchStore.getState().hexWindow;
  assert(hexWin !== null, '4KB Hex stream window fetched on artifact selection');
  assert(hexWin!.targetOffset === targetTx.provenance.byteOffset, `Hex stream centered on offset 0x${targetTx.provenance.byteOffset.toString(16)}`);
  assert(hexWin!.targetLength === targetTx.provenance.byteLength, `Hex stream highlighted span matches ${targetTx.provenance.byteLength} bytes`);

  // Verify byte-level highlighting in 16-byte rows
  const highlightedRows = hexWin!.rows.filter(r => r.bytes.some(b => b.isHighlighted));
  assert(highlightedRows.length > 0, `Hex viewer flagged ${highlightedRows.length} rows with highlighted byte range`);

  // 4. Quick Filter Testing
  console.log('\n--- 4. Quick Filters: ALL, WAL_AND_CARVED, CLOCK_TAMPER ---');
  useWorkbenchStore.getState().setActiveFilter('ALL');
  assert(useWorkbenchStore.getState().activeFilter === 'ALL', 'Filter set to ALL');

  useWorkbenchStore.getState().setActiveFilter('WAL_AND_CARVED_ONLY');
  assert(useWorkbenchStore.getState().activeFilter === 'WAL_AND_CARVED_ONLY', 'Filter set to WAL_AND_CARVED_ONLY');

  useWorkbenchStore.getState().setActiveFilter('CLOCK_TAMPER_ONLY');
  assert(useWorkbenchStore.getState().activeFilter === 'CLOCK_TAMPER_ONLY', 'Filter set to CLOCK_TAMPER_ONLY');

  console.log(`\n=== RESULTS: ${passed}/${total} PHASE 2 TESTS PASSED (100% SUCCESS) ===\n`);
}

// Auto-run if executed directly
if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].includes('phase2_test')) {
  runPhase2Tests().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
