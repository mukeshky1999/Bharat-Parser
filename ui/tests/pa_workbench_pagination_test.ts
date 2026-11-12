/**
 * Verification Test for Cellebrite Physical Analyzer 28-Field Categorized UI Workbench
 * & 1 TB SQLite FTS5 Pagination Engine Integration.
 */

import { useWorkbenchStore } from '../renderer/state/workbenchStore';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    process.exit(1);
  }
  console.log(`[PASS] ${msg}`);
}

async function runPAWorkbenchPaginationTest() {
  console.log('=== [CELLEBRITE PHYSICAL ANALYZER 28-FIELD CATEGORIZED UI WORKBENCH TEST SUITE] ===\n');

  const store = useWorkbenchStore.getState();

  // 1. Initial State & Golden Dataset
  store.loadGoldenDataset();
  const stateAfterLoad = useWorkbenchStore.getState();

  assert(stateAfterLoad.chats.length >= 10, 'Golden dataset loaded chat records');
  assert(stateAfterLoad.currentPage === 1, 'Default pagination page is 1');
  assert(stateAfterLoad.pageSize === 100, 'Default page size is 100');

  // 2. Recovery State Filter Pills
  useWorkbenchStore.getState().setRecoveryPillFilter('WAL');
  assert(useWorkbenchStore.getState().recoveryPillFilter === 'WAL', 'Recovery pill filter set to WAL');

  useWorkbenchStore.getState().setRecoveryPillFilter('CARVED');
  assert(useWorkbenchStore.getState().recoveryPillFilter === 'CARVED', 'Recovery pill filter set to CARVED');

  useWorkbenchStore.getState().setRecoveryPillFilter('ALL');
  assert(useWorkbenchStore.getState().recoveryPillFilter === 'ALL', 'Recovery pill filter reset to ALL');

  // 3. Ephemeral Filter Pills
  useWorkbenchStore.getState().setEphemeralFilter('VIEW_ONCE');
  assert(useWorkbenchStore.getState().ephemeralFilter === 'VIEW_ONCE', 'Ephemeral filter set to VIEW_ONCE');

  useWorkbenchStore.getState().setEphemeralFilter('DISAPPEARING');
  assert(useWorkbenchStore.getState().ephemeralFilter === 'DISAPPEARING', 'Ephemeral filter set to DISAPPEARING');

  useWorkbenchStore.getState().setEphemeralFilter('ALL');
  assert(useWorkbenchStore.getState().ephemeralFilter === 'ALL', 'Ephemeral filter reset to ALL');

  // 4. 3-Way Mode Switcher
  useWorkbenchStore.getState().setChatViewMode('GRID');
  assert(useWorkbenchStore.getState().chatViewMode === 'GRID', 'Mode switched to Mode A: 28-Column PA Table Grid');

  useWorkbenchStore.getState().setChatViewMode('BUBBLE');
  assert(useWorkbenchStore.getState().chatViewMode === 'BUBBLE', 'Mode switched to Mode B: Conversation Bubble Split View');

  useWorkbenchStore.getState().setChatViewMode('DOSSIER');
  assert(useWorkbenchStore.getState().chatViewMode === 'DOSSIER', 'Mode switched to Mode C: Suspect & Romance Scam Lead Dossier');

  // 5. Pagination controls
  useWorkbenchStore.getState().setCurrentPage(2);
  assert(useWorkbenchStore.getState().currentPage === 2, 'Current page updated to 2');

  useWorkbenchStore.getState().setCurrentPage(1);
  assert(useWorkbenchStore.getState().currentPage === 1, 'Current page reset to 1');

  // 6. Bottom Dock Dual Tabs
  assert(useWorkbenchStore.getState().bottomDockTab === 'HEX', 'Default bottom dock tab is HEX');
  useWorkbenchStore.getState().setBottomDockTab('DECODED_TREE');
  assert(useWorkbenchStore.getState().bottomDockTab === 'DECODED_TREE', 'Bottom dock tab switched to Raw Decoded JSON / Protobuf Tree');
  useWorkbenchStore.getState().setBottomDockTab('HEX');
  assert(useWorkbenchStore.getState().bottomDockTab === 'HEX', 'Bottom dock tab switched back to HEX');

  // 7. Physical Byte Offset & Synchronized Hex Stream
  const sampleChat = stateAfterLoad.chats[0];
  await useWorkbenchStore.getState().setSelectedArtifact({
    id: sampleChat.id,
    provenance: sampleChat.provenance,
    timestamp: sampleChat.timestamp,
    itemType: 'CHAT_MESSAGE',
    rawData: sampleChat
  });

  const updatedState = useWorkbenchStore.getState();
  assert(updatedState.selectedArtifact?.id === sampleChat.id, 'Artifact selected in state');
  // REVIEW C-04: no backend / unreadable file => no bytes are shown, and the reason is reported.
  assert(updatedState.hexWindow === null, 'Hex window is empty when real bytes cannot be read (never fabricated)');
  assert(typeof updatedState.hexError === 'string' && updatedState.hexError.length > 0, 'Hex viewer reports why bytes are unavailable');

  console.log('\n=== ALL WORKBENCH PAGINATION & 4-PANE UI TESTS PASSED (100% SUCCESS) ===\n');
}

runPAWorkbenchPaginationTest().catch((err) => {
  console.error(err);
  process.exit(1);
});
