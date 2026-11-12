/**
 * Workbench store behaviour: filters, view modes, pagination state, selection, and the hex viewer's
 * refusal to invent bytes. The fixture below is a test-local record, not shipped data.
 */

import { useWorkbenchStore } from '../renderer/state/workbenchStore';
import { ChatArtifact, ForensicProvenance, normalizeTimestamp } from '../shared/forensic-types';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`[FAIL] ${msg}`);
    process.exit(1);
  }
  console.log(`[PASS] ${msg}`);
}

const provenance: ForensicProvenance = {
  evidenceId: 'TEST',
  archivePath: '/does/not/exist.zip',
  vfsInternalPath: '/does/not/exist/msgstore.db',
  containerType: 'SQLITE',
  tableName: 'messages',
  rowId: 1,
  byteOffset: 4096,
  byteLength: 32,
  recoveryState: 'ACTIVE',
  rawPayloadHex: ''
};

const chat: ChatArtifact = {
  id: 'T_1',
  threadId: 'thread-1',
  sourceApp: 'WhatsApp',
  senderJid: '919999999999@s.whatsapp.net',
  senderName: 'Test Sender',
  body: 'test message',
  isFromMe: false,
  timestamp: normalizeTimestamp('2026-01-02T03:04:05Z', 'ISO_8601'),
  isDeleted: false,
  provenance
};

async function runWorkbenchStoreTest() {
  console.log('=== WORKBENCH STORE TESTS ===\n');

  // 1. A fresh store holds no records: nothing is preloaded.
  const fresh = useWorkbenchStore.getState();
  assert(fresh.chats.length === 0, 'Fresh store has no chat records');
  assert(fresh.upiTransactions.length === 0, 'Fresh store has no transactions');
  assert(fresh.currentPage === 1 && fresh.pageSize === 100, 'Default pagination is page 1, size 100');
  assert(!('loadGoldenDataset' in fresh), 'No demo-dataset loader exists');

  useWorkbenchStore.setState({ chats: [chat] });
  assert(useWorkbenchStore.getState().chats.length === 1, 'Test fixture installed');

  // 2. Recovery-state filter
  for (const f of ['WAL', 'CARVED', 'ALL'] as const) {
    useWorkbenchStore.getState().setRecoveryPillFilter(f);
    assert(useWorkbenchStore.getState().recoveryPillFilter === f, `Recovery filter set to ${f}`);
  }

  // 3. Ephemeral filter
  for (const f of ['VIEW_ONCE', 'DISAPPEARING', 'ALL'] as const) {
    useWorkbenchStore.getState().setEphemeralFilter(f);
    assert(useWorkbenchStore.getState().ephemeralFilter === f, `Ephemeral filter set to ${f}`);
  }

  // 4. Chat view modes
  for (const m of ['GRID', 'BUBBLE', 'DOSSIER'] as const) {
    useWorkbenchStore.getState().setChatViewMode(m);
    assert(useWorkbenchStore.getState().chatViewMode === m, `Chat view mode set to ${m}`);
  }

  // 5. Pagination state
  useWorkbenchStore.getState().setCurrentPage(2);
  assert(useWorkbenchStore.getState().currentPage === 2, 'Current page updated to 2');
  useWorkbenchStore.getState().setCurrentPage(1);
  assert(useWorkbenchStore.getState().currentPage === 1, 'Current page reset to 1');

  // 6. Bottom dock tabs
  assert(useWorkbenchStore.getState().bottomDockTab === 'HEX', 'Default bottom dock tab is HEX');
  useWorkbenchStore.getState().setBottomDockTab('DECODED_TREE');
  assert(useWorkbenchStore.getState().bottomDockTab === 'DECODED_TREE', 'Bottom dock tab switched');
  useWorkbenchStore.getState().setBottomDockTab('HEX');

  // 7. Selecting a record whose source file cannot be read must not fabricate bytes (REVIEW C-04).
  await useWorkbenchStore.getState().setSelectedArtifact({
    id: chat.id,
    provenance: chat.provenance,
    timestamp: chat.timestamp,
    itemType: 'CHAT_MESSAGE',
    rawData: chat
  });
  const s = useWorkbenchStore.getState();
  assert(s.selectedArtifact?.id === chat.id, 'Artifact selected in state');
  assert(s.hexWindow === null, 'Hex window is empty when real bytes cannot be read (never fabricated)');
  assert(typeof s.hexError === 'string' && s.hexError.length > 0, 'Hex viewer reports why bytes are unavailable');

  console.log('\n=== ALL WORKBENCH STORE TESTS PASSED ===\n');
}

runWorkbenchStoreTest().catch((err) => {
  console.error(err);
  process.exit(1);
});
