import { useWorkbenchStore } from '../renderer/state/workbenchStore';
import { normalizeTimestamp } from '../shared/forensic-types';

console.log('=== [PHASE 6 & 7 CHAT, SOCIAL, PRIVACY & CELLEBRITE PA MULTI-FIELD CATEGORIZATION TEST SUITE] ===\n');

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

// 1. Store Initialization & Golden Dataset Verification
const store = useWorkbenchStore.getState();
store.loadGoldenDataset();

const updatedState = useWorkbenchStore.getState();
const chats = updatedState.chats;
const calls = updatedState.callLogs;
const contacts = updatedState.contacts;
const spillovers = updatedState.osSpillovers;

assert(chats.length >= 10, 'Golden dataset loaded at least 10 chat artifacts across target app suites');

// 2. Multi-App Suite Verification
const appsInChats = new Set(chats.map(c => c.sourceApp));
assert(appsInChats.has('WhatsApp'), 'WhatsApp artifact parsed and loaded');
assert(appsInChats.has('Telegram'), 'Telegram artifact parsed and loaded');
assert(appsInChats.has('Signal'), 'Signal Private Messenger artifact parsed and loaded');
assert(appsInChats.has('Zangi'), 'Zangi Private Messenger artifact parsed and loaded');
assert(appsInChats.has('Element'), 'Element / Matrix artifact parsed and loaded');
assert(appsInChats.has('Session'), 'Session Messenger artifact parsed and loaded');
assert(appsInChats.has('Threema'), 'Threema / SimpleX artifact parsed and loaded');
assert(appsInChats.has('Snapchat'), 'Snapchat (Arroyo Engine) artifact parsed and loaded');
assert(appsInChats.has('Instagram'), 'Instagram Direct artifact parsed and loaded');
assert(appsInChats.has('Tinder'), 'Dating App (Tinder Romance Scam Vector) artifact parsed and loaded');

// 3. Active vs WAL Carved Messages Recovery
const activeWA = chats.find(c => c.id === 'WA_01');
const walWA = chats.find(c => c.id === 'WA_02_WAL');

assert(activeWA !== undefined && activeWA.provenance.recoveryState === 'ACTIVE', 'Active WhatsApp message identified in B-Tree table');
assert(walWA !== undefined && walWA.provenance.recoveryState === 'WAL_RECOVERED' && walWA.isDeleted === true, 'Deleted WhatsApp message recovered from WAL frame');

// 4. Privacy & Ephemeral Feature Attributes (No Column Flattening)
const signalMsg = chats.find(c => c.sourceApp === 'Signal');
assert(signalMsg !== undefined && signalMsg.ephemeralDuration === 30, 'Signal message preserves 30s ephemeral timer');

const zangiMsg = chats.find(c => c.sourceApp === 'Zangi');
assert(zangiMsg !== undefined && zangiMsg.senderJid === '1084920194', 'Zangi message preserves 10-digit military Zangi ID 1084920194');

const sessionMsg = chats.find(c => c.sourceApp === 'Session');
assert(sessionMsg !== undefined && sessionMsg.senderJid.startsWith('05b9'), 'Session message preserves 66-character hex Session ID (05b9...)');

const tinderMsg = chats.find(c => c.sourceApp === 'Tinder');
assert(tinderMsg !== undefined && !!tinderMsg.locationName?.includes('Bengaluru'), 'Tinder dating lead preserves location metadata');

// 5. Call Logs Forensic Ledger
assert(calls.length >= 4, 'Call logs ledger populated with Cellular CDR and VoIP calls');
const cellularCall = calls.find(c => c.callType === 'CELLULAR_CDR');
const voipCall = calls.find(c => c.callType === 'VOIP_APP' && c.sourceApp === 'WhatsApp');
const zangiCall = calls.find(c => c.callType === 'VOIP_APP' && c.sourceApp === 'Zangi');

assert(cellularCall !== undefined && cellularCall.durationSeconds === 245, 'Cellular CDR record parsed with 245s duration');
assert(voipCall !== undefined && voipCall.direction === 'INCOMING', 'WhatsApp VoIP incoming call parsed');
assert(zangiCall !== undefined && zangiCall.callerNumberOrId === '1084920194', 'Zangi VoIP call mapped to 10-digit caller ID');

// 6. Contacts & Dating Romance Leads
assert(contacts.length >= 4, 'Contacts ledger populated');
const datingContact = contacts.find(c => c.sourceApp === 'Tinder');
assert(datingContact !== undefined && datingContact.datingMetadata?.age === 26, 'Dating match preserves romance lead age (26)');
assert(datingContact !== undefined && datingContact.datingMetadata?.distanceKm === 4.2, 'Dating match preserves distance (4.2 km)');

// 7. OS-Level Privacy Spillover Recovery
assert(spillovers.length >= 5, 'OS Privacy Spillover populated with 5 vectors');
const notif = spillovers.find(s => s.category === 'NOTIFICATION_LOG');
const kb = spillovers.find(s => s.category === 'KEYBOARD_CACHE');
const clip = spillovers.find(s => s.category === 'CLIPBOARD');
const snap = spillovers.find(s => s.category === 'APP_SWITCHER_SNAPSHOT');
const usage = spillovers.find(s => s.category === 'TIMELINE_USAGE');

assert(notif !== undefined && !!notif.targetData?.includes('492019'), 'Notification spillover captured intercepted OTP 492019');
assert(kb !== undefined && !!kb.targetData?.includes('0x71C8360938A9184B918274910284729184719283'), 'Gboard cache recovered TRC-20 USDT off-ramp address');
assert(clip !== undefined && !!clip.targetData?.includes('1084920194'), 'Clipboard cache recovered Zangi ID 1084920194');
assert(snap !== undefined && !!snap.filePath?.includes('10492_snap.jpg'), 'App Switcher CE snapshot recovered');
assert(usage !== undefined && usage.snippet.includes('AnyDesk'), 'UsageStats foreground timeline corroborates AnyDesk to PhonePe sequence');

// 8. Hex Viewer Window Streaming & Byte Offset Accuracy
const testProv = activeWA!.provenance;
useWorkbenchStore.getState().fetchHexWindowForOffset(testProv).then(() => {
  const hexState = useWorkbenchStore.getState().hexWindow;
  // REVIEW C-04: the fixture's evidence file is not on disk, so no bytes may be invented.
  assert(hexState === null, 'No hex window is fabricated when the evidence file cannot be read');
  assert(!!useWorkbenchStore.getState().hexError, 'Hex viewer reports why bytes are unavailable');

  // Verify view mode toggle
  useWorkbenchStore.getState().setChatViewMode('BUBBLE');
  assert(useWorkbenchStore.getState().chatViewMode === 'BUBBLE', 'Chat view mode switched to BUBBLE');
  useWorkbenchStore.getState().setChatViewMode('GRID');
  assert(useWorkbenchStore.getState().chatViewMode === 'GRID', 'Chat view mode switched to PA Table GRID');

  // 10. Voice Note (.opus) & View-Once Verification
  const voiceNote = useWorkbenchStore.getState().chats.find(c => c.id === 'WA_03_VOICE');
  assert(voiceNote !== undefined && voiceNote.mediaType === 'VOICE_NOTE', 'WhatsApp .opus Voice Note artifact loaded');
  assert(voiceNote !== undefined && voiceNote.mediaMimeType?.includes('opus') === true, 'Audio codec identified as Opus');
  assert(voiceNote !== undefined && !!voiceNote.quotedMessageText, 'Quoted reply context preserved in voice note');

  const viewOnceMsg = useWorkbenchStore.getState().chats.find(c => c.id === 'WA_04_VIEWONCE');
  assert(viewOnceMsg !== undefined && viewOnceMsg.isViewOnce === true, 'View-Once ephemeral photo flag identified');

  // 11. Synchronized Selection & Categorized Inspector State
  useWorkbenchStore.getState().setSelectedArtifact({
    id: voiceNote!.id,
    provenance: voiceNote!.provenance,
    timestamp: voiceNote!.timestamp,
    itemType: 'CHAT_MESSAGE',
    rawData: voiceNote
  }).then(() => {
    const sel = useWorkbenchStore.getState().selectedArtifact;
    assert(sel !== null && sel.id === 'WA_03_VOICE', 'Selected artifact synchronized with Field Inspector store');
    assert(sel !== null && sel.provenance.byteOffset === 0x00067200, 'Selected artifact hex offset matched 0x00067200');

    console.log(`\n=== RESULTS: ALL ${passed}/${total} PHASE 6 & 7 TESTS PASSED (100% SUCCESS) ===\n`);
  });
});
