// Review step 10: the screen never shows another case's data, an unknown stays unknown, and a late reply cannot win.
import * as fs from 'fs';
import * as path from 'path';
import { useWorkbenchStore, numberOrNull, callParties } from '../renderer/state/workbenchStore';
import { forensicClient } from '../renderer/api/forensicClient';
import { createLatestRequest } from '../renderer/utils/latestRequest';
import { csvCell, csvFileText } from '../renderer/utils/csv';
import { whenText } from '../renderer/utils/timeText';

let failures = 0;
function ok(cond: boolean, msg: string) {
  if (!cond) { failures++; console.error('FAIL:', msg); }
}

// ---- unknown stays unknown --------------------------------------------------------------------------------------
ok(numberOrNull(null) === null && numberOrNull('') === null && numberOrNull(undefined) === null && numberOrNull('abc') === null, 'no amount is null, not 0');
ok(numberOrNull(0) === 0 && numberOrNull('12.5') === 12.5, 'zero and numbers stay numbers');
const out = callParties('OUTGOING', '98765', '');
ok(out.callerName === 'This phone' && out.calleeNumberOrId === '98765' && out.callerNumberOrId === '', 'an outgoing call goes from this phone to the other party');
const inc = callParties('INCOMING', '98765', '');
ok(inc.callerNumberOrId === '98765' && inc.calleeName === 'This phone', 'an incoming call comes from the other party');
const unk = callParties('UNKNOWN', '98765', '');
ok(unk.callerNumberOrId === '' && unk.calleeNumberOrId === '' && unk.callerName === '' && unk.calleeName === '', 'an unknown direction names neither side');

// ---- a late reply cannot win ----------------------------------------------------------------------------------------
{
  const r = createLatestRequest();
  const a = r.begin();
  const b = r.begin();
  ok(a.signal.aborted && !a.isCurrent() && b.isCurrent(), 'a newer request replaces the older one');
  r.dispose();
  ok(!b.isCurrent() && b.signal.aborted, 'nothing is current after the component is gone');
}

// ---- timeline time text ---------------------------------------------------------------------------------------------
const ev = (o: Record<string, unknown>) => ({ utc: null, ist: null, local_clock: null, ...o }) as any;
ok(whenText(ev({ ist: '2026-02-01 10:00:00' }), 'IST') === '2026-02-01 10:00:00', 'an IST-only event shows its time');
ok(whenText(ev({ ist: '2026-02-01 10:00:00' }), 'UTC').includes('IST only'), 'in UTC mode an IST-only event says so');
ok(whenText(ev({ utc: '2026-02-01 04:30:00 UTC', ist: '2026-02-01 10:00:00' }), 'UTC') === '2026-02-01 04:30:00 UTC', 'UTC is not suffixed twice');
ok(whenText(ev({}), 'IST') === 'time not recorded', 'no time at all');

// ---- CSV -----------------------------------------------------------------------------------------------------------
ok(csvCell('-500') === '"-500"', 'a plain negative number stays a number');
ok(csvCell('-1+2') === `"'-1+2"`, 'a formula starting with a minus is neutralised');
ok(csvFileText(['a']).charCodeAt(0) === 0xFEFF, 'the file starts with a byte-order mark');

// ---- switching case: nothing of the old case stays, a failed page is an error, not "nothing found" -----------------------
async function storeTests() {
  const client = forensicClient as any;
  const orig = { getCaseSummary: client.getCaseSummary, queryArtifacts: client.queryArtifacts };
  const row = (id: number) => ({ id, Transaction_ID: `T${id}`, Amount: null, Type: 'UNKNOWN', VPA: 'x@ybl', Forensic_Provenance: '' });
  try {
    client.getCaseSummary = async () => ({ loaded: true, case_id: 'A', hashes: {}, extractions: [{}] });
    client.queryArtifacts = async (cat: string) => ({ success: true, rows: cat === 'upi_transactions' ? [row(1)] : [], total: cat === 'upi_transactions' ? 1 : 0 });
    await useWorkbenchStore.getState().syncWithBackendCase();
    let s = useWorkbenchStore.getState();
    ok(s.upiTransactions.length === 1, 'case A loads its payment');
    ok(s.upiTransactions[0].amountInr === null, 'a payment with no amount has no amount (not 0)');
    ok(s.upiTransactions[0].payerVpa === null && s.upiTransactions[0].payeeVpa === null && s.upiTransactions[0].counterpartyVpa === 'x@ybl', 'an unknown direction names no payer or payee');

    useWorkbenchStore.setState({ selectedArtifact: { id: 'TX_1' } as any });
    client.getCaseSummary = async () => ({ loaded: true, case_id: 'B', hashes: {}, extractions: [{}] });
    client.queryArtifacts = async () => ({ success: true, rows: [], total: 0 });
    await useWorkbenchStore.getState().syncWithBackendCase();
    s = useWorkbenchStore.getState();
    ok(s.upiTransactions.length === 0 && s.callLogs.length === 0 && s.chats.length === 0, 'case B (empty) shows none of case A');
    ok(s.selectedArtifact === null && s.hexWindow === null, 'the open record of case A is closed');

    client.queryArtifacts = async (cat: string) => (cat === 'calls' ? { success: false, error: 'boom', rows: [] } : { success: true, rows: [], total: 0 });
    await useWorkbenchStore.getState().syncWithBackendCase();
    s = useWorkbenchStore.getState();
    ok(Object.keys(s.loadErrors).join() === 'calls' && s.loadErrors.calls === 'boom', 'a failed read is reported, not shown as "no calls"');
  } finally {
    client.getCaseSummary = orig.getCaseSummary;
    client.queryArtifacts = orig.queryArtifacts;
  }
}

// ---- the source no longer carries the claims it cannot back ---------------------------------------------------------------
const root = path.resolve(__dirname, '..', 'renderer');
const read = (p: string) => fs.readFileSync(path.join(root, p), 'utf8');
ok(!/High-Value Target|\[OS SPILLOVER\]/.test(read('views/OsSpilloverView.tsx')), 'device traces carry no value ranking or invented state');
ok(!/SHA-256 match validated/.test(read('views/ChatsMasterWorkspace.tsx')), 'no static hash-validated claim on the attachment preview');
ok(!/Corroboration Engine Verified/.test(read('views/ExtractionSummaryTab.tsx')), 'no static "verified" badge on the dossier');
ok(!/'CASE_01'/.test(read('state/workbenchStore.ts')), 'no invented case id');
ok(!/Number\(v\)\.toLocaleString/.test(read('views/CryptoWalletView.tsx')), 'crypto amounts are not rounded through Number');

storeTests().then(() => {
  if (failures > 0) { console.error(`${failures} failure(s)`); process.exit(1); }
  console.log('review_step10_test: all checks pass');
});
