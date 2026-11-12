// Phase 5C: the new screens are registered, and the rules they promised are still in their source.
import * as fs from 'fs';
import * as path from 'path';
import { STAGES } from '../renderer/workspace/stages';
import { shownValue, NOT_RECORDED } from '../renderer/utils/recordText';
import { caseRecordOf } from '../renderer/utils/caseRecord';
import { interpret, parseOffset } from '../renderer/utils/byteInterpreter';

let failures = 0;
function ok(cond: boolean, msg: string) {
  if (!cond) { failures++; console.error('FAIL:', msg); }
}

const tabs = STAGES.flatMap((s) => s.views.map((v) => v.tab as string));
ok(STAGES.length === 8, 'still eight stages');
ok(new Set(tabs).size === tabs.length, 'a view appears in one stage only');
for (const t of ['SEARCH', 'TAGS', 'TIMELINE', 'MEDIA']) ok(tabs.includes(t), `${t} is reachable from a stage`);

// a value that was not recorded is shown as such; zero and false are values
ok(shownValue(null) === NOT_RECORDED && shownValue(undefined) === NOT_RECORDED && shownValue('') === NOT_RECORDED, 'null, undefined and empty show "not recorded"');
ok(shownValue(0) === '0' && shownValue(false) === 'false', 'zero and false are shown as values');
ok(shownValue({ a: 1 }) === '{"a":1}', 'objects are shown as JSON');

// which case-store row a selected item is
const eq = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
ok(eq(caseRecordOf('TX_7'), { table: 'transactions', id: 7 }), 'TX_ id is a transactions row');
ok(eq(caseRecordOf('CNT_3'), { table: 'contacts', id: 3 }) && eq(caseRecordOf('CALL_9'), { table: 'calls', id: 9 }), 'contacts and calls rows');
ok(eq(caseRecordOf('MSG50#12', 'CHAT_MESSAGE'), { table: 'chats', id: 12 }), 'chat message id ends in its row');
ok(eq(caseRecordOf('100000000011#4', 'Financial Transaction'), { table: 'transactions', id: 4 }), 'transaction id ends in its row');
ok(caseRecordOf('file#table#5') === null && caseRecordOf('x#0', 'CHAT_MESSAGE') === null && caseRecordOf(undefined) === null && caseRecordOf('TX_0') === null,
  'anything that is not a case row is not tagged from the card');
ok(/not found/.test(fs.readFileSync(path.join(__dirname, '..', 'renderer', 'inspectors', 'BulkTagBar.tsx'), 'utf8')), 'bulk tagging reports records that were not found');

const view = (name: string) => fs.readFileSync(path.join(__dirname, '..', 'renderer', 'views', name), 'utf8');
const insp = (name: string) => fs.readFileSync(path.join(__dirname, '..', 'renderer', 'inspectors', name), 'utf8');

// the timeline keeps the "no zone" distinction visible
const tl = view('TimelineView.tsx');
ok(/zone not recorded/.test(tl) && /clock_only/.test(tl) && /no_time/.test(tl), 'timeline labels clock-only and no-time events and does not place them');
// media: the camera clock and look-alike results carry their labels
const media = view('MediaLibraryView.tsx');
ok(/no zone recorded, not converted/.test(media), 'camera clock is labelled as having no zone');
ok(/LEAD/.test(media), 'look-alike results are labelled as a lead');
ok(/ships no list/.test(media), 'the hash list panel says the tool ships no list');
// search says when it is incomplete
const search = view('SearchView.tsx');
ok(/may be incomplete/.test(search) && /were not searched/.test(search), 'search says when it stopped early or skipped a table');
// tags are the examiner's decisions
ok(/the tool applies none/.test(insp('TagControls.tsx')), 'record panel says the tool applies no tags');
// progress: no invented percentage
const prog = view('IngestProgressPanel.tsx');
ok(/cannot say how much is left/.test(prog) && /fraction === null/.test(prog), 'progress shows "working" when the step cannot be counted');
// reviewer marks and validation say what they are
const marksCard = view('ReviewerMarksCard.tsx');
ok(/never become tags|not a tag|apart from your tags/.test(marksCard + fs.readFileSync(path.join(__dirname, '..', '..', 'parsers', 'review_marks.py'), 'utf8')), 'reviewer marks are kept apart from tags');
ok(/not touched/.test(view('ValidationCard.tsx')) && /does not show the tool is right/.test(view('ValidationCard.tsx')), 'validation says it leaves the case alone and what it does not show');

// the hex data interpreter: readings, not findings
const rd = (b: number[]) => Object.fromEntries(interpret(Uint8Array.from(b)).map((r) => [r.label, r.value]));
const u32 = rd([0x00, 0xf1, 0x53, 0x65, 0, 0, 0, 0]);          // 1700000000 little-endian
ok(u32['Unsigned 32-bit, little-endian'] === '1700000000', 'unsigned 32-bit little-endian');
ok(u32['As Unix seconds (32-bit, little-endian)'] === '2023-11-14T22:13:20Z UTC', 'a plausible Unix time is shown as a reading');
ok(rd([1, 0])['Unsigned 16-bit, little-endian'] === '1' && rd([1, 0])['Unsigned 16-bit, big-endian'] === '256', 'both byte orders');
const ms = new DataView(new ArrayBuffer(8)); ms.setBigUint64(0, 1700000000000n, true);
ok(rd([...new Uint8Array(ms.buffer)])['As Unix milliseconds (64-bit, little-endian)'] === '2023-11-14T22:13:20Z UTC', 'Unix milliseconds');
const wk = new DataView(new ArrayBuffer(8)); wk.setBigUint64(0, (1700000000000n + 11644473600000n) * 1000n, true);
ok(rd([...new Uint8Array(wk.buffer)])['As WebKit microseconds since 1601 (64-bit)'] === '2023-11-14T22:13:20Z UTC', 'WebKit time');
ok(!('As Unix seconds (32-bit, little-endian)' in rd([0xff, 0xff, 0xff, 0xff])) && !('As Unix seconds (32-bit, little-endian)' in rd([1, 0, 0, 0])),
  'a value outside 2000-2100 is not offered as a time');
ok(interpret(Uint8Array.from([])).length === 0 && !('Unsigned 32-bit, little-endian' in rd([1, 2, 3])), 'too few bytes give no reading that needs more');
ok(parseOffset('0x1F4') === 500 && parseOffset('500') === 500 && parseOffset('1f4') === 500 && parseOffset('zz') === null && parseOffset('') === null, 'offsets parse as hex or decimal, or not at all');
ok(/readings, not findings/.test(fs.readFileSync(path.join(__dirname, '..', 'renderer', 'inspectors', 'DataInterpreter.tsx'), 'utf8')), 'the interpreter says its values are readings');

// none of the new screens keeps case data in browser storage
for (const f of ['ReviewerMarksCard.tsx', 'ValidationCard.tsx', 'SearchView.tsx', 'TimelineView.tsx', 'TagsView.tsx', 'MediaLibraryView.tsx', 'IngestProgressPanel.tsx']) {
  ok(!/localStorage|sessionStorage|indexedDB/.test(view(f)), `${f} does not use browser storage`);
}
ok(!/localStorage|sessionStorage|indexedDB/.test(insp('RecordDetail.tsx') + insp('TagControls.tsx') + insp('BulkTagBar.tsx')), 'RecordDetail does not use browser storage');

if (failures > 0) { console.error(`${failures} failure(s)`); process.exit(1); }
console.log('views_5c_test: all checks pass');
