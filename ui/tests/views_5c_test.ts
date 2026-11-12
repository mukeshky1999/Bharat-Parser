// Phase 5C: the new screens are registered, and the rules they promised are still in their source.
import * as fs from 'fs';
import * as path from 'path';
import { STAGES } from '../renderer/workspace/stages';
import { shownValue, NOT_RECORDED } from '../renderer/utils/recordText';

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
ok(/may be incomplete/.test(search) && /was not searched/.test(search), 'search says when it stopped early or skipped a table');
// tags are the examiner's decisions
ok(/the tool applies none/.test(insp('RecordDetail.tsx')), 'record panel says the tool applies no tags');
// progress: no invented percentage
const prog = view('IngestProgressPanel.tsx');
ok(/cannot say how much is left/.test(prog) && /fraction === null/.test(prog), 'progress shows "working" when the step cannot be counted');
// none of the new screens keeps case data in browser storage
for (const f of ['SearchView.tsx', 'TimelineView.tsx', 'TagsView.tsx', 'MediaLibraryView.tsx', 'IngestProgressPanel.tsx']) {
  ok(!/localStorage|sessionStorage|indexedDB/.test(view(f)), `${f} does not use browser storage`);
}
ok(!/localStorage|sessionStorage|indexedDB/.test(insp('RecordDetail.tsx')), 'RecordDetail does not use browser storage');

if (failures > 0) { console.error(`${failures} failure(s)`); process.exit(1); }
console.log('views_5c_test: all checks pass');
