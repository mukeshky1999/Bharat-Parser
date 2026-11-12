// Checks for the workflow-stage shell: preferences, stage map, the integrity line, and the rules the redesign promised.
import * as fs from 'fs';
import * as path from 'path';
import { sanitizePreferences, DEFAULT_PREFERENCES } from '../renderer/state/preferencesStore';
import { STAGES, stageForTab } from '../renderer/workspace/stages';
import { integrityText } from '../renderer/workspace/integrity';

let failures = 0;
function ok(cond: boolean, msg: string) {
  if (!cond) {
    failures++;
    console.error('FAIL:', msg);
  }
}

// ---- preferences: anything read from storage becomes a valid object -------------------------------------------
ok(JSON.stringify(sanitizePreferences(null)) === JSON.stringify(DEFAULT_PREFERENCES), 'null gives defaults');
ok(JSON.stringify(sanitizePreferences('garbage')) === JSON.stringify(DEFAULT_PREFERENCES), 'string gives defaults');
const wild = sanitizePreferences({ theme: 'neon', density: 'tiny', fontScale: 99, timeZone: 'PST', navWidth: -5, cardWidth: NaN, breakReminder: 'yes' });
ok(wild.theme === 'dim' && wild.density === 'comfortable', 'unknown theme/density fall back');
ok(wild.fontScale === 1.3, 'font scale is clamped to 1.3');
ok(wild.timeZone === 'IST', 'unknown time zone falls back');
ok(wild.navWidth === 180 && wild.cardWidth === DEFAULT_PREFERENCES.cardWidth, 'pane widths are clamped / defaulted');
ok(wild.breakReminder === false, 'break reminder stays off unless it is exactly true');
ok(sanitizePreferences({ theme: 'contrast', fontScale: 0.5 }).fontScale === 0.9, 'font scale lower clamp');
ok(DEFAULT_PREFERENCES.breakReminder === false, 'reminder is off by default');

// ---- stages ------------------------------------------------------------------------------------------------------
ok(STAGES.length === 8, 'eight stages');
ok(STAGES.every((s, i) => s.no === i + 1), 'stages are numbered 1..8 in order');
const tabs = STAGES.flatMap((s) => s.views.map((v) => v.tab));
ok(new Set(tabs).size === tabs.length, 'a view belongs to exactly one stage');
ok(stageForTab('UPI_LEDGER').id === 'money' && stageForTab('CHATS').id === 'messages', 'tab to stage lookup');
ok(['MALICIOUS_APKS', 'REMOTE_ACCESS'].every((t) => !tabs.includes(t as never)), 'views with no data source are not offered');

// ---- integrity line says only what was recorded ----------------------------------------------------------------
ok(integrityText(null).tone === 'none' && /nothing recorded/i.test(integrityText(null).text), 'no integrity data: says nothing recorded');
ok(/NOT RECORDED/.test(integrityText({ preSha256: 'a', postSha256: '', match: null }).text), 'no re-hash: says NOT RECORDED');
ok(/MATCH/.test(integrityText({ preSha256: 'a', postSha256: 'a', match: true }).text) && integrityText({ preSha256: 'a', postSha256: 'a', match: true }).tone === 'ok', 'match');
const bad = integrityText({ preSha256: 'a', postSha256: 'b', match: false });
ok(/MISMATCH/.test(bad.text) && bad.tone === 'bad', 'mismatch is flagged as bad');

// ---- source rules for everything under ui/renderer ---------------------------------------------------------------
function walk(dir: string, out: string[] = []): string[] {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (fs.statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|css)$/.test(f)) out.push(p);
  }
  return out;
}
const root = path.join(__dirname, '..', 'renderer');
const files = walk(root);
const banned: Array<[RegExp, string]> = [
  [/PhysicalAnalyzer|Physical Analyzer|Cellebrite|PAWorkbench|PAField|PATable|PA Table/, 'names from the product this design must not resemble'],
  [/-\[#[0-9a-fA-F]{3,8}\]/, 'hard-coded colour in a class (use the theme scale)'],
  [/text-\[(?:[0-9]|10)(?:\.\d+)?px\]/, 'text smaller than 11px'],
  [/animate-(?:pulse|ping|bounce)/, 'blinking or pulsing animation'],
  [/BIT-FOR-BIT SEAL PASS|Air-Gapped PASS|SHA-256 Verified|Verified Both|Bit-Verified/, 'a status label that claims more than was checked'],
];
for (const f of files) {
  if (f.endsWith('theme.css')) continue;
  const text = fs.readFileSync(f, 'utf8');
  for (const [re, why] of banned) {
    if (f.endsWith('index.css') && /animate/.test(re.source)) continue; // the stylesheet is where those animations are switched off
    const m = re.exec(text);
    if (m) {
      failures++;
      console.error(`FAIL: ${path.relative(root, f)} contains "${m[0]}": ${why}`);
    }
  }
}

if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log('ui_shell_test: all checks pass');
