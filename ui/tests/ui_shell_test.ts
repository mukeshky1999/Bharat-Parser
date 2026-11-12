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
ok(JSON.stringify(DEFAULT_PREFERENCES.hiddenColumns) === '{}', 'no column is hidden by default');
const hc = sanitizePreferences({ hiddenColumns: { CALLS: ['from', 7, 'to'], bad: 'x', ARR: null } }).hiddenColumns;
ok(JSON.stringify(hc) === JSON.stringify({ CALLS: ['from', 'to'] }), 'hidden columns keep only text names and drop anything else');
ok(JSON.stringify(sanitizePreferences({ hiddenColumns: [1, 2] }).hiddenColumns) === '{}', 'a list in place of the map gives no hidden columns');

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
  [/PhysicalAnalyzer|Physical Analyzer|Cellebrite|Magnet AXIOM|Oxygen Forensic|Chainalysis|TRM Labs|PAWorkbench|PAField|PATable|PA Table/, 'names from the product this design must not resemble'],
  [/Section 63|Section 230|Section 94|Bharatiya|BNSS|NCRP|Sec63|Sec230|1930 freeze|court-admissible/i, 'legal form or statute wording (the tool supplies facts; the examiner prepares legal forms)'],
  [/-\[#[0-9a-fA-F]{3,8}\]/, 'hard-coded colour in a class (use the theme scale)'],
  [/text-\[(?:[0-9]|10)(?:\.\d+)?px\]/, 'text smaller than 11px'],
  [/animate-(?:pulse|ping|bounce)/, 'blinking or pulsing animation'],
  [/\(WIPED\)|Pre-Transaction \(Lure\)|High-Risk \/ Structuring|Mule Intermediary|Critical Mule|Syndicate Link|Charge Sheet Chain/, 'a verdict worded as fact or a default label that names a role the evidence did not give'],
  [/BIT-FOR-BIT SEAL PASS|Air-Gapped PASS|SHA-256 Verified|Verified Both|Bit-Verified/, 'a status label that claims more than was checked'],
  [/bg-gradient|backdrop-blur|rounded-(?:xl|2xl|3xl)|font-(?:extrabold|black)|tracking-(?:wider|widest)|(?:group-)?hover:(?:scale|translate)/, 'decorative styling the visual system does not use (see docs/UI_DESIGN.md, Visual system)'],
  [/(?:text|bg|border|ring|from|to|via|fill|stroke)-(?:purple|pink|indigo|fuchsia|violet|teal|lime|yellow|orange|sky)-\d/, 'decorative hue: colour is the cyan accent or a status (emerald, amber, rose) only'],
  [/\bshadow-(?:lg|xl|2xl)\b|shadow-\[/, 'shadow on a surface: only floating layers use shadow-float'],
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

// ---- N-01: a frame that shows server-made HTML must never share the app's origin ------------------------------
{
  const rendererRoot = path.resolve(__dirname, '..', 'renderer');
  const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : /\.tsx?$/.test(e.name) ? [path.join(d, e.name)] : []);
  for (const f of walk(rendererRoot)) {
    if (/allow-same-origin/.test(fs.readFileSync(f, 'utf8'))) ok(false, `${path.relative(rendererRoot, f)} uses allow-same-origin`);
  }
  const main = fs.readFileSync(path.resolve(__dirname, '..', '..', 'electron', 'main.cjs'), 'utf8');
  ok(/Content-Security-Policy/.test(main), 'the Electron shell sets a Content-Security-Policy');
  ok(/will-frame-navigate/.test(main), 'sub-frame navigation is restricted');
  ok(/BHARAT_PARENT_PID/.test(main), 'the backend is told which process to watch');
}

if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log('ui_shell_test: all checks pass');
