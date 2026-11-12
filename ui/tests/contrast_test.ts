// Every text/background pair the themes can produce must be readable (WCAG 2.x contrast).
// Reads the real theme.css, so editing a colour without re-checking it fails here.
import * as fs from 'fs';
import * as path from 'path';

const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'theme.css'), 'utf8').replace(new RegExp(String.fromCharCode(13), 'g'), '');

function themeVars(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`theme block ${selector} missing`);
  const body = css.slice(css.indexOf('{', start) + 1, css.indexOf('}', start));
  const vars: Record<string, string> = {};
  for (const m of body.matchAll(/--c-([a-z]+(?:-\d+)?):\s*(#[0-9a-f]{6});/g)) vars[m[1]] = m[2];
  return vars;
}

function lum(hex: string): number {
  const ch = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)));
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}
function ratio(a: string, b: string): number {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const themes: Array<[string, string]> = [
  [":root,\n:root[data-theme='dim']", 'dim'],
  [":root[data-theme='light']", 'light'],
  [":root[data-theme='contrast']", 'contrast'],
];
const bodyBg = [900, 950];
const panelBg = [800, 900, 950];
let failures = 0;
function check(theme: string, label: string, fg: string, bg: string, min: number) {
  const r = ratio(fg, bg);
  if (r < min) {
    failures++;
    console.error(`FAIL [${theme}] ${label}: ${r.toFixed(2)} < ${min} (${fg} on ${bg})`);
  }
}

for (const [sel, name] of themes) {
  const v = themeVars(sel);
  const strict = name === 'contrast' ? 7 : 4.5;
  // neutral text
  for (const t of [50, 100, 200, 300, 400]) for (const b of panelBg) check(name, `slate-${t} on slate-${b}`, v[`slate-${t}`], v[`slate-${b}`], b === 800 ? 4.5 : strict);
  for (const b of bodyBg) check(name, `slate-500 on slate-${b}`, v['slate-500'], v[`slate-${b}`], 4.5);
  // hue text on neutral surfaces
  for (const fam of ['cyan', 'emerald', 'amber', 'rose', 'red', 'sky', 'teal', 'purple', 'indigo', 'orange', 'blue']) {
    for (const b of bodyBg) check(name, `${fam}-400 on slate-${b}`, v[`${fam}-400`], v[`slate-${b}`], 4.5);
  }
  // tinted status panels: text step on its own tint
  for (const fam of ['emerald', 'amber', 'rose', 'cyan', 'red']) check(name, `${fam}-300 on ${fam}-950`, v[`${fam}-300`], v[`${fam}-950`], 4.5);
  // filled buttons: lightest text step on the 600 fill
  for (const fam of ['cyan', 'emerald', 'rose', 'blue']) check(name, `slate-50 on ${fam}-600`, v['slate-50'], v[`${fam}-600`], 4.5);
  // component boundary visible against the page (high-contrast promise)
  if (name === 'contrast') check(name, 'border slate-800 vs slate-950', v['slate-800'], v['slate-950'], 3);
}

if (failures > 0) {
  console.error(`${failures} contrast failure(s)`);
  process.exit(1);
}
console.log('contrast_test: all pairs pass in dim, light and contrast themes');
