import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { usePreferences, type ThemeName, type Density } from '../state/preferencesStore';
import { useUi } from '../state/uiStore';

const THEMES: Array<[ThemeName, string, string]> = [
  ['light', 'Light', 'White cards on a soft grey page. Default.'],
  ['dim', 'Dim', 'Soft dark. For long sessions in low light.'],
  ['contrast', 'High contrast', 'Black and white. Strongest separation.'],
];
const DENSITIES: Array<[Density, string]> = [['comfortable', 'Comfortable rows'], ['compact', 'Compact rows']];

export const SettingsDialog: React.FC = () => {
  const dialog = useUi((s) => s.dialog);
  const close = useUi((s) => s.close);
  const prefs = usePreferences();
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (dialog !== 'SETTINGS') return;
    ref.current?.querySelector<HTMLElement>('input,button')?.focus();
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && close();
    document.addEventListener('keydown', esc);
    return () => document.removeEventListener('keydown', esc);
  }, [dialog, close]);

  if (dialog !== 'SETTINGS') return null;

  return (
    <div className="fixed inset-0 z-[100] bg-ink/40 grid place-items-center p-4" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="settings-title" className="w-full max-w-lg rounded-[10px] border border-line bg-surface shadow-float">
        <div className="flex items-center justify-between px-5 py-3 border-b border-line">
          <h2 id="settings-title" className="text-base font-semibold text-ink">Display settings</h2>
          <button onClick={close} className="p-1 rounded text-muted hover:text-ink hover:bg-hover" aria-label="Close settings"><X className="w-4 h-4" /></button>
        </div>

        <div className="p-5 space-y-5">
          <fieldset>
            <legend className="text-ink font-medium mb-2">Colour theme</legend>
            <div className="space-y-1">
              {THEMES.map(([id, label, hint]) => (
                <label key={id} className={`flex items-start gap-3 rounded border px-3 py-2 cursor-pointer ${prefs.theme === id ? 'border-accent bg-accent-soft' : 'border-line hover:bg-hover'}`}>
                  <input type="radio" name="theme" checked={prefs.theme === id} onChange={() => prefs.set({ theme: id })} className="mt-1" />
                  <span><span className="block text-ink">{label}</span><span className="block text-muted">{hint}</span></span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset>
            <legend className="text-ink font-medium mb-2">Row density</legend>
            <div className="flex gap-2">
              {DENSITIES.map(([id, label]) => (
                <label key={id} className={`flex-1 flex items-center gap-2 rounded border px-3 py-2 cursor-pointer ${prefs.density === id ? 'border-accent bg-accent-soft' : 'border-line hover:bg-hover'}`}>
                  <input type="radio" name="density" checked={prefs.density === id} onChange={() => prefs.set({ density: id })} />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>

          <div>
            <label htmlFor="font-scale" className="flex justify-between text-ink font-medium mb-2">
              <span>Text size</span><span className="text-muted">{Math.round(prefs.fontScale * 100)}%</span>
            </label>
            <input id="font-scale" type="range" min={90} max={130} step={5} value={Math.round(prefs.fontScale * 100)} onChange={(e) => prefs.set({ fontScale: Number(e.target.value) / 100 })} className="w-full" />
            <p className="mt-2 text-ink">The quick brown fox: 12,48,300.00 · 09:41:07 IST · 9876543210</p>
          </div>

          <fieldset>
            <legend className="text-ink font-medium mb-2">Show times in</legend>
            <div className="flex gap-2">
              {(['IST', 'UTC'] as const).map((z) => (
                <label key={z} className={`flex-1 flex items-center gap-2 rounded border px-3 py-2 cursor-pointer ${prefs.timeZone === z ? 'border-accent bg-accent-soft' : 'border-line hover:bg-hover'}`}>
                  <input type="radio" name="tz" checked={prefs.timeZone === z} onChange={() => prefs.set({ timeZone: z })} />
                  {z === 'IST' ? 'IST (UTC+05:30)' : 'UTC'}
                </label>
              ))}
            </div>
            <p className="mt-1 text-muted">Both are always kept in the record; this only chooses which is shown first.</p>
          </fieldset>

          <label className="flex items-start gap-3 cursor-pointer">
            <input type="checkbox" checked={prefs.breakReminder} onChange={(e) => prefs.set({ breakReminder: e.target.checked })} className="mt-1" />
            <span>
              <span className="block text-ink">Rest-your-eyes reminder</span>
              <span className="block text-muted">Every 20 minutes, a short note to look at something 20 feet away for 20 seconds.</span>
            </span>
          </label>
        </div>

        <div className="flex justify-between px-5 py-3 border-t border-line">
          <button onClick={prefs.reset} className="h-8 px-3 rounded-lg border border-line-strong text-ink hover:bg-hover">Reset to defaults</button>
          <button onClick={close} className="h-8 px-4 rounded-lg bg-accent text-on-accent hover:brightness-110">Done</button>
        </div>
      </div>
    </div>
  );
};
