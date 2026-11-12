import React, { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { usePreferences, type ThemeName, type Density } from '../state/preferencesStore';
import { useUi } from '../state/uiStore';

const THEMES: Array<[ThemeName, string, string]> = [
  ['dim', 'Dim', 'Soft dark. Default for long sessions.'],
  ['light', 'Light', 'Off-white page. For bright rooms.'],
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
    <div className="fixed inset-0 z-[100] bg-black/60 grid place-items-center p-4" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="settings-title" className="w-full max-w-lg rounded-ctl-panel border border-slate-700 bg-slate-900 shadow-float">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <h2 id="settings-title" className="text-base font-semibold text-slate-50">Display settings</h2>
          <button onClick={close} className="p-1 rounded-ctl text-slate-400 hover:text-slate-100 hover:bg-slate-800" aria-label="Close settings"><X className="w-4 h-4" /></button>
        </div>

        <div className="p-5 space-y-5">
          <fieldset>
            <legend className="text-slate-300 font-medium mb-2">Colour theme</legend>
            <div className="space-y-1">
              {THEMES.map(([id, label, hint]) => (
                <label key={id} className={`flex items-start gap-3 rounded-ctl border px-3 py-2 cursor-pointer ${prefs.theme === id ? 'border-cyan-400 bg-slate-800' : 'border-slate-700 hover:bg-slate-800/60'}`}>
                  <input type="radio" name="theme" checked={prefs.theme === id} onChange={() => prefs.set({ theme: id })} className="mt-1" />
                  <span><span className="block text-slate-50">{label}</span><span className="block text-slate-400">{hint}</span></span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset>
            <legend className="text-slate-300 font-medium mb-2">Row density</legend>
            <div className="flex gap-2">
              {DENSITIES.map(([id, label]) => (
                <label key={id} className={`flex-1 flex items-center gap-2 rounded-ctl border px-3 py-2 cursor-pointer ${prefs.density === id ? 'border-cyan-400 bg-slate-800' : 'border-slate-700 hover:bg-slate-800/60'}`}>
                  <input type="radio" name="density" checked={prefs.density === id} onChange={() => prefs.set({ density: id })} />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>

          <div>
            <label htmlFor="font-scale" className="flex justify-between text-slate-300 font-medium mb-2">
              <span>Text size</span><span className="text-slate-400">{Math.round(prefs.fontScale * 100)}%</span>
            </label>
            <input id="font-scale" type="range" min={90} max={130} step={5} value={Math.round(prefs.fontScale * 100)} onChange={(e) => prefs.set({ fontScale: Number(e.target.value) / 100 })} className="w-full" />
            <p className="mt-2 text-slate-300">The quick brown fox: 12,48,300.00 · 09:41:07 IST · 9876543210</p>
          </div>

          <fieldset>
            <legend className="text-slate-300 font-medium mb-2">Show times in</legend>
            <div className="flex gap-2">
              {(['IST', 'UTC'] as const).map((z) => (
                <label key={z} className={`flex-1 flex items-center gap-2 rounded-ctl border px-3 py-2 cursor-pointer ${prefs.timeZone === z ? 'border-cyan-400 bg-slate-800' : 'border-slate-700 hover:bg-slate-800/60'}`}>
                  <input type="radio" name="tz" checked={prefs.timeZone === z} onChange={() => prefs.set({ timeZone: z })} />
                  {z === 'IST' ? 'IST (UTC+05:30)' : 'UTC'}
                </label>
              ))}
            </div>
            <p className="mt-1 text-slate-400">Both are always kept in the record; this only chooses which is shown first.</p>
          </fieldset>

          <label className="flex items-start gap-3 cursor-pointer">
            <input type="checkbox" checked={prefs.breakReminder} onChange={(e) => prefs.set({ breakReminder: e.target.checked })} className="mt-1" />
            <span>
              <span className="block text-slate-50">Rest-your-eyes reminder</span>
              <span className="block text-slate-400">Every 20 minutes, a short note to look at something 20 feet away for 20 seconds.</span>
            </span>
          </label>
        </div>

        <div className="flex justify-between px-5 py-3 border-t border-slate-800">
          <button onClick={prefs.reset} className="h-8 px-3 rounded-ctl border border-slate-700 text-slate-200 hover:bg-slate-800">Reset to defaults</button>
          <button onClick={close} className="h-8 px-4 rounded-ctl bg-cyan-600 text-slate-50 hover:bg-cyan-500">Done</button>
        </div>
      </div>
    </div>
  );
};
