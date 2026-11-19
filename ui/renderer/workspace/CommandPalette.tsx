import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useUi } from '../state/uiStore';
import { useWorkbenchStore } from '../state/workbenchStore';
import { usePreferences } from '../state/preferencesStore';
import { GROUPS } from './dataTree';

interface Command {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

export const CommandPalette: React.FC<{ onPickFile: () => void; onPickFolder: () => void }> = ({ onPickFile, onPickFolder }) => {
  const dialog = useUi((s) => s.dialog);
  const close = useUi((s) => s.close);
  const open = useUi((s) => s.open);
  const setActiveTab = useWorkbenchStore((s) => s.setActiveTab);
  const addToast = useWorkbenchStore((s) => s.addToast);
  const setSearchQuery = useWorkbenchStore((s) => s.setSearchQuery);
  const setPref = usePreferences((s) => s.set);
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const commands: Command[] = useMemo(() => {
    const go: Command[] = GROUPS.flatMap((st) =>
      st.views.map((v) => ({
        id: `go-${v.tab}`, label: `Go to ${v.label}`, hint: v.unavailable ? 'Not available yet' : v.inTesting ? `In testing · ${st.label}` : st.label,
        run: () => (v.unavailable ? addToast({ type: 'info', title: `${v.label}: not available yet`, message: v.unavailable }) : setActiveTab(v.tab)),
      }))
    );
    return [
      ...go,
      { id: 'open-file', label: 'Open evidence file…', run: onPickFile },
      { id: 'open-folder', label: 'Open extracted folder…', run: onPickFolder },
      { id: 'settings', label: 'Display settings', run: () => open('SETTINGS') },
      { id: 't-light', label: 'Theme: Light', run: () => setPref({ theme: 'light' }) },
      { id: 't-dim', label: 'Theme: Dim', run: () => setPref({ theme: 'dim' }) },
      { id: 't-contrast', label: 'Theme: High contrast', run: () => setPref({ theme: 'contrast' }) },
      { id: 'd-compact', label: 'Rows: Compact', run: () => setPref({ density: 'compact' }) },
      { id: 'd-comf', label: 'Rows: Comfortable', run: () => setPref({ density: 'comfortable' }) },
    ];
  }, [setActiveTab, addToast, open, setPref, onPickFile, onPickFolder]);

  const term = q.trim().toLowerCase();
  const matches = term ? commands.filter((c) => `${c.label} ${c.hint ?? ''}`.toLowerCase().includes(term)) : commands.slice(0, 12);
  const items: Command[] = term
    ? [
        ...matches,
        {
          id: 'search',
          label: `Search records for “${q.trim()}”`,
          hint: 'Lists every record that contains it',
          run: () => {
            setSearchQuery(q.trim());
            setActiveTab('SEARCH');
          },
        },
      ]
    : matches;

  useEffect(() => {
    if (dialog === 'PALETTE') {
      setQ('');
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [dialog]);

  if (dialog !== 'PALETTE') return null;

  const run = (c: Command | undefined) => {
    if (!c) return;
    close();
    c.run();
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); run(items[idx]); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  };

  return (
    <div className="fixed inset-0 z-[100] bg-ink/40 flex items-start justify-center pt-[12vh] p-4" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div role="dialog" aria-modal="true" aria-label="Search and commands" className="w-full max-w-xl rounded-[10px] border border-line bg-surface shadow-float overflow-hidden">
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => { setQ(e.target.value); setIdx(0); }}
          onKeyDown={onKey}
          placeholder="Type a view, a command, or words to search for"
          aria-label="Search or jump"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          className="w-full h-12 px-4 bg-surface text-ink placeholder:text-faint border-b border-line outline-none"
        />
        <ul id="palette-list" role="listbox" className="max-h-80 overflow-y-auto py-1">
          {items.map((c, i) => (
            <li key={c.id} role="option" aria-selected={i === idx}>
              <button
                onMouseEnter={() => setIdx(i)}
                onClick={() => run(c)}
                className={`w-full flex items-center justify-between px-4 py-2 text-left ${i === idx ? 'bg-accent-soft text-accent-ink' : 'text-ink'}`}
              >
                <span>{c.label}</span>
                {c.hint && <span className="text-muted text-[0.75rem]">{c.hint}</span>}
              </button>
            </li>
          ))}
        </ul>
        <div className="px-4 py-2 border-t border-line text-muted text-[0.75rem]">Up and Down to choose · Enter to run · Esc to close</div>
      </div>
    </div>
  );
};
