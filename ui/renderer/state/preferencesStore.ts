import { create } from 'zustand';

export type ThemeName = 'light' | 'dim' | 'contrast';
export type Density = 'compact' | 'comfortable';
export type TimeZoneMode = 'IST' | 'UTC';

export interface Preferences {
  theme: ThemeName;
  density: Density;
  /** 0.9 .. 1.3 multiplier on the root font size (everything is sized in rem) */
  fontScale: number;
  timeZone: TimeZoneMode;
  navWidth: number;
  cardWidth: number;
  navCollapsed: boolean;
  cardOpen: boolean;
  /** 20-20-20 reminder: every 20 minutes, look 20 feet away for 20 seconds. Off unless the examiner turns it on. */
  breakReminder: boolean;
  /** Columns the examiner hid, per table (a display choice only: exports keep every column). */
  hiddenColumns: Record<string, string[]>;
}

export const DEFAULT_PREFERENCES: Preferences = {
  theme: 'light',
  density: 'comfortable',
  fontScale: 1,
  timeZone: 'IST',
  navWidth: 264,
  cardWidth: 372,
  navCollapsed: false,
  cardOpen: true,
  breakReminder: false,
  hiddenColumns: {},
};

// v2: light became the default theme; v1 stored 'dim' as the old default for everyone.
const STORAGE_KEY = 'bharat.preferences.v2';
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** Accepts anything read from storage and returns a valid Preferences object (never throws). */
export function sanitizePreferences(raw: unknown): Preferences {
  const out: Preferences = { ...DEFAULT_PREFERENCES };
  if (!raw || typeof raw !== 'object') return out;
  const r = raw as Record<string, unknown>;
  if (r.theme === 'dim' || r.theme === 'light' || r.theme === 'contrast') out.theme = r.theme;
  if (r.density === 'compact' || r.density === 'comfortable') out.density = r.density;
  if (typeof r.fontScale === 'number' && Number.isFinite(r.fontScale)) out.fontScale = clamp(r.fontScale, 0.9, 1.3);
  if (r.timeZone === 'IST' || r.timeZone === 'UTC') out.timeZone = r.timeZone;
  if (typeof r.navWidth === 'number' && Number.isFinite(r.navWidth)) out.navWidth = clamp(r.navWidth, 180, 420);
  if (typeof r.cardWidth === 'number' && Number.isFinite(r.cardWidth)) out.cardWidth = clamp(r.cardWidth, 300, 640);
  if (typeof r.navCollapsed === 'boolean') out.navCollapsed = r.navCollapsed;
  if (typeof r.cardOpen === 'boolean') out.cardOpen = r.cardOpen;
  if (typeof r.breakReminder === 'boolean') out.breakReminder = r.breakReminder;
  if (r.hiddenColumns && typeof r.hiddenColumns === 'object' && !Array.isArray(r.hiddenColumns)) {
    const hc: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(r.hiddenColumns as Record<string, unknown>).slice(0, 20)) {
      if (Array.isArray(v)) hc[k.slice(0, 40)] = v.filter((x): x is string => typeof x === 'string').slice(0, 30).map((x) => x.slice(0, 40));
    }
    out.hiddenColumns = hc;
  }
  return out;
}

function load(): Preferences {
  try {
    const s = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
    return sanitizePreferences(s ? JSON.parse(s) : null);
  } catch {
    return { ...DEFAULT_PREFERENCES }; // storage blocked or corrupt: defaults, never a crash
  }
}

function save(p: Preferences): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(STORAGE_KEY, JSON.stringify(p));
  } catch {
    // preferences are a convenience: a failed save must not break the session
  }
}

/** Writes the preferences to the document so the stylesheet can react. */
export function applyPreferences(p: Preferences): void {
  if (typeof document === 'undefined') return;
  const el = document.documentElement;
  el.setAttribute('data-theme', p.theme);
  el.setAttribute('data-density', p.density);
  el.style.setProperty('--font-scale', String(p.fontScale));
}

interface PreferencesState extends Preferences {
  set: (patch: Partial<Preferences>) => void;
  reset: () => void;
}

function pick(s: Preferences): Preferences {
  return {
    theme: s.theme, density: s.density, fontScale: s.fontScale, timeZone: s.timeZone, navWidth: s.navWidth,
    cardWidth: s.cardWidth, navCollapsed: s.navCollapsed, cardOpen: s.cardOpen, breakReminder: s.breakReminder, hiddenColumns: s.hiddenColumns,
  };
}

export const usePreferences = create<PreferencesState>((set, get) => ({
  ...load(),
  set: (patch) => {
    const next = sanitizePreferences({ ...pick(get()), ...patch });
    save(next);
    applyPreferences(next);
    set(next);
  },
  reset: () => {
    save(DEFAULT_PREFERENCES);
    applyPreferences(DEFAULT_PREFERENCES);
    set({ ...DEFAULT_PREFERENCES });
  },
}));
