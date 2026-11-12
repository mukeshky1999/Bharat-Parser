import { create } from 'zustand';

export type DialogName = 'ADD_EXTRACTION' | 'SETTINGS' | 'PALETTE' | null;

interface UiState {
  dialog: DialogName;
  /** Goes up whenever a tag is applied or removed, so tables showing tag pills read them again. */
  tagsVersion: number;
  bumpTags: () => void;
  open: (d: Exclude<DialogName, null>) => void;
  close: () => void;
}

/** Which dialog is open. Only one at a time; Esc closes it. */
export const useUi = create<UiState>((set) => ({
  dialog: null,
  tagsVersion: 0,
  bumpTags: () => set((s) => ({ tagsVersion: s.tagsVersion + 1 })),
  open: (d) => set({ dialog: d }),
  close: () => set({ dialog: null }),
}));
