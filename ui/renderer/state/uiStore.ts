import { create } from 'zustand';

export type DialogName = 'ADD_EXTRACTION' | 'SEC230' | 'NCRP' | 'SETTINGS' | 'PALETTE' | null;

interface UiState {
  dialog: DialogName;
  open: (d: Exclude<DialogName, null>) => void;
  close: () => void;
}

/** Which dialog is open. Only one at a time; Esc closes it. (Section 63 keeps its own flag in the workbench store.) */
export const useUi = create<UiState>((set) => ({
  dialog: null,
  open: (d) => set({ dialog: d }),
  close: () => set({ dialog: null }),
}));
