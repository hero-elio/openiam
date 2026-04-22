import { create } from "zustand";

interface UIState {
  collapsed: boolean;
  toggleCollapsed: () => void;
  setCollapsed: (v: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  collapsed: false,
  toggleCollapsed: () => set((s) => ({ collapsed: !s.collapsed })),
  setCollapsed: (v) => set({ collapsed: v }),
}));
