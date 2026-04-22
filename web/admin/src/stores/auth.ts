import { create } from "zustand";
import { jwtDecode } from "jwt-decode";
import type { JwtClaims } from "@/types/api";

const STORAGE_KEY = "openiam.admin.tokens";

interface StoredTokens {
  accessToken: string;
  refreshToken: string;
}

function loadTokens(): StoredTokens | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredTokens;
  } catch {
    return null;
  }
}

function persistTokens(tokens: StoredTokens | null) {
  if (!tokens) {
    localStorage.removeItem(STORAGE_KEY);
    return;
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
}

function decodeClaims(token: string | null): JwtClaims | null {
  if (!token) return null;
  try {
    return jwtDecode<JwtClaims>(token);
  } catch {
    return null;
  }
}

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  claims: JwtClaims | null;
  setTokens: (access: string, refresh: string) => void;
  clear: () => void;
  isAuthenticated: () => boolean;
}

const initialTokens = loadTokens();

export const useAuthStore = create<AuthState>((set, get) => ({
  accessToken: initialTokens?.accessToken ?? null,
  refreshToken: initialTokens?.refreshToken ?? null,
  claims: decodeClaims(initialTokens?.accessToken ?? null),
  setTokens: (access, refresh) => {
    persistTokens({ accessToken: access, refreshToken: refresh });
    set({
      accessToken: access,
      refreshToken: refresh,
      claims: decodeClaims(access),
    });
  },
  clear: () => {
    persistTokens(null);
    set({ accessToken: null, refreshToken: null, claims: null });
  },
  isAuthenticated: () => {
    const { accessToken, claims } = get();
    if (!accessToken) return false;
    if (claims?.exp && claims.exp * 1000 < Date.now() - 5_000) {
      // expired (with 5s skew)
      return false;
    }
    return true;
  },
}));

// Imperative helpers used by the axios interceptor where calling a hook
// is not appropriate.
export function getAccessToken(): string | null {
  return useAuthStore.getState().accessToken;
}

export function getRefreshToken(): string | null {
  return useAuthStore.getState().refreshToken;
}

export function applyRefreshedTokens(access: string, refresh: string) {
  useAuthStore.getState().setTokens(access, refresh);
}

export function clearTokens() {
  useAuthStore.getState().clear();
}
