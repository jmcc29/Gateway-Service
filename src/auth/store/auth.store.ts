// src/auth/store/auth.store.ts
import { InjectionToken } from '@nestjs/common';
import type { PendingAuth, SessionData } from '../interfaces';

export interface AuthStore {
  // Pending (state) —— corto plazo
  setPending(state: string, data: PendingAuth): Promise<void>;
  takePending(state: string): Promise<PendingAuth | undefined>; // consume (remove + return)
  gcPending(ttlMs: number): Promise<void>; // opcional en Redis (usa TTL nativo)

  // Sessions by sid
  setSession(sid: string, data: SessionData): Promise<void>;
  getSession(sid: string): Promise<SessionData | undefined>;
  deleteSession(sid: string): Promise<void>;
  gcSessions(): Promise<void>; // no-op en Redis
}

export const AUTH_STORE = 'AUTH_STORE' as InjectionToken;
