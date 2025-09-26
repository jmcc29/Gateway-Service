// src/auth/store/memory.store.ts
import { Injectable } from '@nestjs/common';
import type { AuthStore } from './auth.store';
import type { PendingAuth, SessionData } from '../interfaces';

@Injectable()
export class MemoryAuthStore implements AuthStore {
  private pending = new Map<string, PendingAuth>();   // state -> PendingAuth
  private sessions = new Map<string, SessionData>();  // sid -> SessionData

  async setPending(state: string, data: PendingAuth): Promise<void> {
    this.pending.set(state, data);
  }

  async takePending(state: string): Promise<PendingAuth | undefined> {
    const data = this.pending.get(state);
    if (data) this.pending.delete(state);
    return data;
  }

  async gcPending(ttlMs: number): Promise<void> {
    const cutoff = Date.now() - ttlMs;
    for (const [k, v] of this.pending) if (v.createdAt < cutoff) this.pending.delete(k);
  }

  async setSession(sid: string, data: SessionData): Promise<void> {
    this.sessions.set(sid, data);
  }

  async getSession(sid: string): Promise<SessionData | undefined> {
    return this.sessions.get(sid);
  }

  async deleteSession(sid: string): Promise<void> {
    this.sessions.delete(sid);
  }

  async gcSessions(): Promise<void> {
    const now = Date.now();
    for (const [sid, s] of this.sessions) {
      if (!s?.clients || Object.keys(s.clients).length === 0) {
        this.sessions.delete(sid);
        continue;
      }
      for (const [cid, set] of Object.entries(s.clients)) {
        if (set.expiresAt < now && !set.refreshToken) delete s.clients[cid];
      }
    }
  }
}
