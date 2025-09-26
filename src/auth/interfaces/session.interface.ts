import { Permission } from './permission.interface';
export interface ClientTokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  roles?: string[];
}

export interface PendingAuth {
  codeVerifier: string;
  createdAt: number;
  redirectUri: string;
  clientId: string;
  returnTo: string;
}

export interface SessionData {
  tokenType: string;
  sub?: string;
  clients: Record<string, ClientTokenSet>;
  permissions?: Permission[];
}
