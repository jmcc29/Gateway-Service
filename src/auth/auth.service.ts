// src/auth/auth.service.ts
import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { URLSearchParams } from 'url';
import { KeycloakEnvs, FrontEnvs } from 'src/config';

const base = KeycloakEnvs.authServerUrl;
const realm = KeycloakEnvs.realm;
const oidcScope = 'openid profile email';

const log = new Logger('AuthService');

/* ===================== Tipos ===================== */

type Permission = { resource: string; scopes?: string[] };

type PendingAuth = {
  codeVerifier: string;
  createdAt: number;
  returnTo: string;
  redirectUri: string;
  clientId: string;
};

type ClientTokenSet = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number; // timestamp ms
  roles?: string[];
};

type SessionData = {
  tokenType: string;
  sub?: string;
  clients: Record<string, ClientTokenSet>;
  permissions?: Permission[];
};

/* ===================== Helpers puros ===================== */

// origin normalizado (sin trailing slash)
function originOf(urlStr: string): string {
  const { origin } = new URL(urlStr);
  return origin.replace(/\/+$/, '');
}

// Deriva y valida redirectUri a partir de returnTo
function deriveRedirectUri(returnTo?: string): string {
  if (!returnTo) throw new Error('returnTo es obligatorio para derivar redirectUri');

  let origin: string;
  try {
    origin = originOf(returnTo); // requiere returnTo absoluto
  } catch {
    throw new Error(`returnTo inválido: ${returnTo}`);
  }

  if (!FrontEnvs.frontendServers.includes(origin)) {
    throw new Error('Origen no permitido');
  }
  // Cada frontend debe exponer /api/auth/callback
  return `${origin}/api/auth/callback`;
}

// Construye la "whitelist" de clientes desde envs (inmutable)
type ClientCfg = { id?: string; secret?: string };
const ALLOWED_CLIENTS: Readonly<Record<string, { secret?: string }>> = (() => {
  const map: Record<string, { secret?: string }> = {};
  const hub = KeycloakEnvs.client?.hubInterface as ClientCfg | undefined;
  const ben = KeycloakEnvs.client?.beneficiaryInterface as ClientCfg | undefined;
  if (hub?.id) map[hub.id] = { secret: hub.secret };
  if (ben?.id) map[ben.id] = { secret: ben.secret };
  return Object.freeze(map);
})();

function ensureClientAllowed(clientId: string) {
  if (!clientId || !ALLOWED_CLIENTS[clientId]) {
    throw new Error(`client_id no permitido: ${clientId}`);
  }
}

// Base64url nativo cuando está disponible; fallback a regex
function toBase64Url(buf: Buffer): string {
  // Node 16+ soporta 'base64url'
  try {
    return buf.toString('base64url');
  } catch {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
}

/* ===================== Almacenamiento (memoria) ===================== */

const pending = new Map<string, PendingAuth>();
const sessions = new Map<string, SessionData>();

/* ===================== Servicio ===================== */

@Injectable()
export class AuthService {
  /* ---------- 1) Construye URL de autorización y guarda PKCE + state ---------- */
  async buildAuthUrl(opts: { returnTo: string; clientId: string }) {
    const { returnTo, clientId } = opts;
    ensureClientAllowed(clientId);

    const state = this.randomId();
    const { verifier, challenge } = this.generatePkce();
    const redirectUri = deriveRedirectUri(returnTo);

    pending.set(state, {
      codeVerifier: verifier,
      createdAt: Date.now(),
      returnTo,
      redirectUri,
      clientId,
    });

    this.gcPending();

    const url = this.buildAuthorizeUrl({
      clientId,
      redirectUri,
      state,
      codeChallenge: challenge,
      scope: oidcScope,
    });

    return { url, state };
  }

  /* ---------- 2) Intercambia code→tokens y crea/actualiza sesión (por client_id) ---------- */
  async exchangeCodeAndCreateSession(params: { code: string; state: string }) {
    const { code, state } = params;
    const stash = pending.get(state);
    if (!stash) throw new Error('State no encontrado o expirado');

    pending.delete(state);

    const clientId = stash.clientId;
    ensureClientAllowed(clientId);
    const clientSecret = ALLOWED_CLIENTS[clientId]?.secret;

    const tokenRes = await this.tokenRequest({
      code,
      codeVerifier: stash.codeVerifier,
      redirectUri: stash.redirectUri,
      client: { id: clientId, secret: clientSecret },
    });

    const now = Date.now();
    const expiresAt = now + (tokenRes.expires_in ?? 300) * 1000;

    const sub = this.peekJwtSub(tokenRes.access_token);
    const roles = this.peekJwtRoles(tokenRes.access_token, clientId);

    const sessionId = this.randomId();
    const session: SessionData = {
      tokenType: tokenRes.token_type ?? 'Bearer',
      sub,
      clients: {
        [clientId]: {
          accessToken: tokenRes.access_token,
          refreshToken: tokenRes.refresh_token,
          idToken: tokenRes.id_token,
          expiresAt,
          roles,
        },
      },
    };

    sessions.set(sessionId, session);
    this.gcSessions();

    return {
      sessionId,
      returnTo: stash.returnTo,
    };
  }

  /* ---------- 3) Logout: global (todos los client_id de la sesión) ---------- */
  async logout(sessionId?: string) {
    if (!sessionId) return;

    const session = sessions.get(sessionId);
    if (!session) return;

    try {
      for (const [clientId, set] of Object.entries(session.clients ?? {})) {
        const secret = ALLOWED_CLIENTS[clientId]?.secret;
        if (set.refreshToken) {
          await this.keycloakLogout(set.refreshToken, { id: clientId, secret });
        }
      }
    } catch (e) {
      const msg = (e as any)?.message ?? e;
      log.warn(`Keycloak logout failed: ${msg as string}`);
    }

    sessions.delete(sessionId);
  }

  /* ===================== Helpers OIDC ===================== */

  private authorizeEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`;
  }

  private tokenEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`;
  }

  private logoutEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/logout`;
  }

  private buildAuthorizeUrl(input: {
    clientId: string;
    redirectUri: string;
    state: string;
    codeChallenge: string;
    scope: string;
  }) {
    const url = new URL(this.authorizeEndpoint());
    url.searchParams.set('client_id', input.clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', input.scope);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('state', input.state);
    url.searchParams.set('code_challenge', input.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  private async tokenRequest(opts: {
    code: string;
    codeVerifier: string;
    redirectUri: string;
    client: { id: string; secret?: string };
  }) {
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', opts.client.id);
    if (opts.client.secret) body.set('client_secret', opts.client.secret);
    body.set('code', opts.code);
    body.set('code_verifier', opts.codeVerifier);
    body.set('redirect_uri', opts.redirectUri);

    const { data } = await axios.post(this.tokenEndpoint(), body, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 10_000,
    });

    return data as {
      access_token: string;
      refresh_token?: string;
      id_token?: string;
      expires_in: number;
      scope?: string;
      token_type?: string;
      session_state?: string;
    };
  }

  private async keycloakLogout(
    refreshToken: string,
    client: { id: string; secret?: string },
  ) {
    if (!refreshToken) return;

    const body = new URLSearchParams();
    body.set('client_id', client.id);
    if (client.secret) body.set('client_secret', client.secret);
    body.set('refresh_token', refreshToken);

    await axios.post(this.logoutEndpoint(), body, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 8_000,
    });
  }

  /* ===================== PKCE & misc utils ===================== */

  private generatePkce() {
    const verifier = toBase64Url(crypto.randomBytes(32)); // 43-128 chars
    const challenge = toBase64Url(crypto.createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
  }

  private randomId() {
    // UUID es válido, pero mantenemos base64url para no alterar formato externo
    return toBase64Url(crypto.randomBytes(24));
  }

  private gcPending() {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [k, v] of pending) if (v.createdAt < cutoff) pending.delete(k);
  }

  private gcSessions() {
    const now = Date.now();
    for (const [k, v] of sessions) {
      if (!v?.clients || Object.keys(v.clients).length === 0) {
        sessions.delete(k);
        continue;
      }
      for (const [cid, set] of Object.entries(v.clients)) {
        if (set.expiresAt < now && !set.refreshToken) {
          delete v.clients[cid];
        }
      }
    }
  }

  private peekJwtSub(jwt?: string) {
    try {
      if (!jwt) return undefined;
      const [, payload] = jwt.split('.');
      const json = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
      return json.sub as string | undefined;
    } catch {
      return undefined;
    }
  }

  private peekJwtRoles(jwt: string | undefined, clientId: string) {
    try {
      if (!jwt) return undefined;
      const [, payload] = jwt.split('.');
      const json = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
      const realmRoles: string[] = json?.realm_access?.roles ?? [];
      const clientRoles: string[] = json?.resource_access?.[clientId]?.roles ?? [];
      return [...new Set([...realmRoles, ...clientRoles])];
    } catch {
      return undefined;
    }
  }

  /* ---------- API pública auxiliar ---------- */

  // Devuelve datos de sesión específicos para un client_id
  getSessionData(sessionId: string, clientId: string) {
    const session = sessions.get(sessionId);
    if (!session) throw new Error('Sesión inválida o expirada');

    const set = session.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');

    return {
      accessToken: set.accessToken,
      expiresIn: set.expiresAt, // se mantiene el mismo contrato (timestamp ms)
      sub: session.sub,
      roles: set.roles,
    };
  }
}
