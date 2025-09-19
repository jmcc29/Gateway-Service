// src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { URLSearchParams } from 'url';
import { KeycloakEnvs, FrontEnvs } from 'src/config';

const base = KeycloakEnvs.authServerUrl;
const realm = KeycloakEnvs.realm;
const oidcScope = 'openid profile email';

// ========== Tipos ==========
type Permission = { resource: string; scopes?: string[] };

type PendingAuth = {
  codeVerifier: string;
  createdAt: number;
  returnTo: string;
  redirectUri: string;
  clientId: string; // <- ahora guardamos el client_id real
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
  // Tokens por client_id real
  clients: Record<string, ClientTokenSet>;
  permissions?: Permission[];
};

// ========== Util helpers ==========

// obtiene origin normalizado
function originOf(urlStr: string): string {
  const { origin } = new URL(urlStr);
  return origin.replace(/\/+$/, '');
}

// Deriva y valida el redirectUri a partir del returnTo
function deriveRedirectUri(returnTo?: string): string {
  if (!returnTo) {
    throw new Error('returnTo es obligatorio para derivar redirectUri');
  }
  let origin: string;
  try {
    origin = originOf(returnTo); // requiere returnTo absoluto
  } catch {
    throw new Error(`returnTo inválido: ${returnTo}`);
  }
  if (!FrontEnvs.frontendServers.includes(origin)) {
    throw new Error(`Origen no permitido`);
  }
  // Cada frontend debe exponer /api/auth/callback
  return `${origin}/api/auth/callback`;
}

// Construye la "whitelist" de clientes desde envs
type ClientCfg = { id?: string; secret?: string };
const ALLOWED_CLIENTS: Record<string, { secret?: string }> = (() => {
  const map: Record<string, { secret?: string }> = {};
  const hub = KeycloakEnvs.client?.hubInterface;
  const ben = KeycloakEnvs.client?.beneficiaryInterface;
  if (hub?.id) map[hub.id] = { secret: hub.secret };
  if (ben?.id) map[ben.id] = { secret: ben.secret };
  return map;
})();

function ensureClientAllowed(clientId: string) {
  if (!clientId || !ALLOWED_CLIENTS[clientId]) {
    throw new Error(`client_id no permitido: ${clientId}`);
  }
}

//Almacenamiento en memoria (cambiar por Redis en prod)
const pending = new Map<string, PendingAuth>();
const sessions = new Map<string, SessionData>();

@Injectable()
export class AuthService {
  // 1) Construye URL de autorización y guarda PKCE + state
  //    Ahora recibe el client_id real desde el frontend
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
      clientId, // guardamos qué client_id inició el flujo
    });

    // Limpieza de expirados (simple)
    this.gcPending();

    const authorizeUrl = this.authorizeEndpoint();
    const url =
      `${authorizeUrl}` +
      `?client_id=${encodeURIComponent(clientId)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent(oidcScope)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&state=${encodeURIComponent(state)}` +
      `&code_challenge=${encodeURIComponent(challenge)}` +
      `&code_challenge_method=S256`;

    return { url, state };
  }

  // 2) Intercambia code→tokens y crea/actualiza sesión (por client_id)
  async exchangeCodeAndCreateSession(params: { code: string; state: string }) {
    const { code, state } = params;
    const stash = pending.get(state);
    if (!stash) {
      throw new Error('State no encontrado o expirado');
    }
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

    // (Opcional) decodificar JWT para claims (sub, roles)
    const sub = this.peekJwtSub(tokenRes.access_token);
    const roles = this.peekJwtRoles(tokenRes.access_token, clientId);

    // Si ya existía una sesión, puedes reusar su sid; aquí creamos uno nuevo siempre
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

  // 3) Logout: global (todos los client_id de la sesión)
  async logout(sessionId?: string) {
    if (!sessionId) return; // nada que hacer

    const session = sessions.get(sessionId);
    if (!session) return; // nada que hacer
    try {
      // cierra en Keycloak cada refresh_token de cada cliente
      for (const [clientId, set] of Object.entries(session.clients ?? {})) {
        const secret = ALLOWED_CLIENTS[clientId]?.secret;
        if (set.refreshToken) {
          await this.keycloakLogout(set.refreshToken, { id: clientId, secret });
        }
      }
    } catch (e) {
      console.warn('Keycloak logout failed:', (e as any)?.message ?? e);
    }
    sessions.delete(sessionId);
  }

  // ========== Helpers OIDC ==========

  private authorizeEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`;
  }

  private tokenEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`;
  }

  private logoutEndpoint() {
    return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/logout`;
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
      timeout: 10000,
    });

    // data: { access_token, refresh_token, id_token, expires_in, ... }
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
      timeout: 8000,
    });
  }

  // ========== PKCE utils ==========

  private generatePkce() {
    const verifier = this.base64url(crypto.randomBytes(32)); // 43-128 chars
    const challenge = this.base64url(crypto.createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
  }

  private base64url(buf: Buffer) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  // ========== Misc utils ==========

  private randomId() {
    return this.base64url(crypto.randomBytes(24));
  }

  private gcPending() {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [k, v] of pending) if (v.createdAt < cutoff) pending.delete(k);
  }

  private gcSessions() {
    const now = Date.now();
    for (const [k, v] of sessions) {
      // si la sesión no tiene ningún token vigente, puedes limpiarla;
      // aquí se deja simple y no se elimina por expiración de access token
      // (el refresh puede seguir vivo). Si quieres, agrega lógica extra.
      if (!v?.clients || Object.keys(v.clients).length === 0) {
        sessions.delete(k);
      } else {
        // opcional: limpiar client entries expiradas
        for (const [cid, set] of Object.entries(v.clients)) {
          if (set.expiresAt < now && !set.refreshToken) {
            delete v.clients[cid];
          }
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
      // Realm roles: json.realm_access.roles
      // Client roles: json.resource_access[clientId]?.roles
      const realmRoles: string[] = json?.realm_access?.roles ?? [];
      const clientRoles: string[] = json?.resource_access?.[clientId]?.roles ?? [];
      return [...new Set([...realmRoles, ...clientRoles])];
    } catch {
      return undefined;
    }
  }

  // Devuelve datos de sesión específicos para un client_id
  getSessionData(sessionId: string, clientId: string) {
    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Sesión inválida o expirada');
    }
    const set = session.clients?.[clientId];
    if (!set) {
      throw new Error(`No hay tokens para el client_id solicitado`);
    }
    return {
      accessToken: set.accessToken,
      expiresIn: set.expiresAt,
      sub: session.sub,
      roles: set.roles,
    };
  }
}
