// src/auth/auth.service.ts
import { Inject, Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { URLSearchParams } from 'url';
import { KeycloakEnvs } from 'src/config';
import type { AuthStore } from './store/auth.store';
import { AUTH_STORE } from './store/auth.store';
import type { SessionData } from './interfaces';
import { KeycloakClientService } from 'src/keycloak/keycloak-client.service';

const base = KeycloakEnvs.authServerUrl;
const realm = KeycloakEnvs.realm;
const oidcScope = 'openid profile email';
const log = new Logger('AuthService');

/* ===================== Tipos y helpers ===================== */
type OidcClient = { id: string; secret?: string; origins: string[] };

function toBase64Url(buf: Buffer): string {
  try {
    return buf.toString('base64url');
  } catch {
    return buf
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }
}

function normalizeOrigin(o: string) {
  try {
    const { origin } = new URL(o);
    return origin.replace(/\/+$/, '');
  } catch {
    return o.replace(/\/+$/, '');
  }
}

function originOf(urlStr: string): string {
  const { origin } = new URL(urlStr);
  return normalizeOrigin(origin);
}

function deriveRedirectUriFromOrigin(origin: string) {
  return `${normalizeOrigin(origin)}/api/auth/callback`;
}

/* ===================== Registro dinámico de clientes ===================== */
/** KeycloakEnvs.client debe ser OidcClient[] (de tu envs.ts) */
const CLIENTS_ARR: OidcClient[] = (Array.isArray(KeycloakEnvs.client) ? KeycloakEnvs.client : []).map(
  (c) => ({ ...c, origins: (c.origins ?? []).map(normalizeOrigin) }),
);

/** Acceso O(1) por id */
const CLIENTS_BY_ID = new Map<string, OidcClient>(CLIENTS_ARR.map((c) => [c.id, c]));

/** Mapa origin -> clientId (para deducir cliente por returnTo/origin) */
const ORIGIN_TO_CLIENT_ID = (() => {
  const map = new Map<string, string>();
  for (const c of CLIENTS_ARR) {
    for (const o of c.origins) {
      const prev = map.get(o);
      if (prev && prev !== c.id) {
        log.warn(`⚠️ Origin ${o} está asociado a múltiples client_ids: ${prev}, ${c.id}`);
      }
      map.set(o, c.id);
    }
  }
  return map;
})();

function ensureClientAllowed(clientId: string) {
  if (!clientId || !CLIENTS_BY_ID.has(clientId)) {
    throw new Error(`client_id no permitido: ${clientId}`);
  }
}

function resolveClientByOrigin(origin: string): OidcClient {
  const id = ORIGIN_TO_CLIENT_ID.get(normalizeOrigin(origin));
  if (!id) throw new Error(`Origen no permitido: ${origin}`);
  return CLIENTS_BY_ID.get(id)!;
}

function ensureOriginBelongsToClient(origin: string, client: OidcClient) {
  const norm = normalizeOrigin(origin);
  if (!client.origins.includes(norm)) {
    throw new Error(`El client_id "${client.id}" no permite el origin ${norm}`);
  }
}

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_STORE) private readonly store: AuthStore,
    private readonly kc: KeycloakClientService, // Servicio centralizado de Keycloak
  ) {}

  // 1) Build URL de autorización y guarda pending (state→PKCE/returnTo/redirectUri/clientId)
  //    clientId es OPCIONAL: si no lo envías, se deduce por el origin de returnTo.
  async buildAuthUrl(opts: { returnTo: string; clientId?: string }) {
    const { returnTo } = opts;
    const origin = originOf(returnTo);

    // Si pasan clientId, validar que pertenezca a ese origin; si no, deducir por origin
    let client: OidcClient;
    if (opts.clientId) {
      ensureClientAllowed(opts.clientId);
      client = CLIENTS_BY_ID.get(opts.clientId)!;
      ensureOriginBelongsToClient(origin, client);
    } else {
      client = resolveClientByOrigin(origin);
    }
    const clientId = client.id;

    const state = this.randomId();
    const { verifier, challenge } = this.generatePkce();
    const redirectUri = deriveRedirectUriFromOrigin(origin);

    await this.store.setPending(state, {
      codeVerifier: verifier,
      createdAt: Date.now(),
      returnTo,
      redirectUri,
      clientId,
    });
    await this.store.gcPending(5 * 60 * 1000);

    const url = new URL(this.authorizeEndpoint());
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', oidcScope);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    // 🔎 LOGS
    log.log(
      `PENDING SET state=${state} clientId=${clientId} redirectUri=${redirectUri} returnTo=${returnTo}`,
    );
    log.log(`AUTH URL -> ${url.toString()}`);

    return { url: url.toString(), state };
  }

  // 2) Intercambia code→tokens y crea/actualiza sesión por client_id
  async exchangeCodeAndCreateSession(params: { code: string; state: string; sidCookie?: string }) {
    const { code, state, sidCookie } = params;

    // 🔎 LOGS
    log.log(`EXCHANGE ATTEMPT state=${state} sidCookie=${sidCookie ?? '<none>'}`);

    const stash = await this.store.takePending(state);
    if (!stash) {
      log.error(`PENDING MISS state=${state} (posible GC, multi-login o proceso distinto)`);
      throw new Error('State no encontrado o expirado');
    }

    // 🔎 LOGS
    log.log(
      `PENDING HIT state=${state} clientId=${stash.clientId} redirectUri=${stash.redirectUri} returnTo=${stash.returnTo}`,
    );

    const clientId = stash.clientId;
    ensureClientAllowed(clientId);
    const client = CLIENTS_BY_ID.get(clientId)!;

    let tokenRes: {
      access_token: string;
      refresh_token?: string;
      id_token?: string;
      expires_in: number;
      scope?: string;
      token_type?: string;
      session_state?: string;
    };

    try {
      tokenRes = await this.tokenRequest({
        code,
        codeVerifier: stash.codeVerifier,
        redirectUri: stash.redirectUri,
        client: { id: client.id, secret: client.secret },
      });
    } catch (e: any) {
      log.error(`TOKEN REQUEST FAILED clientId=${clientId} state=${state} msg=${e?.message ?? e}`);
      throw e;
    }

    const now = Date.now();
    const expiresAt = now + (tokenRes.expires_in ?? 300) * 1000;
    const sub = this.peekJwtSub(tokenRes.access_token);
    const roles = this.peekJwtRoles(tokenRes.access_token, clientId);

    // 🔎 LOGS
    log.log(
      `TOKEN OK clientId=${clientId} sub=${sub ?? '<unknown>'} expiresInSec=${tokenRes.expires_in} hasRefresh=${!!tokenRes.refresh_token}`,
    );

    // 🚩 Si ya venía un sid (multi-cliente en misma sesión), reutilízalo
    const sessionId = sidCookie ?? this.randomId();
    const existing =
      (await this.store.getSession(sessionId)) ??
      ({
        tokenType: tokenRes.token_type ?? 'Bearer',
        sub,
        clients: {},
      } as SessionData);

    const before = Object.keys(existing.clients ?? {});

    existing.tokenType = tokenRes.token_type ?? existing.tokenType ?? 'Bearer';
    existing.sub = existing.sub ?? sub;
    existing.clients[clientId] = {
      accessToken: tokenRes.access_token,
      refreshToken: tokenRes.refresh_token,
      idToken: tokenRes.id_token,
      expiresAt,
      roles,
    };

    await this.store.setSession(sessionId, existing);
    await this.store.gcSessions();

    const after = Object.keys(existing.clients ?? {});
    // 🔎 LOGS
    log.log(
      `SESSION UPSERT sid=${sessionId} clientsBefore=[${before.join(',')}] clientsAfter=[${after.join(',')}]`,
    );

    return { sessionId, returnTo: stash.returnTo };
  }

  // 3) Logout global (revoca refresh_token por cada client_id si existe)
  async logout(sessionId?: string) {
    if (!sessionId) return;
    const session = await this.store.getSession(sessionId);
    if (!session) return;

    try {
      for (const [clientId, set] of Object.entries(session.clients ?? {})) {
        const client = CLIENTS_BY_ID.get(clientId);
        if (set.refreshToken && client) {
          await this.keycloakLogout(set.refreshToken, { id: client.id, secret: client.secret });
        }
      }
    } catch (e: any) {
      log.warn(`Keycloak logout failed: ${e?.message ?? e}`);
    }

    await this.store.deleteSession(sessionId);
  }

  // ====== Aux OIDC (axios) ======
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

  private async keycloakLogout(refreshToken: string, client: { id: string; secret?: string }) {
    const body = new URLSearchParams();
    body.set('client_id', client.id);
    if (client.secret) body.set('client_secret', client.secret);
    body.set('refresh_token', refreshToken);

    await axios.post(this.logoutEndpoint(), body, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 8_000,
    });
  }

  // ====== PKCE y utils ======
  private generatePkce() {
    const verifier = toBase64Url(crypto.randomBytes(32));
    const challenge = toBase64Url(crypto.createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
  }
  private randomId() {
    return toBase64Url(crypto.randomBytes(24));
  }

  private parseJwt(jwt?: string): any | undefined {
    try {
      if (!jwt) return;
      const [, p] = jwt.split('.');
      return JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
    } catch {
      return;
    }
  }

  private peekJwtSub(jwt?: string) {
    try {
      if (!jwt) return;
      const [, p] = jwt.split('.');
      return JSON.parse(Buffer.from(p, 'base64').toString('utf8'))?.sub;
    } catch {
      return;
    }
  }

  private peekJwtRoles(jwt: string | undefined, clientId: string) {
    try {
      if (!jwt) return;
      const [, p] = jwt.split('.');
      const j = JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
      const realm: string[] = j?.realm_access?.roles ?? [];
      const client: string[] = j?.resource_access?.[clientId]?.roles ?? [];
      return [...new Set([...realm, ...client])];
    } catch {
      return;
    }
  }

  // ====== API para otros módulos (manteniendo nombres) ======
  async getSessionData(sessionId: string, clientId: string) {
    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');
    return { accessToken: set.accessToken, expiresIn: set.expiresAt, sub: s.sub, roles: set.roles };
  }

  /** Verificación criptográfica del access_token guardado (issuer + azp∈permitidos) */
  async verifySessionAccessToken(sessionId: string, clientId: string) {
    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set?.accessToken) throw new Error('No hay access_token para el client_id');
    const allowed = Array.from(CLIENTS_BY_ID.keys()); // ahora dinámico
    return this.kc.verifyAccessToken(set.accessToken, { allowedClients: allowed });
  }

  private peekUserProfile(jwt?: string) {
    const j = this.parseJwt(jwt);
    if (!j) return;
    return {
      sub: j.sub as string | undefined,
      username: j.preferred_username as string | undefined,
      name: j.name as string | undefined,
      given_name: j.given_name as string | undefined,
      family_name: j.family_name as string | undefined,
      email: j.email as string | undefined,
      email_verified: j.email_verified as boolean | undefined,
    };
  }

  // ====== UMA / Entitlements ======
  /**
   * Devuelve permisos normalizados (array de strings) usando SIEMPRE response_mode=permissions.
   * Se ignora cualquier "decision" que externamente intenten pasar.
   */
  private async fetchUmaPermissions(accessToken: string, audience: string) {
    const data = await this.kc.umaRequest(accessToken, {
      audience,
      responseMode: 'permissions',
    });

    const normalize = (perm: any) => {
      const res = perm.rsname ?? perm.rsid ?? 'unknown';
      const scopes: string[] = Array.isArray(perm.scopes) ? perm.scopes : [];
      if (!scopes.length) return [`${res}:*`];
      return scopes.map((s) => `${res}:${s}`);
    };

    if (Array.isArray(data)) {
      const flat = data.flatMap(normalize);
      return Array.from(new Set(flat)); // únicos
    }
    return [];
  }

  /**
   * Nueva API: decisión booleana para un permission específico ("resource#scope"),
   * usando response_mode=decision.
   */
  async evaluatePermission(params: {
    sessionId: string;
    clientId: string;
    audience: string; // resource server/cliente API en Keycloak
    resource: string; // nombre del recurso (rsname)
    scope: string; // scope de UMA
  }): Promise<boolean> {
    const { sessionId, clientId, audience, resource, scope } = params;

    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set?.accessToken) throw new Error('No hay access_token para el client_id');

    try {
      const data = await this.kc.umaRequest(set.accessToken, {
        audience,
        responseMode: 'decision',
        permission: `${resource}#${scope}`,
      });
      return !!data?.result;
    } catch (e: any) {
      log.warn(
        `UMA decision error audience=${audience} perm=${resource}#${scope}: ${e?.message ?? e}`,
      );
      return false;
    }
  }

  // ====== Facade para /auth/me ======
  async getProfile(params: {
    sessionId: string;
    clientId: string;
    audience?: string;
  }) {
    const { sessionId, clientId, audience } = params;

    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');

    const set = s.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');

    const profile = this.peekUserProfile(set.accessToken);
    const roles = set.roles ?? this.peekJwtRoles(set.accessToken, clientId) ?? [];

    let permissions: string[] | undefined;
    if (audience) {
      try {
        permissions = await this.fetchUmaPermissions(set.accessToken, audience); // siempre permissions
      } catch (e: any) {
        log.warn(`UMA permissions error audience=${audience}: ${e?.message ?? e}`);
      }
    }

    return {
      sub: s.sub ?? profile?.sub,
      username: profile?.username,
      name: profile?.name,
      given_name: profile?.given_name,
      family_name: profile?.family_name,
      email: profile?.email,
      email_verified: profile?.email_verified,
      roles,
      permissions, // undefined si no se pidió audience
      expiresAt: set.expiresAt,
      tokenType: s.tokenType,
      clientId,
    };
  }

  // ====== Endpoint específico sólo-permisos (siempre permissions) ======
  async getPermissions(params: {
    sessionId: string;
    clientId: string;
    audience: string;
  }) {
    const { sessionId, clientId, audience } = params;
    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');

    return this.fetchUmaPermissions(set.accessToken, audience); // siempre permissions
  }
}
