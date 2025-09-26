// src/auth/auth.service.ts
import { Inject, Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { URLSearchParams } from 'url';
import { KeycloakEnvs, FrontEnvs } from 'src/config';
import type { AuthStore } from './store/auth.store';
import { AUTH_STORE } from './store/auth.store';
import type { SessionData } from './interfaces';

const base = KeycloakEnvs.authServerUrl;
const realm = KeycloakEnvs.realm;
const oidcScope = 'openid profile email';
const log = new Logger('AuthService');

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
  if (!clientId || !ALLOWED_CLIENTS[clientId]) throw new Error(`client_id no permitido: ${clientId}`);
}
function toBase64Url(buf: Buffer): string {
  try { return buf.toString('base64url'); }
  catch {
    return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  }
}
function originOf(urlStr: string): string {
  const { origin } = new URL(urlStr);
  return origin.replace(/\/+$/, '');
}
function deriveRedirectUri(returnTo?: string): string {
  if (!returnTo) throw new Error('returnTo es obligatorio para derivar redirectUri');
  let origin: string;
  try { origin = originOf(returnTo); } catch { throw new Error(`returnTo inválido: ${returnTo}`); }
  if (!FrontEnvs.frontendServers.includes(origin)) throw new Error('Origen no permitido');
  return `${origin}/api/auth/callback`;
}

@Injectable()
export class AuthService {
  constructor(@Inject(AUTH_STORE) private readonly store: AuthStore) {}
  
  // 1) Build URL de autorización y guarda pending (state→PKCE/returnTo/redirectUri/clientId)
  async buildAuthUrl(opts: { returnTo: string; clientId: string }) {
    const { returnTo, clientId } = opts;
    ensureClientAllowed(clientId);

    const state = this.randomId();
    const { verifier, challenge } = this.generatePkce();
    const redirectUri = deriveRedirectUri(returnTo);

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
    const clientSecret = ALLOWED_CLIENTS[clientId]?.secret;

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
        client: { id: clientId, secret: clientSecret },
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
        const secret = ALLOWED_CLIENTS[clientId]?.secret;
        if (set.refreshToken) {
          await this.keycloakLogout(set.refreshToken, { id: clientId, secret });
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
  private randomId() { return toBase64Url(crypto.randomBytes(24)); }

  private peekJwtSub(jwt?: string) {
    try { if (!jwt) return; const [, p] = jwt.split('.'); return JSON.parse(Buffer.from(p,'base64').toString('utf8'))?.sub; }
    catch { return; }
  }
  private peekJwtRoles(jwt: string | undefined, clientId: string) {
    try {
      if (!jwt) return;
      const [, p] = jwt.split('.');
      const j = JSON.parse(Buffer.from(p,'base64').toString('utf8'));
      const realm: string[] = j?.realm_access?.roles ?? [];
      const client: string[] = j?.resource_access?.[clientId]?.roles ?? [];
      return [...new Set([...realm, ...client])];
    } catch { return; }
  }

  // ====== API para otros módulos ======
  async getSessionData(sessionId: string, clientId: string) {
    const s = await this.store.getSession(sessionId);
    if (!s) throw new Error('Sesión inválida o expirada');
    const set = s.clients?.[clientId];
    if (!set) throw new Error('No hay tokens para el client_id solicitado');
    return { accessToken: set.accessToken, expiresIn: set.expiresAt, sub: s.sub, roles: set.roles };
  }
}
