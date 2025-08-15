import { Injectable } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { URLSearchParams } from 'url';
import { KeycloakEnvs, PortEnvs } from 'src/config';

const base=KeycloakEnvs.authServerUrl
const realm=KeycloakEnvs.realm
const clientId=KeycloakEnvs.clientId
const clientSecret=KeycloakEnvs.secret
const redirectUri=`http://localhost:${PortEnvs.port}/api/auth/callback`
const oidcScope='openid profile email'

type PendingAuth = {
    codeVerifier: string;
    createdAt: number;
    returnTo: string;
}

type SessionData = {
    accessToken: string;
    refreshToken: string;
    idToken: string;
    expiresIn: number;
    tokenType: string;
    sub?: string;
    roles?: string[];
}

//Almacenamineto en memorio (cambiar por Redis en prod)
const pending = new Map<string, PendingAuth>();
const sessions = new Map<string, SessionData>();

@Injectable()
export class AuthService {
    // 1) Construye URL de autorización y guarda PKCE + state
  async buildAuthUrl(opts?: { returnTo?: string }) {
    const state = this.randomId();
    const { verifier, challenge } = this.generatePkce();

    pending.set(state, {
      codeVerifier: verifier,
      createdAt: Date.now(),
      returnTo: opts?.returnTo,
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

  // 2) Intercambia code→tokens y crea sesión
  async exchangeCodeAndCreateSession(params: { code: string; state: string }) {
    const { code, state } = params;
    const stash = pending.get(state);
    if (!stash) {
      throw new Error('State no encontrado o expirado');
    }
    pending.delete(state);

    const tokenRes = await this.tokenRequest({
      code,
      codeVerifier: stash.codeVerifier,
    });

    const now = Date.now();
    const expiresAt = now + (tokenRes.expires_in ?? 300) * 1000;

    // (Opcional) decodificar JWT para claims (sub, roles)
    const sub = this.peekJwtSub(tokenRes.access_token);
    const roles = this.peekJwtRoles(tokenRes.access_token);

    const sessionId = this.randomId();
    sessions.set(sessionId, {
      accessToken: tokenRes.access_token,
      refreshToken: tokenRes.refresh_token,
      idToken: tokenRes.id_token,
      expiresIn: expiresAt,
      sub,
      roles,
      tokenType: tokenRes.token_type,
    });

    this.gcSessions();

    return {
      sessionId,
      returnTo: stash.returnTo,
      tokens: tokenRes, // solo para debug
    };
  }

  // ========== Helpers OIDC ==========

  private authorizeEndpoint() {
    return `${base}/realms/${encodeURIComponent(
      realm,
    )}/protocol/openid-connect/auth`;
  }

  private tokenEndpoint() {
    return `${base}/realms/${encodeURIComponent(
      realm,
    )}/protocol/openid-connect/token`;
  }

  private async tokenRequest(opts: { code: string; codeVerifier: string }) {
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', clientId);
    if (clientSecret) body.set('client_secret', clientSecret);
    body.set('code', opts.code);
    body.set('code_verifier', opts.codeVerifier);
    body.set('redirect_uri', redirectUri);

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

  // ========== PKCE utils ==========

  private generatePkce() {
    const verifier = this.base64url(crypto.randomBytes(32)); // 43-128 chars
    const challenge = this.base64url(
      crypto.createHash('sha256').update(verifier).digest(),
    );
    return { verifier, challenge };
  }

  private base64url(buf: Buffer) {
    return buf
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
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
    for (const [k, v] of sessions) if (v.expiresIn < now) sessions.delete(k);
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

  private peekJwtRoles(jwt?: string) {
    try {
      if (!jwt) return undefined;
      const [, payload] = jwt.split('.');
      const json = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
      // Realm roles: json.realm_access.roles
      // Client roles: json.resource_access[CLIENT_ID].roles
      const realmRoles: string[] = json?.realm_access?.roles ?? [];
      const clientRoles: string[] =
        json?.resource_access?.[clientId]?.roles ?? [];
      return [...new Set([...realmRoles, ...clientRoles])];
    } catch {
      return undefined;
    }
  }
}
