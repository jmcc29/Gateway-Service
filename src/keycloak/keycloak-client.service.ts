// src/keycloak/keycloak-client.service.ts
import axios from 'axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtVerify, createRemoteJWKSet, JWTPayload } from 'jose-node-cjs-runtime';
import { KeycloakEnvs } from 'src/config';

type VerifyOpts = {
  /** Si se pasa, el azp del token debe pertenecer a esta lista (multi-cliente) */
  allowedClients?: string[];
  /** Opcional: validar que 'aud' contenga este valor (no siempre útil en Keycloak) */
  audience?: string | string[];
};

@Injectable()
export class KeycloakClientService {
  private readonly base = KeycloakEnvs.authServerUrl;
  private readonly realm = KeycloakEnvs.realm;
  private readonly issuer = `${this.base}/realms/${encodeURIComponent(this.realm)}`;
  private readonly jwks = createRemoteJWKSet(new URL(this.certsEndpoint()));

  private tokenEndpoint() {
    return `${this.issuer}/protocol/openid-connect/token`;
  }
  private logoutEndpoint() {
    return `${this.issuer}/protocol/openid-connect/logout`;
  }
  private certsEndpoint() {
    return `${this.issuer}/protocol/openid-connect/certs`;
  }

  /** Verifica firma/issuer/exp/nbf y (opcional) azp∈allowedClients, aud==… */
  async verifyAccessToken(token: string, opts?: VerifyOpts) {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.issuer,
      // Nota: audience no siempre aplica igual en Keycloak; mejor chequear azp.
      audience: Array.isArray(opts?.audience) ? opts?.audience[0] : opts?.audience,
    });

    // Chequeo multi-cliente por azp (Authorized Party)
    if (opts?.allowedClients?.length) {
      const azp = payload.azp as string | undefined;
      if (!azp || !opts.allowedClients.includes(azp)) {
        throw new UnauthorizedException('Token emitido para otro client_id');
      }
    }

    return {
      isValid: true as const,
      payload,
      user: this.toUser(payload),
      roles: this.extractRoles(payload),
      azp: payload.azp as string | undefined,
      aud: payload.aud,
      sub: payload.sub,
    };
  }

  /** UMA: permissions (array) o decision ({result:boolean}), según response_mode */
  async umaRequest(accessToken: string, args: {
    audience: string;
    responseMode?: 'permissions' | 'decision';
    /** Opcional: "resource#scope" para pedir una decisión concreta */
    permission?: string;
  }) {
    const body = new URLSearchParams();
    body.set('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
    body.set('audience', args.audience);
    body.set('response_mode', args.responseMode ?? 'permissions');
    if (args.permission) body.set('permission', args.permission);

    const { data } = await axios.post(this.tokenEndpoint(), body, {
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Bearer ${accessToken}`,
      },
      timeout: 10_000,
    });

    return data;
  }

  /** (Opcional) Logout directo, por si quieres centralizarlo aquí también */
  async logoutByRefreshToken(refreshToken: string, client: { id: string; secret?: string }) {
    const body = new URLSearchParams();
    body.set('client_id', client.id);
    if (client.secret) body.set('client_secret', client.secret);
    body.set('refresh_token', refreshToken);

    await axios.post(this.logoutEndpoint(), body, {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      timeout: 8_000,
    });
  }

  // ---- helpers ----
  private toUser(p: JWTPayload) {
    return {
      sub: p.sub as string | undefined,
      username: (p as any).preferred_username as string | undefined,
      email: p.email as string | undefined,
      name: p.name as string | undefined,
    };
  }
  private extractRoles(p: JWTPayload) {
    const realm: string[] = (p as any)?.realm_access?.roles ?? [];
    // Intentamos extraer todas las client roles
    const resAccess = (p as any)?.resource_access ?? {};
    const clientRoles = Object.values(resAccess)
      .flatMap((r: any) => (Array.isArray(r?.roles) ? r.roles : []));
    return Array.from(new Set([...realm, ...clientRoles]));
  }
}
