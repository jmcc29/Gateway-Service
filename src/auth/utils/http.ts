// src/auth/utils/http.ts
import { Request } from 'express';

export function extractSid(req: Request): string | undefined {
  return req.cookies?.sid;
}

export function extractClientId(req: Request): string | undefined {
  let clientId = req.headers['x-client-id'] as string | undefined;
  if (!clientId) {
    const q = req.query?.client_id;
    if (typeof q === 'string') clientId = q;
    else if (Array.isArray(q) && typeof q[0] === 'string') clientId = q[0];
  }
  return clientId;
}

/** Audiencia = clientId del *resource server* (tu API) */
export function extractAudience(req: Request): string | undefined {
  // Prioridad: header → query → env (fallback)
  const h = req.headers['x-audience'];
  if (typeof h === 'string' && h.trim()) return h.trim();

  const q = req.query?.audience;
  if (typeof q === 'string' && q.trim()) return q.trim();

  const env = process.env.KEYCLOAK_RESOURCE_SERVER_CLIENT_ID || process.env.API_AUDIENCE;
  if (env && env.trim()) return env.trim();

  return undefined;
}
