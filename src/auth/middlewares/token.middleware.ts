// src/auth/token-middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth.service';
import { extractSid, extractClientId } from '../utils/http';

const STRICT_AUTH_HEADER = process.env.STRICT_AUTH_HEADER === 'true';
const REQUIRE_CLIENT_ID = process.env.REQUIRE_CLIENT_ID === 'true';

@Injectable()
export class TokenFromSidMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  async use(req: Request, _res: Response, next: NextFunction) {
    // Logs mínimos y útiles (evita imprimir tokens reales)
    const path = `${req.method} ${req.originalUrl}`;
    try {
      const sid = extractSid(req);
      let clientId = extractClientId(req);

      if (!clientId) {
        if (REQUIRE_CLIENT_ID) {
          // Corta temprano si así lo definiste
          return next(new Error('Falta client_id (x-client-id o ?client_id)'));
        }
        // Si no lo requieres, deja que lo validen los guards
        return next();
      }

      if (!sid) {
        // No hay sesión → no podemos inyectar token
        return next();
      }

      // Si ya viene Authorization, lo comparamos con el de la sesión.
      const incomingAuth = req.headers.authorization;
      const hasBearer =
        typeof incomingAuth === 'string' && /^Bearer\s+.+/i.test(incomingAuth);

      // Intenta obtener token de la sesión para ese clientId
      let sessionToken: string | undefined;
      try {
        const sessionData = await this.authService.getSessionData(sid, clientId);
        sessionToken = sessionData?.accessToken;
      } catch (e) {
        // No abortamos todo el request: dejamos que los guards manejen el error
        // (p.ej., sesión expirada o clientId sin tokens)
        return next();
      }

      if (!sessionToken) return next();

      if (!hasBearer) {
        // Inyecta Authorization si no existe
        req.headers.authorization = `Bearer ${sessionToken}`;
        return next();
      }

      // Si hay Authorization entrante, verifica coherencia
      const incomingToken = incomingAuth!.replace(/^Bearer\s+/i, '').trim();
      if (incomingToken !== sessionToken) {
        if (STRICT_AUTH_HEADER) {
          return next(new Error('Authorization enviado no coincide con sesión activa'));
        }
        // Por defecto, preferimos el token derivado de la sesión
        req.headers.authorization = `Bearer ${sessionToken}`;
      }

      return next();
    } catch (err) {
      // Ante cualquier error inesperado, no rompas toda la ruta
      return next(err);
    }
  }
}
