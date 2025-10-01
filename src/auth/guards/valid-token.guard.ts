// src/auth/guards/valid-token.guard.ts
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { extractSid, extractClientId } from '../utils/http';

@Injectable()
export class ValidTokenGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    const sid = extractSid(req);
    const clientId = extractClientId(req);

    if (!sid) {
      throw new UnauthorizedException('Falta cookie de sesión (sid)');
    }
    if (!clientId) {
      throw new UnauthorizedException('Falta client_id (x-client-id o ?client_id)');
    }

    // 1) Verificación criptográfica del access_token guardado en la sesión
    let valid = false;
    try {
      valid = (await this.auth.verifySessionAccessToken(sid, clientId)).isValid;
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new UnauthorizedException('Token inválido o sesión expirada para este client_id');
    }

    // 2) (Opcional) Adjuntar perfil al request; si falla no bloquea
    try {
      const me = await this.auth.getProfile({ sessionId: sid, clientId });
      (req as any).user = me;
    } catch {
      // Silencioso: ya validamos el token; el perfil es “nice to have”
    }

    return true;
  }
}
