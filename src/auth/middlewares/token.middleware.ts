import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth.service';

@Injectable()
export class TokenFromSidMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    console.log('🛡️ Guard', req.method, req.originalUrl);
    console.log('   Authorization:', req.headers.authorization);
    console.log('   Headers.cookie:', req.headers.cookie);
    console.log('   req.cookies:', req.cookies);
    const sid = req.cookies?.sid;

    console.log('🧩 Middleware ejecutado. SID recibido:', sid);

    if (sid && !req.headers.authorization) {
      const sessionData = this.authService.getSessionData(sid);
      console.log('SESSION DATA:', sessionData);
      const accessToken = sessionData?.accessToken;
      if (accessToken) {
        req.headers.authorization = `Bearer ${accessToken}`;
        console.log('✅ Token inyectado al header Authorization');
      } else {
        console.log('⚠️ No se pudo obtener accessToken con ese SID');
      }
    }
    next();
  }
}
