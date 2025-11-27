import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { NatsService } from 'src/common';

@Injectable()
export class TokenGuard implements CanActivate {
  constructor(private readonly nats: NatsService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    // 1) Obtener sid (cookie en runtime real, header para Swagger/dev)
    const sid =
      (req.cookies && (req.cookies as any).sid) ||
      (req.headers['x-session-id'] as string | undefined);

    if (!sid) {
      throw new UnauthorizedException('sid no encontrado en la solicitud');
    }

    // 2) Obtener origin (header real o x-origin para Swagger)
    const origin =
      (req.headers['origin'] as string | undefined) ||
      (req.headers['x-origin'] as string | undefined);

    console.log('(TokenGuard) origin:', origin);
    console.log('(TokenGuard) sid:', sid);
    // 3) Llamar al microservicio de auth vía NATS
    let status: any;

    try {
      status = await this.nats.firstValue(
        'auth.token.verify',
        { sid, origin },
      );
    } catch (err) {
      // Si el auth-service falla, lo tratamos como no autorizado
      throw new UnauthorizedException('No se pudo verificar el token');
    }

    // 4) Evaluar respuesta
    if (!status?.exists) {
      throw new UnauthorizedException('No existe token para esta sesión');
    }

    if (!status.isValid) {
      throw new UnauthorizedException('Token inválido o expirado');
    }

    console.log('(TokenGuard) Token válido en sid:', sid);
    console.log('(TokenGuard) para el origin:', origin);

    return true;
  }
}
