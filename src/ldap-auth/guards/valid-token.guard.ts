import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { NatsService } from 'src/common';
@Injectable()
export class ValidTokenGuard implements CanActivate {
  constructor(private nats: NatsService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const auth = req.headers['authorization'];

    if (!auth || !auth.startsWith('Bearer ')) {
      throw new UnauthorizedException('Token no enviado');
    }

    const token = auth.split(' ')[1];

    try {
      const result = await this.nats.firstValue('ldap-auth.validateToken', { token });

      if (!result?.isValid) {
        throw new UnauthorizedException('Token inválido');
      }

      // Adjuntar info del usuario al request
      req.user = result.user;
      return true;
    } catch (err) {
      throw new UnauthorizedException('Error al validar el token');
    }
  }
}
