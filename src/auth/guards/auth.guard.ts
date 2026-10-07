import {
  CanActivate,
  ExecutionContext,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { NatsService } from 'src/common';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly nats: NatsService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest<Request & { user?: unknown }>();
    const apiKey = request.headers['x-api-key'];
    const token = this.extractToken(request);
    if (typeof apiKey !== 'string' && !token) {
      throw new NotFoundException({ error: true, message: 'Token no encontrado' });
    }

    try {
      if (typeof apiKey === 'string') {
        return await this.nats.firstValue('auth.verify.apiKey', apiKey);
      }
      request.user = await this.nats.firstValue('auth.verify.token', token);
      return true;
    } catch {
      throw new UnauthorizedException({ error: true, message: 'Sin autorización' });
    }
  }

  private extractToken(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
