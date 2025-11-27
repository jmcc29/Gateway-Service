import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { NatsService } from 'src/common';
import { AUDIENCE_KEY } from '../decorators/audience.decorator';
import { RESOURCE_KEY } from '../decorators/resource.decorator';
import { META_PERMISSION, PermissionMetadata } from '../decorators/permission.decorator';
import { SCOPE_KEY } from '../decorators/scope.decorator';

type EvaluatePermissionRes = {
  ok: true;
  audience: string;
  resource: string;
  scope: string;
  granted: boolean;
};

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly nats: NatsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    // 1) sid (igual que en TokenGuard)
    const sid =
      (req.cookies && (req.cookies as any).sid) ||
      (req.headers['x-session-id'] as string | undefined);

    if (!sid) {
      // En teoría TokenGuard ya bloqueó esto, pero por si alguien usa Scope sin TokenGuard
      throw new UnauthorizedException('sid no encontrado en la solicitud');
    }

    // 2) origin (igual que en TokenGuard)
    const origin =
      (req.headers['x-origin'] as string | undefined) ||
      (req.headers['origin'] as string | undefined);

    // 3) Metadata de audience / resource / scope
    const handler = context.getHandler();
    const klass = context.getClass();

    const audience =
      this.reflector.get<string>(AUDIENCE_KEY, klass) ||
      this.reflector.get<string>(AUDIENCE_KEY, handler);

    const permMeta =
      this.reflector.get<PermissionMetadata | undefined>(META_PERMISSION, handler);

    // resource puede venir de:
    // - @Permission(resource, scope)
    // - @Resource() a nivel de método
    // - @Resource() a nivel de controller
    let resource =
      permMeta?.resource ||
      this.reflector.get<string | undefined>(RESOURCE_KEY, handler) ||
      this.reflector.get<string | undefined>(RESOURCE_KEY, klass);

    // scope puede venir de:
    // - @Permission(resource, scope)
    // - @Scope(scope) a nivel de método
    let scope =
      permMeta?.scope ||
      this.reflector.get<string | undefined>(SCOPE_KEY, handler);

    // 4) Si no hay audience o resource/scope, interpretamos que NO hay restricción de permisos
    //    (solo autenticación). Así puedes usar TokenGuard solo.
    if (!audience || !resource || !scope) {
      // Opcional: loggear para detectar endpoints mal configurados
      // console.warn('[PermissionGuard] No permission metadata, allowing by default');
      return true;
    }

    // 5) Llamar al microservicio de auth para evaluar el permiso
    let res: EvaluatePermissionRes;
    try {
      res = await this.nats.firstValue(
        'auth.permission.evaluate',
        {
          sid,
          origin,
          audience,
          resource,
          scope,
        },
      );
    } catch (err) {
      // Si el auth-service falla, es un problema interno, pero de cara al cliente es 403
      throw new ForbiddenException('No se pudo evaluar el permiso');
    }

    if (!res?.ok) {
      throw new ForbiddenException('No se pudo evaluar el permiso');
    }

    if (!res.granted) {
      throw new ForbiddenException('Acceso denegado');
    }

    return true;
  }
}
