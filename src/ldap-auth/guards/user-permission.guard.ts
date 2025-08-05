import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { NatsService } from 'src/common';
import { META_PERMISSION, PermissionMetadata } from '../decorators/permission-protected.decorator';
import { RESOURCE_KEY } from '../decorators/resource.decorator';
import { SCOPE_KEY } from '../decorators/scope-protected.decorator';

@Injectable()
export class UserPermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly nats: NatsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
      throw new UnauthorizedException('Token de acceso no encontrado');
    }

    // 1. Buscar primero en @PermissionProtected()
    let permission: PermissionMetadata = this.reflector.get<PermissionMetadata>(
      META_PERMISSION,
      context.getHandler(),
    );

    let resource = permission?.resource;
    let scope = permission?.scope;

    // 2. Si no está definido, buscar en @Resource y @ScopeProtected
    if (!resource || !scope) {
      resource = this.reflector.get<string>(RESOURCE_KEY, context.getClass());
      scope = this.reflector.get<string>(SCOPE_KEY, context.getHandler());
    }

    if (!resource || !scope) {
      throw new ForbiddenException('Faltan metadatos de autorización (resource o scope)');
    }

    const hasPermission = await this.nats.firstValue('ldap-auth.evaluatePermission', {
      accessToken: token,
      resource,
      scope,
    });

    if (!hasPermission) {
      throw new ForbiddenException(`No autorizado para ${scope} en ${resource}`);
    }

    return true;
  }
}
