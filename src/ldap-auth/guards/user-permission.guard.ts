import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { NatsService } from 'src/common';
import {
  META_PERMISSION,
  PermissionMetadata,
  PermissionProtected,
} from 'src/ldap-auth/decorators/permission-protected.decorator';

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

    const permission: PermissionMetadata = this.reflector.get<PermissionMetadata>(
      META_PERMISSION,
      context.getHandler(),
    );

    if (!permission) {
      throw new ForbiddenException('Permiso no definido en la ruta');
    }

    const { resource, scope } = permission;

    try {
      const hasPermission = await this.nats.firstValue('ldap-auth.evaluatePermission', {
        accessToken: token,
        resource,
        scope,
      });

      if (!hasPermission) {
        throw new ForbiddenException(`No autorizado para ${scope} en ${resource}`);
      }

      return true;
    } catch (err) {
      throw new ForbiddenException(err.message);
    }
  }
}
