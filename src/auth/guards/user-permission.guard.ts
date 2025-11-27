// src/auth/guards/user-permission.guard.ts
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
import { META_PERMISSION, PermissionMetadata, RESOURCE_KEY, SCOPE_KEY } from '../decorators';
import { extractSid, extractClientId, extractAudience } from '../utils/http';

@Injectable()
export class UserPermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly nats: NatsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    const sid = extractSid(req);
    const clientId = extractClientId(req);
    const audience = extractAudience(req);

    if (!sid) {
      throw new UnauthorizedException('Falta cookie de sesión (sid)');
    }
    if (!clientId) {
      throw new UnauthorizedException('Falta client_id (x-client-id o ?client_id)');
    }
    if (!audience) {
      throw new ForbiddenException('Falta audience (x-audience, ?audience o variable de entorno)');
    }

    // 1) Resolver metadata de autorización
    let meta = this.reflector.get<PermissionMetadata>(META_PERMISSION, context.getHandler());
    let resource = meta?.resource;
    let scope = meta?.scope;

    if (!resource || !scope) {
      const clsResource = this.reflector.get<string>(RESOURCE_KEY, context.getClass());
      const hScope = this.reflector.get<string>(SCOPE_KEY, context.getHandler());
      resource ??= clsResource;
      scope ??= hScope;
    }

    if (!resource || !scope) {
      throw new ForbiddenException('Faltan metadatos de autorización (resource y/o scope)');
    }

    // 2) Decisión UMA
    try {
      const allowed = await this.nats.firstValue('auth.permission.evaluate', {
        sessionId: sid,
        clientId,
        audience,
        resource,
        scope,
      });

      if (!allowed) {
        throw new ForbiddenException(`No autorizado para "${scope}" en recurso "${resource}"`);
      }

      return true;
    } catch (e: any) {
      // Si el call UMA falló (connectivity, config), responde 403 genérico
      throw new ForbiddenException(`No autorizado para "${scope}" en recurso "${resource}"`);
    }
  }
}