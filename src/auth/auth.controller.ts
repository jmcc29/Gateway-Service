// src/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  Query,
  Get,
  Req,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { ApiTags, ApiResponse, ApiQuery, ApiBody } from '@nestjs/swagger';
import { Redirect } from '@nestjs/common';

// Utils de request (no lógica de negocio)
import { extractSid, extractClientId, extractAudience } from './utils/http';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Helper mínimo y centralizado (solo orquesta):
   * - sid: cookie "sid" (o query si la pusieras)
   * - clientId: header X-Client-Id o ?client_id; si no viene, se deduce por Origin/Referer
   * - audience: header X-Audience o ?audience o fallback de env
   *
   * Nota: Deducir clientId se delega al servicio (resolveClientFromHeaders).
   */
  private resolveSidOrThrow(req: Request) {
    const sid = extractSid(req);
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión (cookie "sid").');
    return sid;
  }

  private resolveClientIdOrThrow(req: Request): string {
    const explicit = extractClientId(req);
    if (explicit && explicit.trim()) return explicit.trim();

    // Deducción por Origin/Referer (MAP origin -> clientId configurado en OIDC_CLIENTS)
    try {
      const client = (this.authService as any).resolveClientFromHeaders?.(req);
      if (client?.id) return client.id;
    } catch (e: any) {
      // silencioso; lanzamos error coherente abajo
    }
    throw new BadRequestException('No se pudo determinar el client_id (falta X-Client-Id/param o no hay Origin/Referer válido).');
  }

  private resolveAudienceOrThrow(req: Request) {
    const aud = extractAudience(req);
    if (!aud) throw new BadRequestException('Falta audience (X-Audience o ?audience).');
    return aud;
  }

  /**
   * Inicia el flujo OIDC.
   * - returnTo (obligatorio)
   * - client_id (opcional): si no se envía, se deduce por el Origin/Referer de returnTo
   */
  @Get('login')
  @Redirect()
  @ApiQuery({
    name: 'returnTo',
    required: true,
    description: 'URL absoluta del frontend que inició el flujo',
  })
  @ApiQuery({
    name: 'client_id',
    required: false,
    description: 'client_id real de Keycloak (si no se envía, se deduce por origin)',
  })
  async login(@Req() req: Request, @Query('returnTo') returnTo?: string, @Query('client_id') clientId?: string) {
    if (!returnTo) throw new BadRequestException('Falta returnTo');
    // Si te pasan client_id explícito, se usa; si no, el servicio lo deduce por el origin del returnTo:
    const { url } = await this.authService.buildAuthUrl({ returnTo, clientId: clientId || undefined });
    return { url, statusCode: 302 };
  }

  /**
   * Intercambia code→tokens y crea/actualiza la sesión (sid) del usuario.
   * El client_id se recupera del pending guardado (no hace falta pasarlo aquí).
   */
  @Post('exchange')
  @ApiResponse({
    status: 200,
    description: 'Sesión creada',
    schema: { example: { sessionId: '...', returnTo: '...' } },
  })
  async exchange(@Body() body: { code: string; state: string; sidCookie?: string }) {
    if (!body?.code || !body?.state) throw new BadRequestException('Faltan code/state');
    const { sessionId, returnTo } = await this.authService.exchangeCodeAndCreateSession(body);
    return { sessionId, returnTo };
  }

  /**
   * Devuelve datos de la sesión.
   * - client_id opcional: si no se envía, se deduce por Origin/Referer.
   */
  @Get('session')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: false,
    description: 'client_id del que se requiere el token (si no, se deduce por Origin/Referer)',
  })
  getSession(@Req() req: Request, @Query('sid') sidFromQuery?: string, @Query('client_id') clientIdFromQuery?: string) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    const clientId = clientIdFromQuery ?? this.resolveClientIdOrThrow(req);

    try {
      return this.authService.getSessionData(sid, clientId);
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'Sesión inválida');
    }
  }

  /**
   * Logout global: revoca en Keycloak todos los refresh tokens y borra sid.
   */
  @Post('logout')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  async logout(@Req() req: Request, @Query('sid') sidFromQuery?: string) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    await this.authService.logout(sid);
    return { ok: true };
  }

  /**
   * Devuelve permisos UMA normalizados ("permissions" siempre).
   * - client_id opcional: si no se envía, se deduce por Origin/Referer.
   * - audience obligatorio (X-Audience o ?audience)
   */
  @Get('permissions')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: false,
    description: 'client_id desde el que se toma el access_token (si no, se deduce por Origin/Referer)',
  })
  @ApiQuery({
    name: 'audience',
    required: false,
    description: 'client_id (resource server) contra el que se calculan permisos UMA (si falta, intenta X-Audience o env)',
  })
  async permissions(@Req() req: Request, @Query('sid') sidFromQuery?: string, @Query('client_id') clientIdFromQuery?: string, @Query('audience') audienceFromQuery?: string) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    const clientId = clientIdFromQuery ?? this.resolveClientIdOrThrow(req);
    const audience = audienceFromQuery ?? this.resolveAudienceOrThrow(req);

    try {
      const data = await this.authService.getPermissions({ sessionId: sid, clientId, audience });
      return { audience, response_mode: 'permissions', data };
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'No fue posible obtener permisos');
    }
  }

  /**
   * Perfil enriquecido + permisos (si se envía/resolve audience).
   * - client_id opcional: si no se envía, se deduce por Origin/Referer.
   * - audience opcional: si no viene, se intenta X-Audience o env (puede quedar undefined y retorna sin permisos).
   */
  @Get('profile')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({ name: 'client_id', required: false, description: 'client_id del que se leen tokens (si no, se deduce por Origin/Referer)' })
  @ApiQuery({ name: 'audience', required: false, description: 'client_id (resource server) para calcular permisos UMA (opcional)' })
  @ApiQuery({ name: 'response_mode', required: false, description: 'permissions | decision (default: permissions)' })
  async profile(@Req() req: Request, @Query('sid') sidFromQuery?: string, @Query('client_id') clientIdFromQuery?: string, @Query('audience') audienceFromQuery?: string) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    const clientId = clientIdFromQuery ?? this.resolveClientIdOrThrow(req);
    // audience opcional
    const audience = audienceFromQuery ?? extractAudience(req);

    try {
      return await this.authService.getProfile({ sessionId: sid, clientId, audience });
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'Sesión inválida');
    }
  }

  /**
   * EVALUATE-PERMISSION (UMA decision): booleano para "resource#scope".
   * - client_id opcional: si no se envía, se deduce por Origin/Referer.
   * - audience obligatorio (como en /permissions).
   */
  @Post('evaluate-permission')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: false,
    description: 'client_id desde el que se toma el access_token (si no, se deduce por Origin/Referer)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        audience: { type: 'string', example: 'my-resource-server' },
        resource: { type: 'string', example: 'orders' },
        scope: { type: 'string', example: 'read' },
      },
      required: ['audience', 'resource', 'scope'],
    },
  })
  async evaluatePermission(
    @Req() req: Request,
    @Query('sid') sidFromQuery: string | undefined,
    @Query('client_id') clientIdFromQuery: string | undefined,
    @Body() body: { audience?: string; resource?: string; scope?: string },
  ) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    const clientId = clientIdFromQuery ?? this.resolveClientIdOrThrow(req);

    const audience = body?.audience ?? this.resolveAudienceOrThrow(req);
    const resource = body?.resource;
    const scope = body?.scope;
    if (!resource) throw new BadRequestException('Falta resource');
    if (!scope) throw new BadRequestException('Falta scope');

    try {
      const allowed = await this.authService.evaluatePermission({
        sessionId: sid,
        clientId,
        audience,
        resource,
        scope,
      });
      return { audience, permission: `${resource}#${scope}`, allowed };
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'No fue posible evaluar el permiso');
    }
  }

  /**
   * VERIFY (diagnóstico): Verifica criptográficamente el access_token de la sesión.
   * - client_id opcional: si no se envía, se deduce por Origin/Referer.
   */
  @Get('verify')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: false,
    description: 'client_id desde el que se toma el access_token (si no, se deduce por Origin/Referer)',
  })
  async verify(@Req() req: Request, @Query('sid') sidFromQuery?: string, @Query('client_id') clientIdFromQuery?: string) {
    const sid = sidFromQuery ?? this.resolveSidOrThrow(req);
    const clientId = clientIdFromQuery ?? this.resolveClientIdOrThrow(req);

    try {
      const v = await this.authService.verifySessionAccessToken(sid, clientId);
      return {
        isValid: v.isValid,
        sub: v.sub,
        azp: v.azp,
        aud: v.aud,
        roles: v.roles,
        user: v.user,
      };
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'Token inválido');
    }
  }
}
