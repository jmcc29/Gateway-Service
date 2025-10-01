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

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Inicia el flujo OIDC para un cliente específico.
   * Espera:
   *  - returnTo: URL absoluta del frontend que inició el flujo (whitelist en config)
   *  - client_id: client_id real de Keycloak (whitelist en config)
   */
  @Get('login')
  @Redirect() // Nest gestionará el 302 con lo que retornemos
  @ApiQuery({
    name: 'returnTo',
    required: true,
    description: 'URL absoluta del frontend que inició el flujo',
  })
  @ApiQuery({ name: 'client_id', required: true, description: 'client_id real de Keycloak' })
  async login(@Query('returnTo') returnTo?: string, @Query('client_id') clientId?: string) {
    if (!returnTo) throw new BadRequestException('Falta returnTo');
    if (!clientId) throw new BadRequestException('Falta client_id');

    const { url } = await this.authService.buildAuthUrl({ returnTo, clientId });
    // Importante: redirigimos a Keycloak
    return { url, statusCode: 302 };
  }

  /**
   * Intercambia code→tokens y crea/actualiza la sesión (sid) del usuario.
   * El client_id utilizado se recupera del state guardado en pending (en el servicio).
   */
  @Post('exchange')
  @ApiResponse({
    status: 200,
    description: 'Sesión creada',
    schema: { example: { sessionId: '...', returnTo: '...' } },
  })
  async exchange(@Body() body: { code: string; state: string; sidCookie?: string }) {
    if (!body?.code || !body?.state) {
      throw new BadRequestException('Faltan code/state');
    }
    const { sessionId, returnTo } = await this.authService.exchangeCodeAndCreateSession(body);
    return { sessionId, returnTo };
  }

  /**
   * Devuelve datos de la sesión para un client_id específico.
   * Lee el sid de cookie o query y requiere client_id para seleccionar el token correcto.
   */
  @Get('session')
  @ApiQuery({
    name: 'sid',
    required: false,
    description: 'ID de sesión (si no, se toma de cookie "sid")',
  })
  @ApiQuery({
    name: 'client_id',
    required: true,
    description: 'client_id del que se requiere el token',
  })
  getSession(
    @Req() req: Request,
    @Query('sid') sidFromQuery?: string,
    @Query('client_id') clientId?: string,
  ) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión');
    if (!clientId) throw new BadRequestException('Falta client_id');

    try {
      return this.authService.getSessionData(sid, clientId);
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'Sesión inválida');
    }
  }

  /**
   * Logout global: cierra en Keycloak todos los refresh tokens asociados a la sesión y borra el sid.
   * (Si en el futuro quieres logout por cliente, agrega client_id opcional y delega en el servicio).
   */
  @Post('logout')
  @ApiQuery({
    name: 'sid',
    required: false,
    description: 'ID de sesión (si no, se toma de cookie "sid")',
  })
  async logout(@Req() req: Request, @Query('sid') sidFromQuery?: string) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new BadRequestException('Falta sid');
    await this.authService.logout(sid);
    return { ok: true };
  }

  @Get('permissions')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: true,
    description: 'client_id desde el que se toma el access_token del usuario',
  })
  @ApiQuery({
    name: 'audience',
    required: true,
    description: 'client_id (resource server) contra el que se calculan permisos UMA',
  })
  @ApiQuery({
    name: 'response_mode',
    required: false,
    description: 'permissions | decision (default: permissions)',
  })
  async permissions(
    @Req() req: Request,
    @Query('sid') sidFromQuery?: string,
    @Query('client_id') clientId?: string,
    @Query('audience') audience?: string,
  ) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión');
    if (!clientId) throw new BadRequestException('Falta client_id');
    if (!audience) throw new BadRequestException('Falta audience');

    try {
      const data = await this.authService.getPermissions({
        sessionId: sid,
        clientId,
        audience,
      });
      return { audience, response_mode: 'permissions', data };
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'No fue posible obtener permisos');
    }
  }

  @Get('profile')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({ name: 'client_id', required: true, description: 'client_id del que se leen tokens' })
  @ApiQuery({
    name: 'audience',
    required: false,
    description: 'client_id (resource server) para calcular permisos UMA',
  })
  @ApiQuery({
    name: 'response_mode',
    required: false,
    description: 'permissions | decision (default: permissions)',
  })
  async profile(
    @Req() req: Request,
    @Query('sid') sidFromQuery?: string,
    @Query('client_id') clientId?: string,
    @Query('audience') audience?: string,
    @Query('response_mode') responseMode?: 'permissions' | 'decision',
  ) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión');
    if (!clientId) throw new BadRequestException('Falta client_id');

    try {
      return await this.authService.getProfile({
        sessionId: sid,
        clientId,
        audience,
        responseMode,
      });
    } catch (err: any) {
      throw new UnauthorizedException(err?.message ?? 'Sesión inválida');
    }
  }

  /**
   * EVALUATE-PERMISSION (UMA decision):
   * Devuelve booleano para un permission concreto "resource#scope".
   * Usa el access_token asociado a (sid, client_id).
   */
  @Post('evaluate-permission')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: true,
    description: 'client_id desde el que se toma el access_token del usuario',
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
    @Query('client_id') clientId: string | undefined,
    @Body()
    body: {
      audience?: string;
      resource?: string;
      scope?: string;
    },
  ) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión');
    if (!clientId) throw new BadRequestException('Falta client_id');

    const { audience, resource, scope } = body ?? {};
    if (!audience) throw new BadRequestException('Falta audience');
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
   * VERIFY (opcional): Verifica criptográficamente el access_token de la sesión
   * y que azp ∈ clientes permitidos. Útil para diagnósticos/observabilidad.
   */
  @Get('verify')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, cookie "sid")' })
  @ApiQuery({
    name: 'client_id',
    required: true,
    description: 'client_id desde el que se toma el access_token del usuario',
  })
  async verify(
    @Req() req: Request,
    @Query('sid') sidFromQuery?: string,
    @Query('client_id') clientId?: string,
  ) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new UnauthorizedException('No se encontró ID de sesión');
    if (!clientId) throw new BadRequestException('Falta client_id');

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
