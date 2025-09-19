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
import { ApiTags, ApiResponse, ApiQuery } from '@nestjs/swagger';
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
  @ApiQuery({ name: 'returnTo', required: true, description: 'URL absoluta del frontend que inició el flujo' })
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
  @ApiResponse({ status: 200, description: 'Sesión creada', schema: { example: { sessionId: '...', returnTo: '...' } } })
  async exchange(@Body() body: { code: string; state: string }) {
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
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, se toma de cookie "sid")' })
  @ApiQuery({ name: 'client_id', required: true, description: 'client_id del que se requiere el token' })
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
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión (si no, se toma de cookie "sid")' })
  async logout(@Req() req: Request, @Query('sid') sidFromQuery?: string) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    if (!sid) throw new BadRequestException('Falta sid');
    await this.authService.logout(sid);
    return { ok: true };
  }
}
