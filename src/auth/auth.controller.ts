import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  Redirect,
  Req,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiBody, ApiCookieAuth, ApiOperation, ApiResponse, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { AuthAppMobileGuard } from 'src/auth/guards';
import { NatsService } from 'src/common';
import { Records } from 'src/records/records.interceptor';
import { LoginUserDto, LoginStartDto } from './dto';
import { CurrentUser } from './interfaces/current-user.interface';
import { Query } from '@nestjs/common';
import { ApiQuery } from '@nestjs/swagger';

@ApiTags('auth')
@ApiSecurity('origin-header')
// @UseInterceptors(Records)
@Controller('auth')
export class AuthController {
  constructor(private readonly nats: NatsService) {}

  // @ApiOperation({ summary: 'Auth Web - loginUser' })
  // @ApiBody({
  //   schema: {
  //     type: 'object',
  //     properties: {
  //       username: { type: 'string', example: 'numeroCI' },
  //       password: { type: 'string', example: '71931166' },
  //     },
  //   },
  // })
  // @Post('login')
  // async loginHubWeb(
  //   @Body() loginUserDto: LoginUserDto,
  //   @Res({ passthrough: true }) res: Response,
  // ): Promise<any> {
  //   const data: CurrentUser = await this.nats.firstValue('auth.login', loginUserDto);

  //   const timeShort = 4;
  //   const oneHourMiliseconds = 3600000;

  //   res.cookie('msp', data.access_token, {
  //     path: '/',
  //     httpOnly: true,
  //     sameSite: 'strict',
  //     expires: new Date(Date.now() + timeShort * oneHourMiliseconds),
  //   });

  //   return {
  //     message: 'Login successful',
  //     user: data.user,
  //   };
  // }

  // @ApiOperation({ summary: 'Auth Web - logout' })
  // @Get('logout')
  // async logout(@Res() res: Response): Promise<void> {
  //   res.clearCookie('msp', {
  //     path: '/',
  //     httpOnly: true,
  //     sameSite: 'strict',
  //   });
  //   res.status(200).json({
  //     message: 'Logout successful',
  //   });
  // }

  @ApiOperation({ summary: 'Auth AppMobile - loginAppMobile' })
  @ApiResponse({ status: 200, description: 'Login AppMobile' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        username: { type: 'string', example: 'numeroCI' },
        cellphone: { type: 'string', example: '71931166' },
        signature: { type: 'string', example: 'firma' },
        firebaseToken: { type: 'string', example: 'token' },
        isBiometric: { type: 'boolean', example: 'true' },
        isRegisterCellphone: { type: 'boolean', example: 'false' },
      },
    },
  })
  @Post('loginAppMobile')
  async loginAppMobile(@Body() body: any) {
    return await this.nats.firstValue('auth.loginAppMobile', body);
  }

  @ApiOperation({ summary: 'Auth AppMobile - verifyPin' })
  @ApiResponse({ status: 200, description: 'Verificar pin SMS y crear token' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        pin: { type: 'string', example: '1234' },
        messageId: { type: 'string', example: '99999' },
      },
    },
  })
  @Post('verifyPin')
  async verifyPin(@Body() body: any) {
    const response = await this.nats.firstValue('auth.verifyPin', body);
    const { error, message, data } = response;

    if (!error) {
      this.nats.emit('appMobile.record.create', {
        action: 'verifyPin',
        description: message,
        metadata: {
          username: data.information.username,
          isPolice: data.information.isPolice,
          affiliateId: data.information.affiliateId,
        },
      });
    }
    return response;
  }

  @ApiOperation({ summary: 'Auth AppMobile - logoutAppMobile' })
  @ApiResponse({ status: 200, description: 'Eliminar sesión' })
  @Delete('logoutAppMobile')
  @UseGuards(AuthAppMobileGuard)
  async logoutAppMobile(@Req() req: any) {
    this.nats.emit('appMobile.record.create', {
      action: 'logoutAppMobile',
      description: 'Cierre de sesión en App Móvil',
      metadata: req.user,
    });
    return await this.nats.firstValue('auth.logoutAppMobile', req.user);
  }

  /* ======================================================
   *  OIDC / SSO para Frontend Hub-Interface
   * ====================================================== */

  @ApiOperation({ summary: 'OIDC - Construir URL de autorización (PKCE + state)' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        returnTo: { type: 'string', example: 'http://localhost:3001/modules' },
      },
      required: ['returnTo'],
    },
  })
  @Get('login')
  @Redirect()
  async startLogin(@Req() req: any, @Res() res: Response) {
    // El frontend manda returnTo, y nosotros determinamos el clientId desde .env
    const clientId = req.query.clientId;
    const returnTo = req.query.returnTo;
    const { url } = await this.nats.firstValue('auth.login.start', {
      returnTo,
      clientId,
    });

    res.setHeader('Cache-Control', 'no-store');
    return { url, statusCode: 302 };
  }

  @ApiOperation({ summary: 'OIDC - Exchange code/state → sid (establece cookie sid)' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        code: { type: 'string', example: 'abc123' },
        state: { type: 'string', example: 'xyz789' },
      },
      required: ['code', 'state'],

    },
  })
  @Post('exchange')
  @ApiResponse({
    status: 200,
    description: 'Sesión creada',
    schema: { example: { sessionId: '...', returnTo: '...' } },
  })
  async exchange(
    @Body() body: { code: string; state: string; sidCookie?: string },
    @Res() res: Response,
  ) {
    if (!body?.code || !body?.state) {
      return res.status(400).json({ error: 'Faltan code/state' });
    }

    // 👇 Igual que antes, pero ahora llamando al microservicio
    const { sid, returnTo } = await this.nats.firstValue('auth.login.exchange', {
      code: body.code,
      state: body.state,
      // importante: solo pasa el sidCookie si vino en el body
      ...(body.sidCookie ? { sid: body.sidCookie } : {}),
    });
    console.log('Exchange OIDC - nueva sesión creada:', { sid, returnTo });
    // 👇 formato EXACTO esperado por tu frontend antiguo
    return res.status(200).json({ sessionId: sid, returnTo });
  }

  /* ======================================================
   *  Endpoints útiles de sesión (para debug / status)
   * ====================================================== */

  @ApiOperation({ summary: 'OIDC - Logout SSO (revoca tokens y elimina sid)' })
  @Delete('logout')
  async ssoLogout(@Req() req: Request, @Res() res: Response) {
    const sid = req.cookies?.sid;
    console.log('Logout OIDC - cerrando sesión:', { sid });
    if (sid) {
      try {
        await this.nats.firstValue('auth.logout', { sid });
      } catch (err) {
        console.error('❌ Error al cerrar sesión en Auth-Service:', err);
      }
    }

    // El backend NO elimina cookies del navegador (lo hace el frontend)
    res.setHeader('Cache-Control', 'no-store');
    return res.status(204).send(); // No Content
  }

  /* ======================================================
   *  Endpoints útiles de autorización (para debug / status)
   * ====================================================== */

  @ApiOperation({ summary: 'Auth Plataforma - getProfile' })
  @Get('profile')
  async getProfile(@Req() req: Request, @Res() res: Response) {
    const sid = req.cookies?.sid;
    if (!sid) return res.status(401).json({ ok: false, message: 'Falta cookie sid' });

    const origin =
      (req.headers.origin as string) ||
      (req.headers['x-origin'] as string) ||
      (req.headers.referer as string) ||
      (req.headers['x-referer'] as string);
    console.log('getProfile', { sid, origin });
    try {
      const data = await this.nats.firstValue('auth.profile.get', { sid, origin });
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json(data);
    } catch (e: any) {
      return res
        .status(401)
        .json({ ok: false, code: 'PROFILE_LOOKUP_FAILED', message: e?.message ?? 'Unauthorized' });
    }
  }

  @ApiOperation({ summary: 'Verificar existencia y validez del access token de un cliente' })
  @Get('token/verify')
  async verifyTokenEndpoint(
    @Query('clientId') client_id: string,
    @Req() req: Request, @Res() res: Response
    ) {
      console.log('sid');
    const sid = req.cookies?.sid;
    
    if (!sid) return res.status(401).json({ ok: false, message: 'Falta cookie sid' });

    const clientId = req.query?.clientId || client_id;
    if (!clientId) return res.status(400).json({ ok: false, message: 'Falta clientId' });

    console.log('Verifying token for clientId:', clientId, sid);
    const origin =
      // (req.headers.origin as string) ||
      (req.headers['x-origin'] as string) 
      // (req.headers.referer as string) ||
      // (req.headers['x-referer'] as string);

    console.log('verifyToken', { sid, clientId, origin });
    try {
      const data = await this.nats.firstValue('auth.token.verify', { sid, clientId, origin });
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json(data);
    } catch (e: any) {
      return res
        .status(401)
        .json({ ok: false, code: 'PROFILE_LOOKUP_FAILED', message: e?.message ?? 'Unauthorized' });
    }
  }


  @ApiOperation({ summary: 'Listar permisos UMA para un audience (resource-server)' })
  @ApiQuery({ name: 'audience', type: String, required: true })
  @Get('permissions')
  async getPermissions(
    @Req() req: Request,
    @Res() res: Response,
    // @Query('clientId') clientId: string,
    @Query('audience') aud: string,

  ) {
    const sid = req.cookies?.sid /* || sessionId*/ ;
    
    if (!sid) return res.status(401).json({ ok: false, message: 'Falta cookie sid' });

    const audience = req.query.audience || aud /* || aud*/;
    if (!audience) return res.status(400).json({ ok: false, message: 'Falta audience' });

    const origin =
      (req.headers['x-origin'] as string) ||
      (req.headers.origin as string) ||
      (req.headers.referer as string) ||
      (req.headers['x-referer'] as string);
    console.log('getPermissions', { sid, audience, origin });
    try {
      const out = await this.nats.firstValue('auth.permissions.list', {
        sid,
        audience,
        origin,
      });
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json(out);
    } catch (e: any) {
      return res
        .status(401)
        .json({
          ok: false,
          code: 'PERMISSIONS_LIST_FAILED',
          message: e?.message ?? 'Unauthorized',
        });
    }
  }

  @ApiOperation({ summary: 'Evaluar permiso UMA (resource#scope) contra audience' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        audience: { type: 'string', example: 'records-api' },
        resource: { type: 'string', example: 'expedientes' },
        scope: { type: 'string', example: 'create' },
      },
      required: ['audience', 'resource', 'scope'],
    },
  })
  @Post('permission/evaluate')
  async evaluatePermission(@Req() req: Request, @Res() res: Response, @Body() body: any) {
    const sid = req.cookies?.sid;
    if (!sid) return res.status(401).json({ ok: false, message: 'Falta cookie sid' });

    const { audience, resource, scope } = body ?? {};
    if (!audience || !resource || !scope) {
      return res.status(400).json({ ok: false, message: 'Faltan audience/resource/scope' });
    }

    const origin =
      (req.headers['x-origin'] as string) ||
      (req.headers.origin as string) ||
      (req.headers.referer as string) ||
      (req.headers['x-referer'] as string);
    try {
      const out = await this.nats.firstValue('auth.permission.evaluate', {
        sid,
        audience,
        resource,
        scope,
        origin,
      });
      console.log('evaluatePermission response', out);
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).json(out);
    } catch (e: any) {
      return res
        .status(401)
        .json({
          ok: false,
          code: 'PERMISSION_EVALUATE_FAILED',
          message: e?.message ?? 'Unauthorized',
        });
    }
  }
}
