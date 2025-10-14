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
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { AuthAppMobileGuard } from 'src/auth/guards';
import { NatsService } from 'src/common';
import { Records } from 'src/records/records.interceptor';
import { LoginUserDto, LoginStartDto } from './dto';
import { CurrentUser } from './interfaces/current-user.interface';
import { Query } from '@nestjs/common';
import { ApiQuery } from '@nestjs/swagger';

@ApiTags('auth')
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

  @Get('session')
  async getSession(
    @Query('clientId') clientId: string,
    @Query('sid') sid: string,
    @Res() res: Response,
  ) {
    console.log('getSession', { clientId, sid });
    if (!sid || !clientId) {
      return res.status(400).json({ ok: false, message: 'Faltan parámetros sid o clientId' });
    }

    try {
      const data = await this.nats.firstValue('auth.session.get', { sid, clientId });
      console.log('Datos de sesión obtenidos:', data);

      if (!data)
        return res.status(404).json({ ok: false, message: 'Sesión no encontrada o expirada' });
      if ((data as any).accessToken) (data as any).accessToken = '***redacted***';
      return res.status(200).json({ ok: true, ...data });
    } catch (err: any) {
      return res
        .status(502)
        .json({ ok: false, message: String(err?.message || 'Fallo al consultar sesión') });
    }
  }

  @ApiOperation({ summary: 'OIDC - Logout SSO (revoca tokens y elimina sid)' })
  @Post('logout')
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
}
