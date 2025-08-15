import { Controller, Post, Body, Query, Get, Res, Req, BadRequestException } from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginLdapUserDto } from './dto';
import { ApiTags, ApiResponse } from '@nestjs/swagger';
import { EvaluatePermissionDto } from './dto/evaluate-permission.dto';
import { Redirect } from '@nestjs/common';

@ApiTags('Auth LDAP')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  @Redirect() // Nest gestionará el 302 usando lo que retornes
  async login(
    @Res({ passthrough: true }) res: Response, // solo para setear cookies
    @Query('returnTo') returnTo?: string,
  ) {
    const { url, state } = await this.authService.buildAuthUrl({ returnTo });

    res.cookie('oauth_state', state, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });

    console.log('Redirigiendo a:', returnTo ?? url);

    // Nest hará el redirect según este objeto (una sola "respuesta")
    return { url, statusCode: 302 };
  }

  @Get('callback')
  async callback(
    @Req() req: Request,
    @Res() res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
  ) {
    if (!code || !state) {
      throw new BadRequestException('Faltan parámetros code/state');
    }

    const cookieState = (req as any).cookies?.oauth_state;
    if (!cookieState || cookieState !== state) {
      throw new BadRequestException('State inválido o ausente');
    }

    const { sessionId, returnTo } = await this.authService.exchangeCodeAndCreateSession({
      code,
      state,
    });

    res.cookie('sid', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });

    res.clearCookie('oauth_state');

    // 🔹 Redirigir siempre de forma consistente
    if (!returnTo) {
      throw new BadRequestException(
        'Ocurrió un error al redirigir. No se encontró returnTo.',
      );
    }
    return res.redirect(returnTo);
  }
}
