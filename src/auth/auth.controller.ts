import { Controller, Post, Body, Query, Get, Res, Req, BadRequestException} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginLdapUserDto } from './dto';
import { ApiTags, ApiResponse } from '@nestjs/swagger';
import { EvaluatePermissionDto } from './dto/evaluate-permission.dto';

@ApiTags('Auth LDAP')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  async login(
    @Res() res: Response,
    @Query('returnTo') returnTo: string, //opcional: a donde volver 
  ) {
    const {url, state} = await this.authService.buildAuthUrl({ returnTo });
    //cookie de estado (defensa adicional)
    res.cookie('oauth_state', state, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: 8 * 60 * 60 * 1000, //8h
      path: '/',
    });
    console.log('Redirigiendo a: ', url);
    //Para pruebas: puedes redirigir al frontend o devolver JSON
    if(!returnTo){
      res.redirect(url);
    }
    // Devuelve tokens solo para debug. En prod evitar enviarlos al navegador
    
    return returnTo ? res.redirect(returnTo) : res.json({ ok: true });
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
    console.log('Estado de cookie:', cookieState, 'Estado de query:', state);
    if (!cookieState || cookieState !== state) {
      throw new BadRequestException('State inválido o ausente');
    }
    const { sessionId, returnTo } =
      await this.authService.exchangeCodeAndCreateSession({ code, state });

    res.cookie('sid', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });

    res.clearCookie('oauth_state');
    return res.redirect('http://localhost:3002/persons');
    // return returnTo ? res.redirect(returnTo) : res.json({ ok: true, sessionId });
  }
}
