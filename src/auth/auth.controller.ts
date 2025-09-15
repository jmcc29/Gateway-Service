import {
  Controller,
  Post,
  Body,
  Query,
  Get,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { LoginLdapUserDto } from './dto';
import { ApiTags, ApiResponse, ApiQuery } from '@nestjs/swagger';
import { EvaluatePermissionDto } from './dto/evaluate-permission.dto';
import { Redirect } from '@nestjs/common';

@ApiTags('Auth LDAP')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login')
  @Redirect() // Nest gestionará el 302 usando lo que retornes
  async login(@Query('returnTo') returnTo?: string ) {
    const { url } = await this.authService.buildAuthUrl({ returnTo });
    console.log('Redirigiendo a:', returnTo ?? url);
    // Nest hará el redirect según este objeto (una sola "respuesta")
    return { url, statusCode: 302 };
  }

  @Post('exchange')
  async exchange(@Body() body: { code: string; state: string }) {
    const { sessionId, returnTo } = await this.authService.exchangeCodeAndCreateSession(body);
    return { sessionId, returnTo };
  }

  @Get('session')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión' })
  getSession(@Req() req: Request, @Query('sid') sidFromQuery?: string) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;

    if (!sid) {
      throw new UnauthorizedException('No se encontro ID de sesión');
    }

    try {
      return this.authService.getSessionData(sid);
    } catch (err) {
      throw new UnauthorizedException(err.message);
    }
  }
  
  @Post('logout')
  @ApiQuery({ name: 'sid', required: false, description: 'ID de sesión' })
  logout(@Req() req: Request, @Query('sid') sidFromQuery?: string) {
    const sid = sidFromQuery ?? (req as any).cookies?.sid;
    console.log('Logout de sesión recibido para logout:', sid);
    this.authService.logout(sid);
    return { ok: true };
  }
}
