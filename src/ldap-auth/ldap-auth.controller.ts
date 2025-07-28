import { Controller, Post, Body } from '@nestjs/common';
import { LdapAuthService } from './ldap-auth.service';
import { LoginLdapUserDto } from './dto';
import { ApiTags, ApiResponse } from '@nestjs/swagger';

@ApiTags('Auth LDAP')
@Controller('ldap-auth')
export class LdapAuthController {
  constructor(private readonly ldapAuthService: LdapAuthService) {}

  @Post('login')
  @ApiResponse({
    status: 200,
    description: 'Emitir token de Keycloak conectado a LDAP, para acceso a usuarios internos',
  })
  async loginLdapKeycloak(@Body() dto: LoginLdapUserDto) {
    return this.ldapAuthService.loginLdapKeycloak(dto);
  }
  
}
