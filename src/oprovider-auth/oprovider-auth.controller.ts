import { Controller, Post, Body } from '@nestjs/common';
import { OproviderAuthService } from './oprovider-auth.service';
import { LoginUserDto, LoginLdapUserDto } from './dto';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Oprovider')
@Controller('oprovider')
export class OproviderAuthController {
  constructor(private readonly oproviderAuthService: OproviderAuthService) {}

  @Post('loginLdapKeycloak')
  async loginLdapKeycloak(@Body() dto: LoginLdapUserDto) {
    return this.oproviderAuthService.loginLdapKeycloak(dto);
  }

  @Post('login')
  async login(@Body() dto: LoginUserDto) {
    return this.oproviderAuthService.login(dto);
  }

  @Post('register')
  async register(@Body() dto: LoginUserDto) {
    return this.oproviderAuthService.register(dto);
  }

  @Post('identify')
  async identify(@Body() dto: LoginUserDto) {
    return this.oproviderAuthService.identify(dto);
  }
}
