import { Body, Controller, Get, Logger, Post, Res } from '@nestjs/common';
import { CreateUserDto, LoginUserDto } from './dto';
import { Response } from 'express';
import { NatsService, RecordService } from 'src/common';
import { CurrentUser } from './interfaces/current-user.interface';
import { ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger('AuthController');
  constructor(
    private readonly nats: NatsService,
    private readonly recordService: RecordService,
    private readonly authService: AuthService,
  ) {}

  // @Post('login')
  // async loginUser(@Body() loginUserDto: LoginUserDto, @Res({ passthrough: true }) res: Response) {
  //   this.logger.log({ username: loginUserDto.username });
  //   try {
  //     const data: CurrentUser = await this.nats.firstValue('auth.login', loginUserDto);
  //     const timeShort = 4; // 4 horas
  //     const oneHourMiliseconds = 3600000;
  //     this.logger.log('Login successful');
  //     if (data.user.username != 'pvtbe') {
  //       this.recordService.http('Inicio de sesion exitosa', data.user.username, 1, 1, 'User');
  //     }
  //     res
  //       .cookie('msp', data.access_token, {
  //         path: '/',
  //         httpOnly: true,
  //         sameSite: 'strict',
  //         expires: new Date(Date.now() + timeShort * oneHourMiliseconds),
  //       })
  //       .status(200)
  //       .json({
  //         message: 'Login successful',
  //         user: data.user,
  //       });
  //   } catch (error) {
  //     this.logger.error(error);
  //     res.status(401).json({
  //       error: true,
  //       message: error.message,
  //     });
  //   }
  // }

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
  @Post('login')
  @ApiResponse({
    status: 200,
    description: 'Emitir token para exchange con Keycloak, para acceso a usuarios externos',
  })
  async login(@Body() dto: LoginUserDto) {
    return this.authService.loginKeycloak(dto);
  }
  @Post('register')
  async register(@Body() dto: CreateUserDto) {
    return this.authService.register(dto);
  }

  @Post('identify')
  async identify(@Body() dto: LoginUserDto) {
    return this.authService.identify(dto);
  }
}
