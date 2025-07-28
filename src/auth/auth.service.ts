import { Injectable } from '@nestjs/common';
import { NatsService } from 'src/common';
import { LoginUserDto, CreateUserDto } from './dto';

@Injectable()
export class AuthService {
  constructor(private readonly nats: NatsService) {}
  async loginKeycloak(dto: LoginUserDto) {
    const response = await this.nats.firstValue('auth.login', dto);
    return response;
  }
  async register(dto: CreateUserDto) {
    const response = await this.nats.firstValue('auth.register', dto);
    return response;
  }
  async identify(dto: LoginUserDto) {
    const response = await this.nats.firstValue('auth.identify', dto);
    return response;
  }
}
