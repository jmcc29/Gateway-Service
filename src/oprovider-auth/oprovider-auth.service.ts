import { Injectable } from '@nestjs/common';
import { NatsService} from 'src/common';
import { LoginUserDto } from './dto/login-user.dto';

@Injectable()
export class OproviderAuthService {
    constructor( private readonly nats: NatsService) {}
    async login(dto: LoginUserDto) {
        const response = await this.nats.firstValue('auth.login', dto);
        return response;
    }
    async register(dto: LoginUserDto) {
        const response = await this.nats.firstValue('auth.register', dto);
        return response;
    }
    async identify(dto: LoginUserDto) {
        const response = await this.nats.firstValue('auth.identify', dto);
        return response;
    }
}
