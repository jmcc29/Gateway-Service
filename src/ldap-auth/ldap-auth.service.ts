import { Injectable } from '@nestjs/common';
import { NatsService} from 'src/common';
import { LoginUserDto, LoginLdapUserDto } from './dto';

@Injectable()
export class LdapAuthService {
    constructor( private readonly nats: NatsService) {}
    async loginLdapKeycloak(dto: LoginLdapUserDto) {
        const response = await this.nats.firstValue('ldap-auth.login', dto);
        return response;
    }
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
