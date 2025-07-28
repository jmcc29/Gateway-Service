import { Injectable } from '@nestjs/common';
import { NatsService} from 'src/common';
import { LoginLdapUserDto } from './dto';

@Injectable()
export class LdapAuthService {
    constructor( private readonly nats: NatsService) {}
    async loginLdapKeycloak(dto: LoginLdapUserDto) {
        const response = await this.nats.firstValue('ldap-auth.login', dto);
        return response;
    }
}
