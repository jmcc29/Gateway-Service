import { Injectable } from '@nestjs/common';
import { NatsService} from 'src/common';
import { LoginLdapUserDto } from './dto';
import { EvaluatePermissionDto } from './dto/evaluate-permission.dto';

@Injectable()
export class LdapAuthService {
    constructor( private readonly nats: NatsService) {}
    async loginLdapKeycloak(dto: LoginLdapUserDto) {
        const response = await this.nats.firstValue('ldap-auth.login', dto);
        return response;
    }
    async evaluatePermission(dto: EvaluatePermissionDto) {
        const response = await this.nats.firstValue('ldap-auth.evaluatePermission', dto);
        return response;
    }
}
