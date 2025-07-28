import { Module } from '@nestjs/common';
import { LdapAuthService } from './ldap-auth.service';
import { LdapAuthController } from './ldap-auth.controller';
import { NatsService } from 'src/common';
import {
  KeycloakConnectModule,
  PolicyEnforcementMode,
  TokenValidation,
} from 'nest-keycloak-connect';
import { KeycloakEnvs } from 'src/config';
@Module({
  imports: [
    KeycloakConnectModule.register({
      authServerUrl: KeycloakEnvs.authServerUrl,
      // authServerUrl: "http://192.168.1.100:8080",
      realm: KeycloakEnvs.realm,
      clientId: KeycloakEnvs.clientId,
      secret: KeycloakEnvs.secret,
      // policyEnforcement: PolicyEnforcementMode.ENFORCING,
      // tokenValidation: TokenValidation.ONLINE,
    }),
  ],
  controllers: [LdapAuthController],
  providers: [LdapAuthService, NatsService],
  exports: [KeycloakConnectModule],
})
export class LdapAuthModule {}
