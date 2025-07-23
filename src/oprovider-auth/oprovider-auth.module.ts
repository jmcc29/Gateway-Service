import { Module } from '@nestjs/common';
import { OproviderAuthService } from './oprovider-auth.service';
import { OproviderAuthController } from './oprovider-auth.controller';
import { NatsService } from 'src/common';
import { KeycloakConnectModule } from 'nest-keycloak-connect';
import { KeycloakEnvs } from 'src/config';
@Module({
  imports: [KeycloakConnectModule.register({
    authServerUrl: KeycloakEnvs.authServerUrl,
    // authServerUrl: "http://192.168.1.100:8080",
    realm: KeycloakEnvs.realm,
    clientId: KeycloakEnvs.clientId,
    secret: KeycloakEnvs.secret,
  })],
  controllers: [OproviderAuthController],
  providers: [OproviderAuthService, NatsService],
  exports: [KeycloakConnectModule]
})
export class OproviderAuthModule {}
