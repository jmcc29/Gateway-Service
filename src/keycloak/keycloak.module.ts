import { Module } from '@nestjs/common';
import { KeycloakClientService } from './keycloak-client.service';

@Module({
  providers: [KeycloakClientService],
  exports: [KeycloakClientService],
})
export class KeycloakModule {}
