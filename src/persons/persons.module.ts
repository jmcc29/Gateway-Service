import { Module } from '@nestjs/common';
import { PersonsController } from './persons.controller';
import { LdapAuthModule } from 'src/ldap-auth/ldap-auth.module';

@Module({
  controllers: [PersonsController],
  providers: [],
  imports: [LdapAuthModule],
})
export class PersonsModule {}
