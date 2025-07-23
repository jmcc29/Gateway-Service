import { Module } from '@nestjs/common';
import { PersonsController } from './persons.controller';
import { OproviderAuthModule } from 'src/oprovider-auth/oprovider-auth.module';

@Module({
  controllers: [PersonsController],
  providers: [],
  imports: [OproviderAuthModule],
})
export class PersonsModule {}
