import { Module } from '@nestjs/common';
import { PersonsController } from './persons.controller';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  controllers: [PersonsController],
  providers: [],
  imports: [AuthModule],
})
export class PersonsModule {}
