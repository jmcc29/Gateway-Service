import { Module } from '@nestjs/common';
import { AffiliatesController } from './affiliates.controller';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  controllers: [AffiliatesController],
  providers: [],
  imports: [AuthModule],
})
export class AffiliatesModule {}
