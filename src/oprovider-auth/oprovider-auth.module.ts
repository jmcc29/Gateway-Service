import { Module } from '@nestjs/common';
import { OproviderAuthService } from './oprovider-auth.service';
import { OproviderAuthController } from './oprovider-auth.controller';
import { NatsService } from 'src/common';

@Module({
  controllers: [OproviderAuthController],
  providers: [OproviderAuthService, NatsService],
})
export class OproviderAuthModule {}
