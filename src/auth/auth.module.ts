import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { NatsService } from 'src/common';
import { AUTH_STORE } from './store/auth.store';
import { MemoryAuthStore } from './store/memory.store';
@Module({
  controllers: [AuthController],
  providers: [AuthService, NatsService, { provide: AUTH_STORE, useClass: MemoryAuthStore }],
  exports: [AuthService],
})
export class AuthModule {}
