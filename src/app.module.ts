import { Module } from '@nestjs/common';
import { AffiliatesModule } from './affiliates/affiliates.module';
import { AuthModule } from './auth/auth.module';
import { GeneralModule } from './general/general.module';
import { PersonsModule } from './persons/persons.module';
import { KioskModule } from './kiosk/kiosk.module';
import { CommonModule } from './common/common.module';
import { DatabaseModule } from './database/database.module';
import { PracticeModule } from './practice/practice.module';
import { OproviderAuthModule } from './oprovider-auth/oprovider-auth.module';

@Module({
  imports: [
    // AuthModule,
    PersonsModule,
    GeneralModule,
    AffiliatesModule,
    KioskModule,
    CommonModule,
    DatabaseModule,
    PracticeModule,
    OproviderAuthModule,
  ],
})
export class AppModule {}
