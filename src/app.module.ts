import { Module } from '@nestjs/common';
import { AffiliatesModule } from './affiliates/affiliates.module';
import { AuthModule } from './auth/auth.module';
import { GeneralModule } from './general/general.module';
import { PersonsModule } from './persons/persons.module';
import { KioskModule } from './kiosk/kiosk.module';
import { CommonModule } from './common/common.module';
import { DatabaseModule } from './database/database.module';
import { PracticeModule } from './practice/practice.module';

@Module({
  imports: [
    AuthModule,
    PersonsModule,
    GeneralModule,
    AffiliatesModule,
    KioskModule,
    CommonModule,
    DatabaseModule,
    PracticeModule,
  ],
})
export class AppModule {}
