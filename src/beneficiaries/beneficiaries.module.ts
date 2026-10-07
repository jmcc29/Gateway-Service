import { Module } from '@nestjs/common';
import { AffiliatesController } from './affiliates.controller';
import { PersonsController } from './persons.controller';
import { AuthGuard, WebAuthorizationGuard } from 'src/auth/guards';
import { PvtDocumentImportController } from './pvt-document-import.controller';

@Module({
  controllers: [AffiliatesController, PersonsController, PvtDocumentImportController],
  providers: [WebAuthorizationGuard, AuthGuard],
  imports: [],
})
export class BeneficiariesModule {}
