import { Body, Controller, Post, UseGuards, UseInterceptors } from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { AuthGuard } from 'src/auth/guards';
import { NatsService, RecordsService } from 'src/common';

interface LegacyAnalysisBody {
  path: string;
  user: string;
  pass: string;
}

@ApiTags('beneficiaries-pvt')
@ApiHeader({ name: 'x-api-key', required: true })
@UseGuards(AuthGuard)
@UseInterceptors(RecordsService)
@Controller('beneficiaries/affiliates/documents')
export class PvtDocumentImportController {
  constructor(private readonly nats: NatsService) {}

  @Post('analysis')
  documentsAnalysis(@Body() body: LegacyAnalysisBody) {
    const { path, user, pass } = body;
    return this.nats.send('affiliate.documentsAnalysis', { path, user, pass });
  }

  @Post('imports')
  documentsImports(@Body() body: object) {
    return this.nats.send('affiliate.documentsImports', body);
  }
}
