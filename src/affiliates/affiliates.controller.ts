import {
  Controller,
  Get,
  Param,
  Post,
  UploadedFile,
  UseInterceptors,
  Res,
  Req,
  UseGuards,
  Body,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { FileRequiredPipe, NatsService, RecordService } from 'src/common';
import { Response } from 'express';
import { ValidTokenGuard } from 'src/auth/guards';
@ApiTags('affiliates')
@Controller('affiliates')
export class AffiliatesController {
  constructor(
    private readonly nats: NatsService,
    private readonly recordService: RecordService,
  ) {}

  @Get(':affiliateId')
  @ApiResponse({ status: 200, description: 'Mostrar datos del afiliado' })
  async findOneData(@Param('affiliateId') affiliateId: string) {
    return this.nats.send('affiliate.findOneData', { affiliateId });
  }

  @Post(':affiliateId/document/:procedureDocumentId/createOrUpdate')
  @ApiOperation({ summary: 'Enlazar y Subir Documento del Afiliado' })
  @ApiResponse({ status: 200, description: 'El documento fue subido exitosamente.' })
  @ApiResponse({
    status: 400,
    description: 'El archivo PDF es obligatorio o el archivo no es válido.',
  })
  @ApiResponse({ status: 500, description: 'Error interno del servidor.' })
  @ApiParam({ name: 'affiliateId', description: 'ID del afiliado', type: Number, example: 123 })
  @ApiParam({
    name: 'procedureDocumentId',
    description: 'ID del del documento',
    type: Number,
    example: 456,
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Archivo PDF del documento del afiliado',
    type: 'multipart/form-data',
    required: true,
    schema: {
      type: 'object',
      properties: {
        documentPdf: {
          type: 'string',
          format: 'binary',
          description: 'Archivo PDF a subir',
        },
      },
    },
  })
  @UseGuards(ValidTokenGuard)
  @UseInterceptors(FileInterceptor('documentPdf'))
  async createOrUpdateDocument(
    @Req() req: any,
    @Param('affiliateId') affiliateId: string,
    @Param('procedureDocumentId') procedureDocumentId: string,
    @UploadedFile(new FileRequiredPipe()) documentPdf: Express.Multer.File,
  ) {
    this.recordService.http(
      `Registro de documento [${procedureDocumentId}]`,
      req.user,
      2,
      +affiliateId,
      'Affiliate',
    );
    return this.nats.send('affiliate.createOrUpdateDocument', {
      affiliateId,
      procedureDocumentId,
      documentPdf,
    });
  }

  @Get(':affiliateId/documents')
  @ApiResponse({ status: 200, description: 'Mostrar Documentos del Afiliado' })
  async showDocuments(@Param('affiliateId') affiliateId: string) {
    return this.nats.send('affiliate.showDocuments', { affiliateId });
  }

  @Get(':affiliateId/documents/:procedureDocumentId')
  @ApiResponse({ status: 200, description: 'Buscar el documento del Afiliado' })
  async findDocument(
    @Param('affiliateId') affiliateId: string,
    @Param('procedureDocumentId') procedureDocumentId: string,
    @Res() res: Response,
  ) {
    const documentPdf = await this.nats.firstValue('affiliate.findDocument', {
      affiliateId,
      procedureDocumentId,
    });

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${affiliateId}${procedureDocumentId}.pdf"`,
    });

    res.send(Buffer.from(documentPdf, 'base64'));
  }

  @UseGuards(ValidTokenGuard)
  @Get(':affiliateId/modality/:modalityId/collate')
  @ApiResponse({
    status: 200,
    description: 'Cotejar documentos del Afiliado con los documentos requeridos de la modalidad',
  })
  async collateDocuments(
    @Param('affiliateId') affiliateId: string,
    @Param('modalityId') modalityId: string,
  ) {
    return this.nats.send('affiliate.collateDocuments', { affiliateId, modalityId });
  }

  @Post('documents/analysis')
  async documentsAnalysis(@Body() body: { path: string; user: string; pass: string }) {
    const { path, user, pass } = body;

    this.recordService.http(
      `Realizo el análisis de documentos en la ruta ${path}`,
      user,
      1,
      1,
      'User',
    );

    return this.nats.send('affiliate.documentsAnalysis', { path, user, pass });
  }

  @Post('documents/imports')
  async documentsImports(@Body() body: object) {
    return this.nats.send('affiliate.documentsImports', body);
  }
}
