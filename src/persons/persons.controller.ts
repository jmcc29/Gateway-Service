import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  CreatePersonDto,
  UpdatePersonDto,
  CreatePersonFingerprintDto,
  FilteredPaginationDto,
} from './dto';
import { ApiTags, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { NatsService, RecordService } from 'src/common';
// import { AuthGuard, RoleGuard, Roles} from 'nest-keycloak-connect';
import { ValidTokenGuard, UserPermissionGuard } from 'src/ldap-auth/guards';
import { PermissionProtected, Resource, Scope } from 'src/ldap-auth/decorators';
import { ValidScopes } from 'src/ldap-auth/interfaces/valid-scopes';

@ApiTags('persons')
@ApiBearerAuth('access-token')
@Resource('persons')
@Controller('persons')
export class PersonsController {
  constructor(
    private readonly nats: NatsService,
    private readonly recordService: RecordService,
  ) {}

  // @UseGuards(UserPermissionGuard)
  // @PermissionProtected('persons', 'persons:view-fingerprint-list')
  @Scope('persons:view-fingerprint-list')
  @Get('showListFingerprint')
  @ApiResponse({
    status: 200,
    description: 'Mostrar el listado de huellas digitales',
  })
  async showListFingerprint() {
    return this.nats.send('person.showListFingerprint', {});
  }

  @UseGuards(ValidTokenGuard)
  @Get()
  @ApiResponse({ status: 200, description: 'Mostrar todas las personas' })
  findAllPersons(@Query() filterDto: FilteredPaginationDto) {
    return this.nats.send('person.findAll', filterDto);
  }

  // @UseGuards(UserPermissionGuard)                           // @UseGuards(RoleGuard)
  // @PermissionProtected('persons', 'persons:view-single')    // @Roles({ roles: ['rol1'] })
  @Scope(ValidScopes.persons.viewSingle)
  @Get(':term')
  @ApiResponse({ status: 200, description: 'Mostrar una persona' })
  async findOnePersons(@Param('term') term: string) {
    return this.nats.send('person.findOne', { term, field: 'id' });
  }

  @Scope(ValidScopes.persons.create)
  @Post()
  @ApiResponse({ status: 200, description: 'Añadir una persona' })
  createProduct(@Body() createPersonDto: CreatePersonDto) {
    return this.nats.send('person.create', createPersonDto);
  }

  @Scope(ValidScopes.persons.edit)
  @Patch(':id')
  @ApiResponse({ status: 200, description: 'Editar una persona' })
  patchProduct(@Param('id', ParseIntPipe) id: number, @Body() updatePersonDto: UpdatePersonDto) {
    return this.nats.send('person.update', {
      id,
      ...updatePersonDto,
    });
  }

  @Scope(ValidScopes.persons.delete)
  @Delete(':id')
  @ApiResponse({ status: 200, description: 'Eliminar una persona' })
  deleteProduct(@Param('id') id: string) {
    return this.nats.send('person.delete', { id });
  }

  @Scope(ValidScopes.persons.viewDetails)
  @Get(':uuid/details')
  @ApiResponse({
    status: 200,
    description: 'Muestra una persona con sus relaciones y características adicionales',
  })
  async findPerson(@Param('uuid', new ParseUUIDPipe()) uuid: string) {
    return this.nats.send('person.findOneWithFeatures', { uuid });
  }

  @Scope(ValidScopes.persons.viewBeneficiaries)
  @Get(':personId/beneficiaries')
  @ApiResponse({
    status: 200,
    description: 'Mostrar los beneficiarios de una persona',
  })
  async findBeneficiaries(@Param('personId') id: string) {
    return this.nats.send('person.getBeneficiariesOfAffiliate', { id });
  }

  async showPersonsRelatedToAffiliate(@Param('id') id: string) {
    return this.nats.send('person.showPersonsRelatedToAffiliate', { id });
  }

  @Scope(ValidScopes.persons.viewAffiliates)
  @Get(':personId/affiliates')
  @ApiResponse({
    status: 200,
    description: 'Mostrar los afiliados relacionados con una persona',
  })
  async findAffiliteRelatedWithPerson(@Param('personId') id: string) {
    return this.nats.send('person.findAffiliates', { id });
  }

  @Scope(ValidScopes.persons.createPersonFingerprint)
  @Post('createPersonFingerprint')
  @ApiBody({ type: CreatePersonFingerprintDto }) // Esto especifica que el cuerpo de la solicitud debe ser del tipo CreatePersonFingerprintDto
  @ApiResponse({
    status: 200,
    description: 'Crear una huella digital de una persona',
  })
  @ApiResponse({
    status: 400,
    description: 'Error de validación de entrada',
  })
  @ApiResponse({
    status: 500,
    description: 'Error interno del servidor',
  })
  @ApiResponse({
    status: 200,
    description: 'Crear una huella digital de una persona',
  })
  async createPersonFingerprint(
    @Req() req: any,
    @Body()
    createPersonFingerprintDto: CreatePersonFingerprintDto,
  ) {
    const result = await this.nats.send(
      'person.createPersonFingerprint',
      createPersonFingerprintDto,
    );
    this.recordService.http(
      `Registro de huella [${createPersonFingerprintDto.fingerprints.map((e) => e.fingerprintTypeId)}]`,
      req.user,
      2,
      createPersonFingerprintDto.personId,
      'Person',
    );
    return result;
  }

  @Scope(ValidScopes.persons.viewFingerprint)
  @Get('showPersonFingerprint/:id')
  @ApiResponse({
    status: 200,
    description: 'Mostrar el listado de huellas digitales de una persona',
  })
  async showFingerprintRegistered(@Param('id') id: string) {
    return this.nats.send('person.showFingerprintRegistered', { id });
  }
}
