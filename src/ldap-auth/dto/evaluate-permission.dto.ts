import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';
export class EvaluatePermissionDto {
  @ApiProperty({ description: 'Keycloak token' })
  @IsString()
  accessToken: string;

  @ApiProperty({ description: 'Resource' })
  @IsString()
  resource: string;

  @ApiProperty({ description: 'Scope of resource' })
  @IsString()
  scope: string;
}
