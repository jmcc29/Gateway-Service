import { IsString, IsDateString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export class LoginUserDto {
  @ApiProperty({ description: 'Username ci' })
  @IsString()
  ci: string;

  @ApiProperty({ description: 'Username birthdate' })
  @IsDateString()
  birthdate: string;

  @IsString()
  @IsOptional()
  celphone: string;
}
