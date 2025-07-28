import { ApiProperty } from '@nestjs/swagger';
import { IsDateString, IsOptional, IsString } from 'class-validator';

export class LoginUserDto {
  // @IsString()
  // username: string;

  // @IsString()
  // password: string;
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
