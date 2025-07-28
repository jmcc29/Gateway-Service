import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsDateString, IsOptional } from 'class-validator';
export class CreateUserDto {
  @ApiProperty()
  @IsString()
  ci: string;

  @ApiProperty()
  @IsString()
  first_name: string;

  @ApiProperty({ description: 'Second name of the user is optional', required: false })
  @IsString()
  @IsOptional()
  second_name: string;

  @ApiProperty()
  @IsString()
  lastname: string;

  @ApiProperty({ description: 'Second lastname of the user is optional', required: false })
  @IsString()
  @IsOptional()
  mother_lastname: string;

  @ApiProperty()
  @IsDateString()
  birthdate: string;
  
  @ApiProperty({ description: 'Cellphone number of the user is optional', required: false })
  @IsString()
  @IsOptional()
  celphone: string;
}
