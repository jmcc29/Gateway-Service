import { IsString, IsDateString, IsOptional } from 'class-validator';
export class CreateUserDto {
  @IsString()
  ci: string;

  @IsString()
  first_name: string;

  @IsString()
  second_name: string;

  @IsString()
  lastname: string;

  @IsString()
  @IsOptional()
  mother_lastname: string;

  @IsDateString()
  birthdate: string;

  @IsString()
  @IsOptional()
  celphone: string;
}
