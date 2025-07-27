import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';
export class LoginLdapUserDto {
  @ApiProperty({ description: 'Username for LDAP login' })
  @IsString()
  username: string;

  @ApiProperty({ description: 'Password for LDAP login' })
  @IsString()
  password: string;
}
