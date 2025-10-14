import { IsString, IsUrl } from 'class-validator';

export class LoginStartDto {
  @IsUrl({ require_tld: false })
  returnTo!: string;

  @IsString()
  clientId!: string;
}

export type LoginStartRes = {
  ok: true;
  url: string;
  state: string;
};
