import { IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";
export class ExchangeCodeDto {
    @ApiProperty({ description: 'Authorization code' })
    @IsString()
    code: string;

    @ApiProperty({ description: 'State parameter' })
    @IsString()
    state: string;

    @ApiProperty({ description: 'Optional session ID from cookie' })
    @IsString()
    sidCookie?: string;
}
