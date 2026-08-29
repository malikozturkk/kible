import { Type } from 'class-transformer';
import { IsOptional, IsString, ValidateNested } from 'class-validator';
import { AuthResponseUserDto } from './auth-response.dto';

export class RotatedTokensDto {
  @IsString()
  accessToken: string;

  @IsString()
  @IsOptional()
  refreshToken?: string;
}

export class UpdateProfileResponseDto extends AuthResponseUserDto {
  @ValidateNested()
  @Type(() => RotatedTokensDto)
  @IsOptional()
  tokens?: RotatedTokensDto;
}
