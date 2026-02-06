import { Type } from 'class-transformer';
import { IsString, ValidateNested, IsOptional } from 'class-validator';

export class AuthResponseUserDto {
  @IsString()
  id: string;

  @IsString()
  username: string;

  @IsString()
  phone: string;

  @IsString()
  @IsOptional()
  avatar: string | null;
}

export class AuthResponseDto {
  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;

  @ValidateNested()
  @Type(() => AuthResponseUserDto)
  user: AuthResponseUserDto;
}
