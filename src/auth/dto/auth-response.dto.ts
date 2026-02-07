import { Type } from 'class-transformer';
import { IsString, ValidateNested, IsOptional } from 'class-validator';

export class AuthResponseUserDto {
  @IsString()
  id: string;

  @IsString()
  username: string;

  @IsString()
  @IsOptional()
  phone: string | null;

  @IsString()
  @IsOptional()
  email: string | null;

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
