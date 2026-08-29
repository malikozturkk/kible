import { IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class RefreshTokenDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  refreshToken?: string;
}
