import { IsString, IsOptional, Matches, MinLength } from 'class-validator';

export class UpdateProfileDto {
  @IsString()
  @IsOptional()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'INVALID_USERNAME_FORMAT',
  })
  username?: string;

  @IsString()
  @IsOptional()
  avatar?: string;

  @IsString()
  @IsOptional()
  currentPassword?: string;

  @IsString()
  @IsOptional()
  @MinLength(8, { message: 'PASSWORD_TOO_SHORT' })
  newPassword?: string;
}
