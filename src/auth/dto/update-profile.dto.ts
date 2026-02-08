import { IsString, IsOptional, Matches } from 'class-validator';

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
}
