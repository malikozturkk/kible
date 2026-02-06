import { IsString, IsOptional, Matches } from 'class-validator';

export class UpdateProfileDto {
  @IsString()
  @IsOptional()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username must contain only letters, numbers, and underscores',
  })
  username?: string;

  @IsString()
  @IsOptional()
  avatar?: string;
}
