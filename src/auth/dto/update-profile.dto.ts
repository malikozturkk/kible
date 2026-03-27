import { Type } from 'class-transformer';
import { IsString, IsOptional, Matches, MinLength, ValidateNested, IsIn } from 'class-validator';
import { AvatarColorsDto } from './avatar-colors.dto';
import { GENDER_VALUES, type GenderValue } from '../constants/gender.constants';

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

  @IsOptional()
  @IsIn(GENDER_VALUES, { message: 'INVALID_GENDER' })
  gender?: GenderValue;

  @ValidateNested()
  @Type(() => AvatarColorsDto)
  @IsOptional()
  avatarColors?: AvatarColorsDto;

  @IsString()
  @IsOptional()
  currentPassword?: string;

  @IsString()
  @IsOptional()
  @MinLength(8, { message: 'PASSWORD_TOO_SHORT' })
  newPassword?: string;
}
