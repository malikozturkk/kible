import { Type } from 'class-transformer';
import {
  IsString,
  IsOptional,
  Matches,
  MinLength,
  MaxLength,
  ValidateNested,
  IsIn,
  IsEnum,
  IsNumber,
  Min,
  Max,
} from 'class-validator';
import { Madhab } from '@prisma/client';
import { AvatarColorsDto } from './avatar-colors.dto';
import { GENDER_VALUES, type GenderValue } from '../constants/gender.constants';
import { SUPPORTED_LANGUAGES } from '../constants/language.constants';

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

  @IsString()
  @IsOptional()
  @IsIn(SUPPORTED_LANGUAGES, { message: 'INVALID_LANGUAGE' })
  language?: string;

  @IsString()
  @IsOptional()
  @MaxLength(64)
  country?: string;

  @IsString()
  @IsOptional()
  @MaxLength(85)
  city?: string;

  @Type(() => Number)
  @IsOptional()
  @IsNumber({ maxDecimalPlaces: 8 }, { message: 'INVALID_LATITUDE' })
  @Min(-90, { message: 'INVALID_LATITUDE' })
  @Max(90, { message: 'INVALID_LATITUDE' })
  latitude?: number;

  @Type(() => Number)
  @IsOptional()
  @IsNumber({ maxDecimalPlaces: 8 }, { message: 'INVALID_LONGITUDE' })
  @Min(-180, { message: 'INVALID_LONGITUDE' })
  @Max(180, { message: 'INVALID_LONGITUDE' })
  longitude?: number;

  @IsOptional()
  @IsEnum(Madhab, { message: 'INVALID_MADHAB' })
  madhab?: Madhab;
}
