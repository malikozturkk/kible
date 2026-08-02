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
import {
  PASSWORD_COMPLEXITY_MESSAGE,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_PATTERN,
  USERNAME_MAX_LENGTH,
  USERNAME_MIN_LENGTH,
  USERNAME_PATTERN,
} from '../constants/credential.constants';

export class UpdateProfileDto {
  @IsString()
  @IsOptional()
  @MinLength(USERNAME_MIN_LENGTH, { message: 'USERNAME_TOO_SHORT' })
  @MaxLength(USERNAME_MAX_LENGTH, { message: 'USERNAME_TOO_LONG' })
  @Matches(USERNAME_PATTERN, {
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
  @MinLength(PASSWORD_MIN_LENGTH, { message: 'PASSWORD_TOO_SHORT' })
  @MaxLength(PASSWORD_MAX_LENGTH, { message: 'PASSWORD_TOO_LONG' })
  @Matches(PASSWORD_PATTERN, { message: PASSWORD_COMPLEXITY_MESSAGE })
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
