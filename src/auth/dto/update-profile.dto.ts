import { Transform, Type } from 'class-transformer';
import {
  IsString,
  IsOptional,
  Matches,
  MinLength,
  MaxLength,
  ValidateNested,
  IsIn,
  IsEnum,
} from 'class-validator';
import { Madhab } from '@prisma/client';
import { AvatarColorsDto } from './avatar-colors.dto';
import { GENDER_VALUES, type GenderValue } from '../constants/gender.constants';
import { SUPPORTED_LANGUAGES } from '../constants/language.constants';
import {
  CITY_MAX_LENGTH,
  COUNTRY_MAX_LENGTH,
  PLACE_NAME_PATTERN,
} from '../constants/location.constants';
import { trimPlaceName } from '../utils/place-name.util';
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
  @Transform(trimPlaceName)
  @MaxLength(COUNTRY_MAX_LENGTH, { message: 'INVALID_COUNTRY' })
  @Matches(PLACE_NAME_PATTERN, { message: 'INVALID_COUNTRY' })
  country?: string;

  @IsString()
  @IsOptional()
  @Transform(trimPlaceName)
  @MaxLength(CITY_MAX_LENGTH, { message: 'INVALID_CITY' })
  @Matches(PLACE_NAME_PATTERN, { message: 'INVALID_CITY' })
  city?: string;

  @IsOptional()
  @IsEnum(Madhab, { message: 'INVALID_MADHAB' })
  madhab?: Madhab;
}
