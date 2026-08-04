import {
  IsString,
  IsNotEmpty,
  IsEmail,
  MinLength,
  MaxLength,
  Matches,
  IsBoolean,
  Equals,
  IsEnum,
  IsNumber,
  Min,
  Max,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { Gender, Madhab } from '@prisma/client';
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

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(USERNAME_MIN_LENGTH, { message: 'USERNAME_TOO_SHORT' })
  @MaxLength(USERNAME_MAX_LENGTH, { message: 'USERNAME_TOO_LONG' })
  @Matches(USERNAME_PATTERN, {
    message: 'INVALID_USERNAME_FORMAT',
  })
  username: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(PASSWORD_MIN_LENGTH, {
    message: 'PASSWORD_TOO_SHORT',
  })
  @MaxLength(PASSWORD_MAX_LENGTH, { message: 'PASSWORD_TOO_LONG' })
  @Matches(PASSWORD_PATTERN, { message: PASSWORD_COMPLEXITY_MESSAGE })
  password: string;

  @IsEnum(Gender, { message: 'INVALID_GENDER' })
  gender: Gender;

  @IsString()
  @Transform(trimPlaceName)
  @IsNotEmpty({ message: 'COUNTRY_REQUIRED' })
  @MaxLength(COUNTRY_MAX_LENGTH, { message: 'INVALID_COUNTRY' })
  @Matches(PLACE_NAME_PATTERN, { message: 'INVALID_COUNTRY' })
  country: string;

  @IsString()
  @Transform(trimPlaceName)
  @IsNotEmpty({ message: 'CITY_REQUIRED' })
  @MaxLength(CITY_MAX_LENGTH, { message: 'INVALID_CITY' })
  @Matches(PLACE_NAME_PATTERN, { message: 'INVALID_CITY' })
  city: string;

  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 }, { message: 'INVALID_LATITUDE' })
  @Min(-90, { message: 'INVALID_LATITUDE' })
  @Max(90, { message: 'INVALID_LATITUDE' })
  latitude: number;

  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 }, { message: 'INVALID_LONGITUDE' })
  @Min(-180, { message: 'INVALID_LONGITUDE' })
  @Max(180, { message: 'INVALID_LONGITUDE' })
  longitude: number;

  @IsEnum(Madhab, { message: 'INVALID_MADHAB' })
  madhab: Madhab;

  @IsString()
  @Matches(/^[a-z]{2}(-[A-Z]{2})?$/, { message: 'INVALID_LANGUAGE' })
  language: string;

  @IsBoolean({ message: 'TERMS_ACCEPTED_MUST_BE_BOOLEAN' })
  @Equals(true, { message: 'TERMS_NOT_ACCEPTED' })
  termsAccepted: boolean;

  @IsBoolean({ message: 'PRIVACY_POLICY_ACCEPTED_MUST_BE_BOOLEAN' })
  @Equals(true, { message: 'PRIVACY_POLICY_NOT_ACCEPTED' })
  privacyPolicyAccepted: boolean;
}
