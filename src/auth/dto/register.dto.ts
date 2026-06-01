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
import { Type } from 'class-transformer';
import { Gender, Madhab } from '@prisma/client';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'INVALID_USERNAME_FORMAT',
  })
  username: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'PASSWORD_TOO_SHORT',
  })
  password: string;

  @IsEnum(Gender, { message: 'INVALID_GENDER' })
  gender: Gender;

  @IsString()
  @IsNotEmpty({ message: 'COUNTRY_REQUIRED' })
  @MaxLength(64)
  country: string;

  @IsString()
  @IsNotEmpty({ message: 'CITY_REQUIRED' })
  @MaxLength(85)
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
