import { Type } from 'class-transformer';
import { IsString, ValidateNested, IsOptional, IsObject, IsIn, IsInt } from 'class-validator';
import { Madhab } from '@prisma/client';
import { GENDER_VALUES, type GenderValue } from '../constants/gender.constants';
import { MADHAB_VALUES } from '../constants/madhab.constants';

export class AvatarCustomizationResponseDto {
  @IsIn(GENDER_VALUES)
  gender: GenderValue;

  @IsObject()
  colors: Record<string, string>;

  @IsObject()
  accessories: Record<string, unknown>;
}

export class AuthResponseUserDto {
  @IsInt()
  locationChangeCount: number;

  @IsInt()
  madhabChangeCount: number;

  @IsString()
  id: string;

  @IsString()
  username: string;

  @IsString()
  email: string | null;

  @IsString()
  @IsOptional()
  avatar: string | null;

  @IsString()
  @IsOptional()
  country: string | null;

  @IsString()
  @IsOptional()
  city: string | null;

  @IsIn(MADHAB_VALUES)
  madhab: Madhab;

  @IsString()
  language: string;

  @ValidateNested()
  @Type(() => AvatarCustomizationResponseDto)
  @IsOptional()
  avatarCustomization?: AvatarCustomizationResponseDto;
}

export class AuthResponseDto {
  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;

  @ValidateNested()
  @Type(() => AuthResponseUserDto)
  user: AuthResponseUserDto;
}
