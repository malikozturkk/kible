import { Type } from 'class-transformer';
import { IsString, ValidateNested, IsOptional, IsObject, IsIn } from 'class-validator';
import { GENDER_VALUES, type GenderValue } from '../constants/gender.constants';

export class AvatarCustomizationResponseDto {
  @IsIn(GENDER_VALUES)
  gender: GenderValue;

  @IsObject()
  colors: Record<string, string>;

  @IsObject()
  accessories: Record<string, unknown>;
}

export class AuthResponseUserDto {
  @IsString()
  id: string;

  @IsString()
  username: string;

  @IsString()
  email: string | null;

  @IsString()
  @IsOptional()
  avatar: string | null;

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
