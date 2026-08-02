import { IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';
import {
  PASSWORD_COMPLEXITY_MESSAGE,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_PATTERN,
} from '../constants/credential.constants';

export class ResetPasswordDto {
  @IsNotEmpty()
  @IsString()
  userId: string;

  @IsNotEmpty()
  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(PASSWORD_MIN_LENGTH, {
    message: 'PASSWORD_TOO_SHORT',
  })
  @MaxLength(PASSWORD_MAX_LENGTH, { message: 'PASSWORD_TOO_LONG' })
  @Matches(PASSWORD_PATTERN, { message: PASSWORD_COMPLEXITY_MESSAGE })
  newPassword: string;

  @IsNotEmpty()
  @IsString()
  confirmPassword: string;
}
