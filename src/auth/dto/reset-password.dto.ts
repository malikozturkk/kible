import { IsString, IsNotEmpty, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsNotEmpty()
  @IsString()
  userId: string;

  @IsNotEmpty()
  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8, { message: 'PASSWORD_TOO_SHORT' })
  newPassword: string;

  @IsNotEmpty()
  @IsString()
  confirmPassword: string;
}

