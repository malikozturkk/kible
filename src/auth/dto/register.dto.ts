import { IsString, IsNotEmpty, IsEmail, MinLength, Matches } from 'class-validator';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username must contain only letters, numbers, and underscores',
  })
  username: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, {
    message: 'Password must be at least 8 characters long',
  })
  password: string;
}
