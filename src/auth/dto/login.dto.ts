import { IsString, IsNotEmpty, IsEmail } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
