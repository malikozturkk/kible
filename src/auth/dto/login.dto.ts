import { IsString, IsNotEmpty, IsOptional, IsEmail, Matches } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsOptional()
  @Matches(/^\+?[1-9]\d{1,14}$/, {
    message: 'Phone must be a valid phone number',
  })
  phone?: string;

  @IsOptional()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email?: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
