import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResumeRegistrationDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'INVALID_EMAIL_FORMAT' })
  email: string;
}
