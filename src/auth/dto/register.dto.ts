import { IsString, IsNotEmpty, IsEmail, MinLength, Matches, IsBoolean, Equals } from 'class-validator';

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

  @IsBoolean({ message: 'TERMS_ACCEPTED_MUST_BE_BOOLEAN' })
  @Equals(true, { message: 'TERMS_NOT_ACCEPTED' })
  termsAccepted: boolean;

  @IsBoolean({ message: 'PRIVACY_POLICY_ACCEPTED_MUST_BE_BOOLEAN' })
  @Equals(true, { message: 'PRIVACY_POLICY_NOT_ACCEPTED' })
  privacyPolicyAccepted: boolean;
}
