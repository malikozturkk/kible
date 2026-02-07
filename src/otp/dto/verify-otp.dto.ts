import { IsString, IsNotEmpty, Length, Matches } from 'class-validator';

export class VerifyOtpDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'OTP_CODE_MUST_BE_6_DIGITS' })
  code: string;
}
