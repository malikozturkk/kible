import { IsString, IsNotEmpty } from 'class-validator';

export class ValidateResetTokenDto {
  @IsNotEmpty()
  @IsString()
  userId: string;

  @IsNotEmpty()
  @IsString()
  token: string;
}

