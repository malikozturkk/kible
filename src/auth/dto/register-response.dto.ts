import { IsString } from 'class-validator';

export class RegisterResponseDto {
  @IsString()
  tempToken: string;
}
