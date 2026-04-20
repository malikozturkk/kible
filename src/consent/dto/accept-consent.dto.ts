import { IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { ConsentType } from '@prisma/client';

export class AcceptConsentDto {
  @IsEnum(ConsentType)
  type: ConsentType;

  @IsString()
  @IsNotEmpty()
  version: string;
}
