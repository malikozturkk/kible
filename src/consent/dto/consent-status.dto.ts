import { IsString, IsBoolean, IsArray, ValidateNested, IsEnum, IsOptional } from 'class-validator';
import { Type } from 'class-transformer';
import { ConsentType } from '@prisma/client';

export class ConsentStatusItemDto {
  @IsEnum(ConsentType)
  type: ConsentType;

  @IsString()
  @IsOptional()
  acceptedVersion: string | null;

  @IsString()
  currentVersion: string;

  @IsBoolean()
  requiresReaccept: boolean;
}

export class ConsentStatusResponseDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ConsentStatusItemDto)
  items: ConsentStatusItemDto[];

  @IsBoolean()
  blocked: boolean;
}
