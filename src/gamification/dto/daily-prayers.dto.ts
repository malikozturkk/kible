import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { PrayerCategory, PrayerType } from '@prisma/client';

export class DailyPrayersQueryDto {
  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lat: number;

  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lng: number;

  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'date must be YYYY-MM-DD' })
  date: string;

  @IsString()
  @MaxLength(64)
  tz: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  method?: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  madhab?: string;
}

export class PrayerCardDto {
  @IsEnum(PrayerType)
  type: PrayerType;

  @IsEnum(PrayerCategory)
  category: PrayerCategory;

  @IsBoolean()
  isObligatory: boolean;

  @IsString()
  scheduledAt: string;

  @IsString()
  windowStartsAt: string;

  @IsString()
  windowEndsAt: string;

  @IsInt()
  xpReward: number;

  @IsBoolean()
  isCompleted: boolean;

  @IsBoolean()
  canMarkAsCompleted: boolean;

  @IsOptional()
  @IsString()
  completedAt: string | null;

  @IsBoolean()
  streakContribution: boolean;

  @IsOptional()
  @IsString()
  pendingQuizId: string | null;
}

export class DailyPrayersResponseDto {
  @IsString()
  date: string;

  @IsString()
  timezone: string;

  @IsBoolean()
  isFriday: boolean;

  @IsBoolean()
  isRamadan: boolean;

  @IsBoolean()
  isEidDay: boolean;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PrayerCardDto)
  prayers: PrayerCardDto[];
}
