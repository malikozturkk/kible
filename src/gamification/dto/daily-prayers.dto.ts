import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  ValidateNested,
} from 'class-validator';
import { PrayerCategory, PrayerType } from '@prisma/client';

export class DailyPrayersQueryDto {
  @IsString()
  @Matches(/^\d{4}-\d{2}-\d{2}$/, { message: 'date must be YYYY-MM-DD' })
  date: string;
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
