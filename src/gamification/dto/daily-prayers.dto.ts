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
import { PrayerCategory, PrayerCompletionStatus, PrayerType } from '@prisma/client';

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

  @IsString()
  markWindowEndsAt: string;

  @IsInt()
  xpReward: number;

  @IsInt()
  lateXpReward: number;

  @IsBoolean()
  isCompleted: boolean;

  @IsBoolean()
  canMarkAsCompleted: boolean;

  @IsBoolean()
  isLateWindow: boolean;

  @IsOptional()
  @IsEnum(PrayerCompletionStatus)
  completionStatus: PrayerCompletionStatus | null;

  @IsOptional()
  @IsString()
  completedAt: string | null;

  @IsBoolean()
  streakContribution: boolean;

  @IsOptional()
  @IsInt()
  xpAwarded: number | null;

  @IsOptional()
  @IsString()
  pendingQuizId: string | null;

  @IsBoolean()
  isLocked: boolean;
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

  @IsInt()
  firstOfDayBonusXp: number;

  @IsBoolean()
  firstOfDayBonusAvailable: boolean;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PrayerCardDto)
  prayers: PrayerCardDto[];
}
