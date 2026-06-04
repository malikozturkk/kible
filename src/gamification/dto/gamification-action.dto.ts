import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { PrayerType } from '@prisma/client';
import { GamificationActionType } from '../enums/gamification-action.enum';
import { StreakFreezeUsageResultDto } from './streak-freeze-result.dto';

export class GamificationActionRequestDto {
  @IsEnum(GamificationActionType)
  actionType: GamificationActionType;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  clientRequestId?: string;
}

export class PrayerCompletionResultDto {
  @IsString()
  prayerCompletionId: string;

  @IsEnum(PrayerType)
  prayerType: PrayerType;

  @IsString()
  prayerDate: string;

  @IsString()
  completedAt: string;

  @IsInt()
  xpAwarded: number;

  @IsInt()
  xpAfter: number;

  @IsInt()
  level: number;

  @IsBoolean()
  leveledUp: boolean;

  @IsBoolean()
  streakAdvanced: boolean;

  @IsInt()
  currentStreak: number;

  @IsInt()
  longestStreak: number;

  @IsBoolean()
  isFirstOfDay: boolean;
}

export class GamificationActionResponseDto {
  @IsEnum(GamificationActionType)
  actionType: GamificationActionType;

  @IsOptional()
  @ValidateNested()
  @Type(() => StreakFreezeUsageResultDto)
  streakFreezeUsage?: StreakFreezeUsageResultDto;
}
