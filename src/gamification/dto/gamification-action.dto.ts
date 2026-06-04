import { Type } from 'class-transformer';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { PrayerType } from '@prisma/client';
import { GamificationActionType } from '../enums/gamification-action.enum';
import { PRAYER_QUIZ_QUESTION_COUNT } from '../constants/prayer.constants';
import { StreakFreezeUsageResultDto } from './streak-freeze-result.dto';

export class QuizAnswerDto {
  @IsUUID()
  questionId: string;

  @IsUUID()
  optionId: string;
}

export class GamificationActionRequestDto {
  @IsEnum(GamificationActionType)
  actionType: GamificationActionType;

  @IsOptional()
  @IsUUID()
  quizId?: string;

  @IsOptional()
  @IsEnum(PrayerType)
  prayerType?: PrayerType;

  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => QuizAnswerDto)
  @ArrayMinSize(PRAYER_QUIZ_QUESTION_COUNT)
  @ArrayMaxSize(PRAYER_QUIZ_QUESTION_COUNT)
  answers?: QuizAnswerDto[];

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
  @Type(() => PrayerCompletionResultDto)
  prayerCompletion?: PrayerCompletionResultDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => StreakFreezeUsageResultDto)
  streakFreezeUsage?: StreakFreezeUsageResultDto;
}
