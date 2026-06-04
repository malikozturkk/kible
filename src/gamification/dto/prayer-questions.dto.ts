import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  ValidateNested,
} from 'class-validator';
import { PrayerQuizQuestionStatus, PrayerQuizStatus } from '@prisma/client';
import { PrayerCompletionResultDto } from './gamification-action.dto';

export class QuestionOptionPublicDto {
  @IsString()
  id: string;

  @IsString()
  text: string;
}

export class QuestionPublicDto {
  @IsString()
  id: string;

  @IsString()
  prompt: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => QuestionOptionPublicDto)
  options: QuestionOptionPublicDto[];

  @IsInt()
  orderIndex: number;

  @IsInt()
  timeLimitSeconds: number;

  @IsEnum(PrayerQuizQuestionStatus)
  status: PrayerQuizQuestionStatus;

  @IsOptional()
  @IsString()
  shownAt: string | null;

  @IsOptional()
  @IsString()
  deadlineAt: string | null;

  @IsOptional()
  @IsString()
  answeredAt: string | null;

  @IsOptional()
  @IsString()
  selectedOptionId: string | null;

  @IsOptional()
  @IsBoolean()
  isCorrect: boolean | null;

  @IsBoolean()
  isAnswerable: boolean;

  @IsBoolean()
  canBeAnsweredAgain: boolean;

  @IsBoolean()
  isExpired: boolean;
}

export class PrayerQuestionsResponseDto {
  @IsString()
  quizId: string;

  @IsString()
  expiresAt: string;

  @IsEnum(PrayerQuizStatus)
  quizStatus: PrayerQuizStatus;

  @IsBoolean()
  isLocked: boolean;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => QuestionPublicDto)
  questions: QuestionPublicDto[];
}

export class StartPrayerQuestionParamsDto {
  @IsUUID()
  quizId: string;

  @IsUUID()
  questionId: string;
}

export class StartPrayerQuestionResponseDto {
  @IsString()
  quizId: string;

  @IsEnum(PrayerQuizStatus)
  quizStatus: PrayerQuizStatus;

  @ValidateNested()
  @Type(() => QuestionPublicDto)
  question: QuestionPublicDto;
}

export class AnswerPrayerQuestionBodyDto {
  @IsUUID()
  optionId: string;
}

export enum AnswerResultStatus {
  CORRECT = 'CORRECT',
  INCORRECT = 'INCORRECT',
  EXPIRED = 'EXPIRED',
}

export class AnswerPrayerQuestionResponseDto {
  @IsString()
  quizId: string;

  @IsEnum(PrayerQuizStatus)
  quizStatus: PrayerQuizStatus;

  @IsEnum(AnswerResultStatus)
  result: AnswerResultStatus;

  @IsBoolean()
  isLocked: boolean;

  @ValidateNested()
  @Type(() => QuestionPublicDto)
  question: QuestionPublicDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => PrayerCompletionResultDto)
  prayerCompletion?: PrayerCompletionResultDto;
}
