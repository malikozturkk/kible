import { Type } from 'class-transformer';
import {
  IsArray,
  IsNumber,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';

export class PrayerQuestionsQueryDto {
  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lat: number;

  @Type(() => Number)
  @IsNumber({ maxDecimalPlaces: 8 })
  lng: number;

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
}

export class PrayerQuestionsResponseDto {
  @IsString()
  quizId: string;

  @IsString()
  expiresAt: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => QuestionPublicDto)
  questions: QuestionPublicDto[];
}
