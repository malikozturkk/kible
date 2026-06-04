import { Type } from 'class-transformer';
import { IsArray, IsString, ValidateNested } from 'class-validator';

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
