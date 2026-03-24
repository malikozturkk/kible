import { IsString, MinLength } from 'class-validator';

export class GuideCheckQuestionBodyDto {
  @IsString()
  @MinLength(1)
  questionId: string;

  @IsString()
  answer: string;
}

export class GuideCheckQuestionResponseDto {
  isCorrect: boolean;
}
