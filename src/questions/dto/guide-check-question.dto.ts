import { IsUUID } from 'class-validator';

export class GuideCheckQuestionBodyDto {
  @IsUUID()
  questionId: string;

  @IsUUID()
  optionId: string;
}

export class GuideCheckQuestionResponseDto {
  isCorrect: boolean;
  correctOptionId: string;
  explanation: string | null;
}
