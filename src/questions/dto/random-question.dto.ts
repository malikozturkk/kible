import { IsArray, IsString } from 'class-validator';

export class RandomQuestionPublicDto {
  @IsString()
  id: string;

  @IsString()
  question: string;

  @IsArray()
  @IsString({ each: true })
  options: string[];
}
