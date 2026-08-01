import { Type } from 'class-transformer';
import { IsArray, IsString, ValidateNested } from 'class-validator';

export class RandomQuestionOptionDto {
  @IsString()
  id: string;

  @IsString()
  text: string;
}

export class RandomQuestionPublicDto {
  @IsString()
  id: string;

  @IsString()
  question: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RandomQuestionOptionDto)
  options: RandomQuestionOptionDto[];
}
