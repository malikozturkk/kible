import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsString, IsArray, IsBoolean, ValidateNested } from 'class-validator';
import { RandomQuestionPublicDto } from '../../questions/dto/random-question.dto';

export class StepDto {
  @IsInt()
  step: number;

  @IsInt()
  totalSteps: number;

  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  bodyPart?: string;

  @IsOptional()
  @IsString()
  repeat?: string;

  @IsOptional()
  @IsString()
  shortDescription?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  tips?: string[];

  @IsOptional()
  @IsString()
  recitation?: string;

  @IsOptional()
  @IsBoolean()
  isFard?: boolean;

  @IsOptional()
  @IsInt()
  rekat?: number;

  @IsOptional()
  @IsString()
  type?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => RandomQuestionPublicDto)
  randomQuestion?: RandomQuestionPublicDto | null;
}

