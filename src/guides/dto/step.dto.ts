import { IsInt, IsOptional, IsString, IsArray, IsBoolean } from 'class-validator';

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
}

