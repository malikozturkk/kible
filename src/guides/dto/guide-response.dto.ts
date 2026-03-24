import { IsArray, IsInt, IsOptional, IsString } from 'class-validator';
import { StepDto } from './step.dto';

export class GuideResponseDto {
  @IsString()
  id: string;

  @IsString()
  title: string;

  @IsInt()
  totalSteps: number;

  @IsOptional()
  @IsInt()
  totalRakats?: number;

  @IsOptional()
  @IsInt()
  sunnahBefore?: number;

  @IsOptional()
  @IsInt()
  sunnahAfter?: number;

  @IsArray()
  steps: StepDto[];
}
