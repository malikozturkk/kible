import { IsArray, IsInt, IsString } from 'class-validator';
import { StepDto } from './step.dto';

export class GuideResponseDto {
  @IsString()
  id: string;

  @IsString()
  title: string;

  @IsInt()
  totalSteps: number;

  @IsArray()
  steps: StepDto[];
}

