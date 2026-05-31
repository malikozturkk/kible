import { IsBoolean, IsInt, IsOptional, IsString } from 'class-validator';

export class StreakRiskAssessmentDto {
  @IsInt()
  currentStreak: number;

  @IsInt()
  longestStreak: number;

  @IsInt()
  freezesAvailable: number;

  @IsOptional()
  @IsString()
  lastActiveDate: string | null;

  @IsOptional()
  @IsInt()
  daysSinceLastActive: number | null;

  @IsBoolean()
  atRisk: boolean;

  @IsBoolean()
  canFreezeNow: boolean;

  @IsBoolean()
  freezeWindowExpired: boolean;
}
