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
  isBroken: boolean;

  @IsInt()
  recoverableStreak: number;

  @IsBoolean()
  atRisk: boolean;

  @IsBoolean()
  canFreezeNow: boolean;

  @IsBoolean()
  freezeWindowExpired: boolean;

  @IsOptional()
  @IsString()
  lastFreezeUsedAt: string | null;
}
