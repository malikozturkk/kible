import { IsArray, IsBoolean, IsInt, IsString } from 'class-validator';

export class StreakFreezeUsageResultDto {
  @IsInt()
  currentStreak: number;

  @IsInt()
  longestStreak: number;

  @IsInt()
  freezesRemaining: number;

  @IsArray()
  @IsString({ each: true })
  protectedDates: string[];

  @IsBoolean()
  alreadyApplied: boolean;
}
