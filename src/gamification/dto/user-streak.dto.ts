import { Type } from 'class-transformer';
import { IsInt, IsOptional, IsDate } from 'class-validator';

export class UserStreakResponseDto {
  @IsInt()
  currentStreak: number;

  @IsInt()
  longestStreak: number;

  @IsInt()
  streakFreezeCount: number;

  @IsOptional()
  @Type(() => Date)
  @IsDate()
  lastActiveDate?: Date | null;
}
