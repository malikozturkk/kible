import { IsInt, IsOptional, IsString } from 'class-validator';

export class UserXpResponseDto {
  @IsInt()
  xp: number;

  @IsInt()
  @IsOptional()
  totalXp?: number;

  @IsInt()
  level: number;

  @IsInt()
  currentLevelXp: number;

  @IsInt()
  xpToNextLevel: number;

  @IsInt()
  totalXpForNextLevel: number;

  @IsString()
  badgeKey: string;

  @IsInt()
  progressPercent: number;
}
