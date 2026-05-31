import { IsBoolean, IsInt } from 'class-validator';

export class XpAwardResultDto {
  @IsInt()
  xpAwarded: number;

  @IsInt()
  xp: number;

  @IsInt()
  totalXp: number;

  @IsInt()
  level: number;

  @IsBoolean()
  leveledUp: boolean;

  @IsInt()
  progressPercent: number;
}
