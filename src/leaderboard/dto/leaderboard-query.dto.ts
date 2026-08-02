import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, Max, Min } from 'class-validator';
import { LeaderboardMetric, LeaderboardPeriod, LeaderboardScope } from '../enums/leaderboard.enums';
import {
  LEADERBOARD_DEFAULT_LIMIT,
  LEADERBOARD_MAX_LIMIT,
} from '../constants/leaderboard.constants';

export class LeaderboardQueryDto {
  @IsOptional()
  @IsEnum(LeaderboardMetric, { message: 'INVALID_LEADERBOARD_METRIC' })
  metric?: LeaderboardMetric = LeaderboardMetric.STREAK;

  @IsOptional()
  @IsEnum(LeaderboardScope, { message: 'INVALID_LEADERBOARD_SCOPE' })
  scope?: LeaderboardScope = LeaderboardScope.GLOBAL;

  @IsOptional()
  @IsEnum(LeaderboardPeriod, { message: 'INVALID_LEADERBOARD_PERIOD' })
  period?: LeaderboardPeriod = LeaderboardPeriod.ALL_TIME;

  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'INVALID_LEADERBOARD_LIMIT' })
  @Min(1, { message: 'INVALID_LEADERBOARD_LIMIT' })
  @Max(LEADERBOARD_MAX_LIMIT, { message: 'INVALID_LEADERBOARD_LIMIT' })
  limit?: number = LEADERBOARD_DEFAULT_LIMIT;
}
