export enum LeaderboardMetric {
  XP = 'XP',
  STREAK = 'STREAK',
  PRAYERS = 'PRAYERS',
}

export enum LeaderboardScope {
  GLOBAL = 'GLOBAL',
  CITY = 'CITY',
  FOLLOWING = 'FOLLOWING',
}

export enum LeaderboardPeriod {
  ALL_TIME = 'ALL_TIME',
  WEEKLY = 'WEEKLY',
  MONTHLY = 'MONTHLY',
}

export const LEADERBOARD_METRIC_VALUES = Object.values(LeaderboardMetric);
export const LEADERBOARD_SCOPE_VALUES = Object.values(LeaderboardScope);
export const LEADERBOARD_PERIOD_VALUES = Object.values(LeaderboardPeriod);
