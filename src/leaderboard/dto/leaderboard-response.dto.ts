import type { AvatarCustomizationResponseDto } from '../../auth/dto/auth-response.dto';
import type {
  LeaderboardMetric,
  LeaderboardPeriod,
  LeaderboardScope,
} from '../enums/leaderboard.enums';

export interface LeaderboardEntryDto {
  rank: number;
  username: string;
  city: string | null;
  avatar: string | null;
  avatarCustomization: AvatarCustomizationResponseDto;
  score: number;
  isCurrentUser: boolean;
}

export interface LeaderboardResponseDto {
  metric: LeaderboardMetric;
  scope: LeaderboardScope;
  period: LeaderboardPeriod;
  city: string | null;
  entries: LeaderboardEntryDto[];
  currentUser: {
    rank: number | null;
    score: number;
    inTopList: boolean;
  };
}
