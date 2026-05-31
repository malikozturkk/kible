import { AvatarCustomizationPayload } from '../../auth/utils/avatar-config.util';

export interface PrayerBreakdownDto {
  fajr: number;
  dhuhr: number;
  asr: number;
  maghrib: number;
  isha: number;
  jumuah: number;
  tarawih: number;
  eidFitr: number;
  eidAdha: number;
}

export interface PublicLevelStatsDto {
  level: number;
  badgeKey: string;
  progressPercent: number;
}

export interface SelfLevelStatsDto extends PublicLevelStatsDto {
  xp: number;
  totalXp: number;
  currentLevelXp: number;
  xpToNextLevel: number;
  totalXpForNextLevel: number;
}

export interface PublicStreakStatsDto {
  current: number;
  longest: number;
}

export interface SelfStreakStatsDto extends PublicStreakStatsDto {
  freezeCount: number;
  lastActiveDate: string | null;
}

export interface PublicPrayerStatsDto {
  totalCompleted: number;
  breakdown: PrayerBreakdownDto;
}

export interface SelfPrayerStatsDto extends PublicPrayerStatsDto {
  lastCompletedAt: string | null;
  quiz: {
    totalAttempts: number;
    passed: number;
    failed: number;
    accuracyPercent: number;
  };
}

export interface SocialStatsDto {
  followerCount: number;
  followingCount: number;
}

export interface SelfStatsResponseDto {
  username: string;
  avatarCustomization: AvatarCustomizationPayload;
  joinedAt: string;
  level: SelfLevelStatsDto;
  streak: SelfStreakStatsDto;
  prayers: SelfPrayerStatsDto;
  social: SocialStatsDto;
}

export interface PublicStatsResponseDto {
  username: string;
  avatarCustomization: AvatarCustomizationPayload;
  joinedAt: string;
  level: PublicLevelStatsDto;
  streak: PublicStreakStatsDto;
  prayers: PublicPrayerStatsDto;
  social: SocialStatsDto;
  isSelf: boolean;
}
