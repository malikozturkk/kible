import { UserXpResponseDto } from '../dto/user-xp.dto';

const BASE_XP = 40;
const LINEAR_FACTOR = 10;
const CURVE_FACTOR = 2;

export class LevelCalculator {
  static requiredXp(level: number): number {
    if (level <= 0) return 0;
    return BASE_XP + level * LINEAR_FACTOR + level * level * CURVE_FACTOR;
  }

  static cumulativeXpForLevel(level: number): number {
    if (level <= 0) return 0;
    let total = 0;
    for (let l = 1; l <= level; l++) {
      total += LevelCalculator.requiredXp(l);
    }
    return total;
  }

  static getBadgeKey(level: number): string {
    if (level < 10) return 'steadfast_beginner';
    if (level < 20) return 'prayer_committed';
    if (level < 30) return 'consistent_worshipper';
    if (level < 40) return 'dedicated_servant';
    if (level < 50) return 'steadfast_believer';
    if (level < 75) return 'mindful_devotee';
    if (level < 100) return 'spiritual_guardian';
    if (level < 150) return 'excellence_in_prayer';
    if (level < 200) return 'community_inspiration';
    return 'legacy_of_devotion';
  }

  static computeLevelFromXp(xp: number): UserXpResponseDto {
    const safeXp = Math.max(0, Math.floor(xp || 0));

    let level = 0;
    let nextLevel = 1;
    while (true) {
      const nextThreshold = LevelCalculator.cumulativeXpForLevel(nextLevel);
      if (safeXp >= nextThreshold) {
        level = nextLevel;
        nextLevel += 1;
      } else {
        break;
      }
    }

    const totalForCurrentLevel = LevelCalculator.cumulativeXpForLevel(level);
    const totalForNextLevel = LevelCalculator.cumulativeXpForLevel(level + 1);
    const currentLevelXp = safeXp - totalForCurrentLevel;
    const xpToNextLevel = Math.max(0, totalForNextLevel - safeXp);

    const badgeKey = LevelCalculator.getBadgeKey(Math.max(1, level));
    const totalXpForNextLevel = LevelCalculator.requiredXp(level + 1);
    const progress =
      totalXpForNextLevel > 0 ? Math.floor((currentLevelXp / totalXpForNextLevel) * 100) : 0;
    const progressPercent = Math.max(0, Math.min(100, progress));

    return {
      xp: safeXp,
      level,
      currentLevelXp,
      xpToNextLevel,
      totalXpForNextLevel,
      badgeKey,
      progressPercent,
    };
  }
}
