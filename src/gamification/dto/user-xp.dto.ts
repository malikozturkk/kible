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
  currentLevelXp: number; // Mevcut level içindeki XP

  @IsInt()
  xpToNextLevel: number; // Sonraki level için gereken XP

  @IsInt()
  totalXpForNextLevel: number; // Sonraki level için gereken toplam XP

  @IsString()
  badgeKey: string;

  @IsInt()
  progressPercent: number; // Sonraki level için % kaç doldu
}
