import { CalculationMethod, Madhab as AdhanMadhab } from 'adhan';
import type { Madhab as UserMadhab } from '@prisma/client';

export type CalculationMethodKey = keyof typeof CalculationMethod;
export type AsrShadowRatio = 1 | 2;
export type PrayerCalculationProfileKey = 'DIYANET';
export interface PrayerCalculationProfile {
  key: PrayerCalculationProfileKey;
  method: CalculationMethodKey;
  asrShadowRatio: AsrShadowRatio;
}

export const DIYANET_PROFILE: PrayerCalculationProfile = {
  key: 'DIYANET',
  method: 'Turkey',
  asrShadowRatio: 1,
};

export const PRAYER_CALCULATION_PROFILE_BY_MADHAB: Record<UserMadhab, PrayerCalculationProfile> = {
  SHAFI: DIYANET_PROFILE,
  HANAFI: DIYANET_PROFILE,
};

export const DEFAULT_PRAYER_CALCULATION_PROFILE = DIYANET_PROFILE;

export function resolvePrayerCalculationProfile(
  madhab?: UserMadhab | null,
): PrayerCalculationProfile {
  if (!madhab) return DEFAULT_PRAYER_CALCULATION_PROFILE;
  return PRAYER_CALCULATION_PROFILE_BY_MADHAB[madhab] ?? DEFAULT_PRAYER_CALCULATION_PROFILE;
}

export function toAdhanMadhab(
  ratio: AsrShadowRatio,
): (typeof AdhanMadhab)[keyof typeof AdhanMadhab] {
  return ratio === 2 ? AdhanMadhab.Hanafi : AdhanMadhab.Shafi;
}
