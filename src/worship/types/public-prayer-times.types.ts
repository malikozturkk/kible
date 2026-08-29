import type {
  AsrShadowRatio,
  CalculationMethodKey,
  PrayerCalculationProfileKey,
} from '../constants/prayer-calculation.constants';
import type { PrayerName } from './prayer.types';

export interface PublicPrayerDayDTO {
  date: string;
  weekdayName: string;
  gregorianLabel: string;
  hijriDate: string;
  hijriMonthName: string;
  times: Record<PrayerName, string>;
}

export interface PublicPrayerTimesDTO {
  city: string;
  latitude: number;
  longitude: number;
  timezone: string;
  calculationMethod: CalculationMethodKey;
  calculationProfile: PrayerCalculationProfileKey;
  asrShadowRatio: AsrShadowRatio;
  today: PublicPrayerDayDTO;
  days: PublicPrayerDayDTO[];
}
