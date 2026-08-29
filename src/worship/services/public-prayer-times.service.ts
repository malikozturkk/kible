import { HttpStatus, Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { BusinessException } from '../../common/exceptions/business.exception';
import { findTrCity } from '../../auth/constants/tr-cities.constants';
import { resolveTimezone } from '../../common/utils/timezone.util';
import { toHijriLabel } from '../../gamification/helpers/hijri.helper';
import { PRAYER_NAMES, PrayerTimesService } from './prayer-times.service';
import { PrayerName } from '../types/prayer.types';
import {
  PUBLIC_PRAYER_TIMES_DEFAULT_DAYS,
  PUBLIC_PRAYER_TIMES_MAX_DAYS,
  PublicPrayerTimesQueryDto,
} from '../dto/public-prayer-times.dto';
import { PublicPrayerDayDTO, PublicPrayerTimesDTO } from '../types/public-prayer-times.types';
import { DEFAULT_PRAYER_CALCULATION_PROFILE } from '../constants/prayer-calculation.constants';

const DISPLAY_LOCALE = 'tr';

@Injectable()
export class PublicPrayerTimesService {
  constructor(private readonly prayerTimesService: PrayerTimesService) {}

  getPrayerTimes(query: PublicPrayerTimesQueryDto): PublicPrayerTimesDTO {
    const city = findTrCity(query.city);
    if (!city) {
      throw new BusinessException('CITY_NOT_FOUND', HttpStatus.NOT_FOUND);
    }

    const timezone = resolveTimezone(city.latitude, city.longitude);
    const start = query.date
      ? DateTime.fromISO(query.date, { zone: timezone })
      : DateTime.now().setZone(timezone).startOf('day');

    if (!start.isValid) {
      throw new BusinessException('INVALID_DATE', HttpStatus.BAD_REQUEST);
    }

    const dayCount = Math.min(
      query.days ?? PUBLIC_PRAYER_TIMES_DEFAULT_DAYS,
      PUBLIC_PRAYER_TIMES_MAX_DAYS,
    );

    const days: PublicPrayerDayDTO[] = Array.from({ length: dayCount }, (_, offset) =>
      this.buildDay(city.latitude, city.longitude, start.plus({ days: offset }), timezone),
    );

    return {
      city: city.city,
      latitude: city.latitude,
      longitude: city.longitude,
      timezone,
      calculationMethod: DEFAULT_PRAYER_CALCULATION_PROFILE.method,
      calculationProfile: DEFAULT_PRAYER_CALCULATION_PROFILE.key,
      asrShadowRatio: DEFAULT_PRAYER_CALCULATION_PROFILE.asrShadowRatio,
      today: days[0],
      days,
    };
  }

  private buildDay(
    latitude: number,
    longitude: number,
    date: DateTime,
    timezone: string,
  ): PublicPrayerDayDTO {
    const { entries } = this.prayerTimesService.getDay({ latitude, longitude, date, timezone });
    const byKey = new Map(entries.map((entry) => [entry.key, entry.time]));
    const hijri = toHijriLabel(date);

    const times = PRAYER_NAMES.reduce<Record<PrayerName, string>>(
      (acc, key) => {
        const time = byKey.get(key);
        acc[key] = time && time.isValid ? time.toFormat('HH:mm') : '--:--';
        return acc;
      },
      {} as Record<PrayerName, string>,
    );

    const localized = date.setLocale(DISPLAY_LOCALE);

    return {
      date: date.toFormat('yyyy-LL-dd'),
      weekdayName: localized.toFormat('cccc'),
      gregorianLabel: localized.toFormat('d LLLL yyyy'),
      hijriDate: hijri.date,
      hijriMonthName: hijri.monthName,
      times,
    };
  }
}
