import { DateTime } from 'luxon';
import { PrayerTimes } from 'adhan';
import { PrayerType } from '@prisma/client';
import { PrayerSlot } from '../types/gamification.types';
import {
  PRAYER_WINDOW_AFTER_MINUTES,
  PRAYER_WINDOW_BEFORE_MINUTES,
  getPrayerBaseXp,
  getPrayerMetadata,
} from '../constants/prayer.constants';
import { HijriDate, isEidAdha, isEidFitr, isFriday, isRamadan } from './hijri.helper';

export function buildPrayerSlots(args: {
  todayPrayerTimes: PrayerTimes;
  zonedDate: DateTime;
  timezone: string;
  hijri: HijriDate;
}): PrayerSlot[] {
  const { todayPrayerTimes, zonedDate, timezone, hijri } = args;

  const toZoned = (d: Date): DateTime => DateTime.fromJSDate(d, { zone: timezone });

  const fajr = toZoned(todayPrayerTimes.fajr);
  const sunrise = toZoned(todayPrayerTimes.sunrise);
  const dhuhr = toZoned(todayPrayerTimes.dhuhr);
  const asr = toZoned(todayPrayerTimes.asr);
  const maghrib = toZoned(todayPrayerTimes.maghrib);
  const isha = toZoned(todayPrayerTimes.isha);

  const slots: PrayerSlot[] = [
    makeSlot('FAJR', fajr),
    makeSlot('DHUHR', dhuhr),
    makeSlot('ASR', asr),
    makeSlot('MAGHRIB', maghrib),
    makeSlot('ISHA', isha),
  ];

  if (isFriday(zonedDate)) {
    slots.splice(2, 0, makeSlot('JUMUAH', dhuhr));
  }

  if (isRamadan(hijri)) {
    const tarawih = isha.plus({ minutes: 30 });
    slots.push(makeSlot('TARAWIH', tarawih));
  }

  if (isEidFitr(hijri)) {
    slots.unshift(makeSlot('EID_FITR', sunrise.plus({ minutes: 30 })));
  }
  if (isEidAdha(hijri)) {
    slots.unshift(makeSlot('EID_ADHA', sunrise.plus({ minutes: 30 })));
  }

  return slots;
}

function makeSlot(type: PrayerType, scheduledAt: DateTime): PrayerSlot {
  const meta = getPrayerMetadata(type);
  return {
    type,
    category: meta.category,
    scheduledAt,
    windowStartsAt: scheduledAt.minus({ minutes: PRAYER_WINDOW_BEFORE_MINUTES }),
    windowEndsAt: scheduledAt.plus({ minutes: PRAYER_WINDOW_AFTER_MINUTES }),
    xpReward: getPrayerBaseXp(type),
    isObligatory: meta.isObligatory,
  };
}

export function isWithinWindow(slot: PrayerSlot, now: DateTime): boolean {
  return now >= slot.windowStartsAt && now <= slot.windowEndsAt;
}
