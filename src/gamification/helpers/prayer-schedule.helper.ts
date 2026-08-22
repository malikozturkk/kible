import { DateTime } from 'luxon';
import { PrayerTimes } from 'adhan';
import { PrayerCompletionStatus, PrayerType } from '@prisma/client';
import { PrayerSlot } from '../types/gamification.types';
import {
  CONGREGATIONAL_MARK_WINDOW_MINUTES,
  getLatePrayerXp,
  getPrayerBaseXp,
  getPrayerMetadata,
} from '../constants/prayer.constants';
import { HijriDate, isEidAdha, isEidFitr, isFriday, isRamadan } from './hijri.helper';

export function buildPrayerSlots(args: {
  todayPrayerTimes: PrayerTimes;
  tomorrowPrayerTimes: PrayerTimes;
  zonedDate: DateTime;
  timezone: string;
  hijri: HijriDate;
}): PrayerSlot[] {
  const { todayPrayerTimes, tomorrowPrayerTimes, zonedDate, timezone, hijri } = args;

  const toZoned = (d: Date): DateTime => DateTime.fromJSDate(d, { zone: timezone });

  const fajr = toZoned(todayPrayerTimes.fajr);
  const sunrise = toZoned(todayPrayerTimes.sunrise);
  const dhuhr = toZoned(todayPrayerTimes.dhuhr);
  const asr = toZoned(todayPrayerTimes.asr);
  const maghrib = toZoned(todayPrayerTimes.maghrib);
  const isha = toZoned(todayPrayerTimes.isha);
  const tomorrowFajr = toZoned(tomorrowPrayerTimes.fajr);
  const friday = isFriday(zonedDate);

  const slots: PrayerSlot[] = [];
  slots.push(makeSlot('FAJR', fajr, fajr, sunrise, dhuhr));

  if (friday) {
    slots.push(makeCongregationalSlot('JUMUAH', dhuhr));
  } else {
    slots.push(makeSlot('DHUHR', dhuhr, dhuhr, asr, asr));
  }

  slots.push(makeSlot('ASR', asr, asr, maghrib, maghrib));
  slots.push(makeSlot('MAGHRIB', maghrib, maghrib, isha, isha));
  slots.push(makeSlot('ISHA', isha, isha, tomorrowFajr, tomorrowFajr));

  if (isRamadan(hijri)) {
    const tarawih = isha.plus({ minutes: 30 });
    slots.push(makeSlot('TARAWIH', tarawih, tarawih, tomorrowFajr, tomorrowFajr));
  }

  if (isEidFitr(hijri)) {
    slots.unshift(makeCongregationalSlot('EID_FITR', sunrise.plus({ minutes: 30 })));
  }
  if (isEidAdha(hijri)) {
    slots.unshift(makeCongregationalSlot('EID_ADHA', sunrise.plus({ minutes: 30 })));
  }

  return slots;
}

function makeCongregationalSlot(type: PrayerType, scheduledAt: DateTime): PrayerSlot {
  const opensAt = scheduledAt.minus({ minutes: CONGREGATIONAL_MARK_WINDOW_MINUTES });
  const closesAt = scheduledAt.plus({ minutes: CONGREGATIONAL_MARK_WINDOW_MINUTES });
  return makeSlot(type, scheduledAt, opensAt, closesAt, closesAt);
}

function makeSlot(
  type: PrayerType,
  scheduledAt: DateTime,
  windowStartsAt: DateTime,
  windowEndsAt: DateTime,
  markWindowEndsAt: DateTime,
): PrayerSlot {
  const meta = getPrayerMetadata(type);
  return {
    type,
    category: meta.category,
    scheduledAt,
    windowStartsAt,
    windowEndsAt,
    markWindowEndsAt: markWindowEndsAt > windowEndsAt ? markWindowEndsAt : windowEndsAt,
    xpReward: getPrayerBaseXp(type),
    lateXpReward: getLatePrayerXp(type),
    isObligatory: meta.isObligatory,
  };
}

export function isWithinWindow(slot: PrayerSlot, now: DateTime): boolean {
  return now >= slot.windowStartsAt && now < slot.windowEndsAt;
}

export function isWithinMarkWindow(slot: PrayerSlot, now: DateTime): boolean {
  return now >= slot.windowStartsAt && now < slot.markWindowEndsAt;
}

export function resolveCompletionStatus(slot: PrayerSlot, now: DateTime): PrayerCompletionStatus {
  return isWithinWindow(slot, now) ? PrayerCompletionStatus.ON_TIME : PrayerCompletionStatus.LATE;
}
