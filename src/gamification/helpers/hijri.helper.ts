import { DateTime } from 'luxon';

export interface HijriDate {
  year: number;
  month: number;
  day: number;
}

export function toHijri(local: DateTime): HijriDate {
  const anchor = new Date(Date.UTC(local.year, local.month - 1, local.day, 12));
  const parts = new Intl.DateTimeFormat('en-u-ca-islamic-umalqura', {
    day: 'numeric',
    month: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  }).formatToParts(anchor);

  return {
    year: parseInt(parts.find((p) => p.type === 'year')!.value, 10),
    month: parseInt(parts.find((p) => p.type === 'month')!.value, 10),
    day: parseInt(parts.find((p) => p.type === 'day')!.value, 10),
  };
}

export function isRamadan(hijri: HijriDate): boolean {
  return hijri.month === 9;
}

export function isEidFitr(hijri: HijriDate): boolean {
  return hijri.month === 10 && hijri.day === 1;
}

export function isEidAdha(hijri: HijriDate): boolean {
  return hijri.month === 12 && hijri.day === 10;
}

export const FRIDAY_WEEKDAY = 5;

export function isFriday(local: DateTime): boolean {
  return local.weekday === FRIDAY_WEEKDAY;
}
