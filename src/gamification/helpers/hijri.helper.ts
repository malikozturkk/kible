import { DateTime } from 'luxon';

export interface HijriDate {
  year: number;
  month: number;
  day: number;
}

function hijriAnchor(local: DateTime): Date {
  return new Date(Date.UTC(local.year, local.month - 1, local.day, 12));
}

export function toHijri(local: DateTime): HijriDate {
  const parts = new Intl.DateTimeFormat('en-u-ca-islamic-umalqura', {
    day: 'numeric',
    month: 'numeric',
    year: 'numeric',
    timeZone: 'UTC',
  }).formatToParts(hijriAnchor(local));

  return {
    year: parseInt(parts.find((p) => p.type === 'year')!.value, 10),
    month: parseInt(parts.find((p) => p.type === 'month')!.value, 10),
    day: parseInt(parts.find((p) => p.type === 'day')!.value, 10),
  };
}

export interface HijriLabel {
  date: string;
  monthName: string;
}

const HIJRI_DISPLAY_LOCALE = 'tr-TR-u-ca-islamic-umalqura';

export function toHijriLabel(local: DateTime): HijriLabel {
  const anchor = hijriAnchor(local);

  return {
    date: new Intl.DateTimeFormat(HIJRI_DISPLAY_LOCALE, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      timeZone: 'UTC',
    }).format(anchor),
    monthName: new Intl.DateTimeFormat(HIJRI_DISPLAY_LOCALE, {
      month: 'long',
      timeZone: 'UTC',
    }).format(anchor),
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
