import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { FastingDTO, RamadanDTO } from '../types/prayer.types';

@Injectable()
export class FastingProgressService {
  private toHijri(date: Date): { year: number; month: number; day: number } {
    const parts = new Intl.DateTimeFormat('en-u-ca-islamic-umalqura', {
      day: 'numeric',
      month: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    }).formatToParts(date);

    return {
      year: parseInt(parts.find((p) => p.type === 'year')!.value, 10),
      month: parseInt(parts.find((p) => p.type === 'month')!.value, 10),
      day: parseInt(parts.find((p) => p.type === 'day')!.value, 10),
    };
  }

  private hijriMonthLength(year: number, month: number): number {
    if (month % 2 === 1) return 30;
    if (month === 12) {
      const leapPattern = [2, 5, 7, 10, 13, 16, 18, 21, 24, 26, 29];
      return leapPattern.includes(year % 30) ? 30 : 29;
    }
    return 29;
  }

  calculate(fajr: DateTime, maghrib: DateTime, now: DateTime): FastingDTO {
    const localMidnight = fajr.startOf('day').toJSDate();
    const hijri = this.toHijri(localMidnight);
    const isRamadan = hijri.month === 9;

    const fastingStart = fajr.toISO();
    const fastingEnd = maghrib.toISO();

    const isFastingTime = now >= fajr && now < maghrib;
    const totalSeconds = Math.max(0, Math.floor(maghrib.diff(fajr).as('seconds')));

    let remainingSeconds: number;
    let progressPercent: number;

    if (now < fajr) {
      remainingSeconds = totalSeconds;
      progressPercent = 0;
    } else if (now >= maghrib) {
      remainingSeconds = 0;
      progressPercent = 100;
    } else {
      const passedSeconds = Math.floor(now.diff(fajr).as('seconds'));
      remainingSeconds = Math.max(0, Math.floor(maghrib.diff(now).as('seconds')));
      progressPercent = parseFloat(((passedSeconds / totalSeconds) * 100).toFixed(2));
    }

    let ramadan: RamadanDTO | null = null;
    if (isRamadan) {
      const totalDays = this.hijriMonthLength(hijri.year, 9);
      const ramadanDay = hijri.day;
      const remainingDays = totalDays - ramadanDay;
      ramadan = { ramadanDay, totalDays, remainingDays };
    }

    return {
      isRamadan,
      isFastingTime,
      fastingStart,
      fastingEnd,
      remainingSeconds,
      progressPercent,
      ramadan,
    };
  }
}
