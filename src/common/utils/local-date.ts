import { DateTime } from 'luxon';

export class LocalDate {
  private constructor(
    public readonly year: number,
    public readonly month: number,
    public readonly day: number,
  ) {}

  static of(year: number, month: number, day: number): LocalDate {
    const dt = DateTime.fromObject({ year, month, day }, { zone: 'utc' });
    if (!dt.isValid) {
      throw new RangeError(`INVALID_LOCAL_DATE: ${year}-${month}-${day}`);
    }
    return new LocalDate(year, month, day);
  }

  static fromISO(value: string): LocalDate {
    const dt = DateTime.fromFormat(value, 'yyyy-LL-dd', { zone: 'utc' });
    if (!dt.isValid) {
      throw new RangeError(`INVALID_LOCAL_DATE: ${value}`);
    }
    return new LocalDate(dt.year, dt.month, dt.day);
  }

  static fromInstant(instant: DateTime, timezone: string): LocalDate {
    const local = instant.setZone(timezone);
    if (!local.isValid) {
      throw new RangeError(`INVALID_TIMEZONE: ${timezone}`);
    }
    return new LocalDate(local.year, local.month, local.day);
  }

  static todayIn(timezone: string): LocalDate {
    return LocalDate.fromInstant(DateTime.now(), timezone);
  }

  static fromPersisted(d: Date): LocalDate {
    return new LocalDate(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
  }

  toISO(): string {
    return [
      this.year.toString().padStart(4, '0'),
      this.month.toString().padStart(2, '0'),
      this.day.toString().padStart(2, '0'),
    ].join('-');
  }

  toUtcMidnight(): Date {
    return new Date(Date.UTC(this.year, this.month - 1, this.day));
  }

  toZonedStartOfDay(timezone: string): DateTime {
    const dt = DateTime.fromObject(
      { year: this.year, month: this.month, day: this.day },
      { zone: timezone },
    );
    if (!dt.isValid) {
      throw new RangeError(`INVALID_TIMEZONE: ${timezone}`);
    }
    return dt.startOf('day');
  }

  plusDays(delta: number): LocalDate {
    const next = DateTime.fromObject(
      { year: this.year, month: this.month, day: this.day },
      { zone: 'utc' },
    ).plus({ days: delta });
    return new LocalDate(next.year, next.month, next.day);
  }

  minusDays(delta: number): LocalDate {
    return this.plusDays(-delta);
  }

  daysUntil(other: LocalDate): number {
    const a = this.toUtcMidnight().getTime();
    const b = other.toUtcMidnight().getTime();
    return Math.round((b - a) / 86_400_000);
  }

  equals(other: LocalDate): boolean {
    return this.year === other.year && this.month === other.month && this.day === other.day;
  }

  weekday(timezone = 'utc'): number {
    return this.toZonedStartOfDay(timezone).weekday;
  }
}
