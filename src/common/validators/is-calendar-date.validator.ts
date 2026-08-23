import { registerDecorator, ValidationOptions } from 'class-validator';
import { DateTime } from 'luxon';

export const CALENDAR_DATE_FORMAT = 'yyyy-LL-dd';
export const CALENDAR_DATE_MESSAGE = 'date must be YYYY-MM-DD between 1970 and 2100';
export const CALENDAR_DATE_MIN_YEAR = 1970;
export const CALENDAR_DATE_MAX_YEAR = 2100;

export function isCalendarDate(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = DateTime.fromFormat(value, CALENDAR_DATE_FORMAT, { zone: 'utc' });
  if (!parsed.isValid) return false;
  return parsed.year >= CALENDAR_DATE_MIN_YEAR && parsed.year <= CALENDAR_DATE_MAX_YEAR;
}

export function IsCalendarDate(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      name: 'isCalendarDate',
      target: object.constructor,
      propertyName,
      options: { message: CALENDAR_DATE_MESSAGE, ...validationOptions },
      validator: {
        validate: (value: unknown) => isCalendarDate(value),
      },
    });
  };
}
