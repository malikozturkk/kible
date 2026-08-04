import { registerDecorator, ValidationOptions } from 'class-validator';
import { DateTime } from 'luxon';

export const CALENDAR_DATE_FORMAT = 'yyyy-LL-dd';
export const CALENDAR_DATE_MESSAGE = 'date must be YYYY-MM-DD';

export function isCalendarDate(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  return DateTime.fromFormat(value, CALENDAR_DATE_FORMAT, { zone: 'utc' }).isValid;
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
