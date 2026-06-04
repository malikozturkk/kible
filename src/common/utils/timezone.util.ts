import tzlookup from 'tz-lookup';

export const DEFAULT_TIMEZONE = 'Europe/Istanbul';

export function resolveTimezone(latitude: number, longitude: number): string {
  try {
    return tzlookup(latitude, longitude) || DEFAULT_TIMEZONE;
  } catch {
    return DEFAULT_TIMEZONE;
  }
}
