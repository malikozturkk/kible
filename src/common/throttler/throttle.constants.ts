const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export const THROTTLE_DEFAULT = { ttl: MINUTE, limit: 10 };

export const THROTTLE_LOGIN = { ttl: MINUTE, limit: 5 };

export const THROTTLE_REGISTER = { ttl: HOUR, limit: 5 };

export const THROTTLE_OTP_VERIFY = { ttl: MINUTE, limit: 5 };

export const THROTTLE_EMAIL_SEND = { ttl: HOUR, limit: 3 };

export const THROTTLE_RESET = { ttl: MINUTE, limit: 5 };

export const THROTTLE_REFRESH = { ttl: MINUTE, limit: 20 };

export const LOGIN_MAX_FAILED_ATTEMPTS = 10;
export const LOGIN_LOCK_DURATION_MS = 15 * MINUTE;
