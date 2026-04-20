import { ConsentType } from '@prisma/client';

export enum ConsentErrorCode {
  CONSENT_REQUIRED = 'CONSENT_REQUIRED',
  CONSENT_OUTDATED = 'CONSENT_OUTDATED',
}

export type ConsentVersionsMap = Record<ConsentType, string>;
export const CONSENT_CACHE_PREFIX = 'consent:';
export const CONSENT_CACHE_TTL_MS = 30_000;

export const CONSENT_BYPASS_ROUTES: ReadonlyArray<{ method: string; path: RegExp }> = [
  { method: 'GET', path: /^\/consent\/status\/?$/ },
  { method: 'POST', path: /^\/consent\/accept\/?$/ },
  { method: 'POST', path: /^\/auth\/logout\/?$/ },
  { method: 'POST', path: /^\/auth\/refresh\/?$/ },
  { method: 'GET', path: /^\/legal(\/.*)?$/ },
];

export const CONSENT_VERSION_ENV_KEYS = {
  TERMS_OF_SERVICE: 'CONSENT_VERSION_TERMS_OF_SERVICE',
  PRIVACY_POLICY: 'CONSENT_VERSION_PRIVACY_POLICY',
} as const;
