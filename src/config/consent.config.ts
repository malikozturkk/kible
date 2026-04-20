import { ConsentType } from '@prisma/client';
import { CONSENT_VERSION_ENV_KEYS, type ConsentVersionsMap } from '../consent/consent.constants';

export const consentConfig = () => {
  const types: ConsentType[] = [ConsentType.TERMS_OF_SERVICE, ConsentType.PRIVACY_POLICY];

  const map = {} as ConsentVersionsMap;
  const missing: string[] = [];

  for (const type of types) {
    const envKey = CONSENT_VERSION_ENV_KEYS[type];
    const envVal = process.env[envKey];
    if (!envVal || envVal.trim().length === 0) {
      missing.push(envKey);
      continue;
    }
    map[type] = envVal.trim();
  }

  if (missing.length > 0) {
    throw new Error(`CONSENT_VERSIONS_NOT_CONFIGURED: missing env vars: ${missing.join(', ')}`);
  }

  return { CONSENT_VERSIONS: map };
};
