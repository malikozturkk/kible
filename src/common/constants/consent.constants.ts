export const CONSENT_TYPE = {
  TERMS_OF_SERVICE: 'TERMS_OF_SERVICE',
  PRIVACY_POLICY: 'PRIVACY_POLICY',
} as const;

export type ConsentTypeKey = keyof typeof CONSENT_TYPE;

export const CONSENT_VERSIONS: Record<ConsentTypeKey, string> = {
  TERMS_OF_SERVICE: '1.0',
  PRIVACY_POLICY: '1.0',
};
