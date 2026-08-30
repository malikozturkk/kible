import { ConsentType } from '@prisma/client';

export const LEGAL_DOCUMENT_KEYS = [
  ConsentType.TERMS_OF_SERVICE,
  ConsentType.PRIVACY_POLICY,
  ConsentType.SPECIAL_CATEGORY_DATA,
  'COOKIE_POLICY',
] as const;

export type LegalDocumentKey = (typeof LEGAL_DOCUMENT_KEYS)[number];

export const CONSENT_DOCUMENT_KEYS: ConsentType[] = [
  ConsentType.TERMS_OF_SERVICE,
  ConsentType.PRIVACY_POLICY,
  ConsentType.SPECIAL_CATEGORY_DATA,
];

export interface LegalDocumentConfig {
  version: string;
  effectiveDate: string;
}

export type LegalDocumentsMap = Record<LegalDocumentKey, LegalDocumentConfig>;

export const LEGAL_CONFIG_KEY = 'LEGAL_DOCUMENTS';

export const legalVersionEnvKey = (key: LegalDocumentKey): string => `CONSENT_VERSION_${key}`;

export const legalEffectiveDateEnvKey = (key: LegalDocumentKey): string =>
  `CONSENT_EFFECTIVE_DATE_${key}`;

export const LEGAL_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
export const LEGAL_EFFECTIVE_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
