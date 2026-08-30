import {
  LEGAL_CONFIG_KEY,
  LEGAL_DOCUMENT_KEYS,
  LEGAL_EFFECTIVE_DATE_PATTERN,
  LEGAL_VERSION_PATTERN,
  legalEffectiveDateEnvKey,
  legalVersionEnvKey,
  type LegalDocumentsMap,
} from '../legal/legal.constants';

export const legalConfig = () => {
  const documents = {} as LegalDocumentsMap;
  const problems: string[] = [];

  for (const key of LEGAL_DOCUMENT_KEYS) {
    const versionKey = legalVersionEnvKey(key);
    const effectiveDateKey = legalEffectiveDateEnvKey(key);
    const version = process.env[versionKey]?.trim();
    const effectiveDate = process.env[effectiveDateKey]?.trim();

    if (!version) {
      problems.push(`${versionKey} (missing)`);
    } else if (!LEGAL_VERSION_PATTERN.test(version)) {
      problems.push(`${versionKey} (expected semver, e.g. 1.0.0)`);
    }

    if (!effectiveDate) {
      problems.push(`${effectiveDateKey} (missing)`);
    } else if (
      !LEGAL_EFFECTIVE_DATE_PATTERN.test(effectiveDate) ||
      Number.isNaN(Date.parse(`${effectiveDate}T00:00:00Z`))
    ) {
      problems.push(`${effectiveDateKey} (expected ISO date, e.g. 2026-08-12)`);
    }

    if (version && effectiveDate) {
      documents[key] = { version, effectiveDate };
    }
  }

  if (problems.length > 0) {
    throw new Error(`LEGAL_DOCUMENTS_NOT_CONFIGURED: ${problems.join(', ')}`);
  }

  return { [LEGAL_CONFIG_KEY]: documents };
};
