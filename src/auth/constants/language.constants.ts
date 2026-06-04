export const SUPPORTED_LANGUAGES = ['tr'] as const;
export type LanguageValue = (typeof SUPPORTED_LANGUAGES)[number];
export const DEFAULT_LANGUAGE: LanguageValue = 'tr';
