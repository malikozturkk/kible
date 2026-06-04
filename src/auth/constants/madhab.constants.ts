export const MADHAB_VALUES = ['SHAFI', 'HANAFI'] as const;
export type MadhabValue = (typeof MADHAB_VALUES)[number];
export const DEFAULT_MADHAB: MadhabValue = 'HANAFI';
