export const GENDER_VALUES = ['MALE', 'FEMALE'] as const;
export type GenderValue = (typeof GENDER_VALUES)[number];

/** Default when no avatar config row exists yet */
export const DEFAULT_GENDER: GenderValue = 'MALE';
