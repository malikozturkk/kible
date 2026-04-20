export const GENDER_VALUES = ['MALE', 'FEMALE'] as const;
export type GenderValue = (typeof GENDER_VALUES)[number];
export const DEFAULT_GENDER: GenderValue = 'MALE';
