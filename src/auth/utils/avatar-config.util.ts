import {
  AVATAR_COLOR_KEYS,
  DEFAULT_AVATAR_COLORS,
  type AvatarColorKey,
} from '../constants/avatar.constants';
import { DEFAULT_GENDER, type GenderValue } from '../constants/gender.constants';

export type AvatarCustomizationPayload = {
  gender: GenderValue;
  colors: Record<AvatarColorKey, string>;
  accessories: Record<string, unknown>;
};

function resolveGender(raw: unknown): GenderValue {
  if (raw === 'MALE' || raw === 'FEMALE') {
    return raw;
  }
  return DEFAULT_GENDER;
}

export function getDefaultAvatarCustomization(): AvatarCustomizationPayload {
  return {
    gender: DEFAULT_GENDER,
    colors: { ...DEFAULT_AVATAR_COLORS },
    accessories: {},
  };
}

function pickAvatarColors(raw: unknown): Partial<Record<AvatarColorKey, string>> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {};
  }
  const o = raw as Record<string, unknown>;
  const out: Partial<Record<AvatarColorKey, string>> = {};
  for (const key of AVATAR_COLOR_KEYS) {
    const v = o[key];
    if (typeof v === 'string') {
      out[key] = v;
    }
  }
  return out;
}

function normalizeAccessories(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  return {};
}

export function resolveAvatarColors(raw: unknown): Record<AvatarColorKey, string> {
  return {
    ...DEFAULT_AVATAR_COLORS,
    ...pickAvatarColors(raw),
  };
}

export function resolveAvatarCustomizationFromDb(
  row: { colors: unknown; accessories: unknown; gender?: unknown } | null | undefined,
): AvatarCustomizationPayload {
  if (!row) {
    return getDefaultAvatarCustomization();
  }
  return {
    gender: resolveGender(row.gender),
    colors: resolveAvatarColors(row.colors),
    accessories: normalizeAccessories(row.accessories),
  };
}
