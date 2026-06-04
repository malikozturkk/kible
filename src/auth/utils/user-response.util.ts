import { Prisma, Madhab } from '@prisma/client';
import { AuthResponseUserDto } from '../dto/auth-response.dto';
import { resolveAvatarCustomizationFromDb } from './avatar-config.util';

export const USER_RESPONSE_SELECT = {
  id: true,
  username: true,
  email: true,
  avatar: true,
  country: true,
  city: true,
  madhab: true,
  language: true,
  avatarConfig: {
    select: { colors: true, accessories: true, gender: true },
  },
} satisfies Prisma.UserSelect;

type AvatarConfigRow = {
  colors: unknown;
  accessories: unknown;
  gender?: unknown;
} | null;

type AuthUserRow = {
  id: string;
  username: string;
  email: string | null;
  avatar: string | null;
  country: string | null;
  city: string | null;
  madhab: Madhab;
  language: string;
  avatarConfig?: AvatarConfigRow;
};

export function toAuthUser(row: AuthUserRow): AuthResponseUserDto {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    avatar: row.avatar,
    country: row.country,
    city: row.city,
    madhab: row.madhab,
    language: row.language,
    avatarCustomization: resolveAvatarCustomizationFromDb(row.avatarConfig),
  };
}
