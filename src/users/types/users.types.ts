import { AvatarCustomizationPayload } from 'src/auth/utils/avatar-config.util';

export interface SearchUserResult {
  username: string;
  avatarCustomization: AvatarCustomizationPayload;
  mutualFollowers: {
    count: number;
    preview: {
      username: string;
      avatarCustomization: AvatarCustomizationPayload;
    }[];
  };
  isFollowing: boolean;
}

export interface SearchUsersResponse {
  users: SearchUserResult[];
  totalCount: number;
  nextCursor: number | null;
}

export const AVATAR_CONFIG_SELECT = {
  select: { colors: true, accessories: true, gender: true },
} as const;
