import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SearchUsersDto } from './dto/search-users.dto';
import { resolveAvatarCustomizationFromDb } from '../auth/utils/avatar-config.util';
import { AVATAR_CONFIG_SELECT, SearchUserResult, SearchUsersResponse } from './types/users.types';
import { SEARCH_MIN_SIMILARITY, TRIGRAM_SIZE } from './constants/search.constants';
@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async searchUsers(dto: SearchUsersDto, requesterId: string): Promise<SearchUsersResponse> {
    const { query, pageSize, cursor } = dto;
    const normalizedQuery = query.toLowerCase().trim();
    const trigrams = this.generateTrigrams(normalizedQuery);
    const candidates = await this.prisma.user.findMany({
      where: {
        OR: [
          { username: { contains: this.escapeLikePattern(normalizedQuery), mode: 'insensitive' } },
          ...trigrams.map((tri) => ({
            username: { contains: this.escapeLikePattern(tri), mode: 'insensitive' as const },
          })),
        ],
      },
      select: {
        id: true,
        username: true,
        avatarConfig: AVATAR_CONFIG_SELECT,
      },
      take: 500,
    });

    const isShortQuery = normalizedQuery.length < TRIGRAM_SIZE;
    const scored = candidates
      .map((user) => ({
        ...user,
        similarity: isShortQuery
          ? this.shortQuerySimilarity(normalizedQuery, user.username.toLowerCase())
          : this.trigramSimilarity(normalizedQuery, user.username.toLowerCase()),
      }))
      .filter((user) => user.similarity >= SEARCH_MIN_SIMILARITY);

    if (scored.length === 0) {
      return { users: [], totalCount: 0, nextCursor: null };
    }

    const totalCount = scored.length;

    const scoredIds = scored.map((u) => u.id);

    const [directFollows, myFollowingIds] = await Promise.all([
      this.prisma.follow.findMany({
        where: { followerId: requesterId, followingId: { in: scoredIds } },
        select: { followingId: true },
      }),
      this.prisma.follow.findMany({
        where: { followerId: requesterId },
        select: { followingId: true },
      }),
    ]);

    const directFollowIdSet = new Set(directFollows.map((f) => f.followingId));
    const myFollowingIdList = myFollowingIds.map((f) => f.followingId);
    let secondDegreeIdSet = new Set<string>();
    if (myFollowingIdList.length > 0) {
      const secondDegreeFollows = await this.prisma.follow.findMany({
        where: {
          followerId: { in: myFollowingIdList },
          followingId: { in: scoredIds },
        },
        select: { followingId: true },
      });
      secondDegreeIdSet = new Set(secondDegreeFollows.map((f) => f.followingId));
    }

    const ranked = scored.map((user) => {
      let tier: number;
      if (user.username.toLowerCase() === normalizedQuery) tier = 0;
      else if (directFollowIdSet.has(user.id)) tier = 1;
      else if (secondDegreeIdSet.has(user.id)) tier = 2;
      else tier = 3;
      return { ...user, tier };
    });

    ranked.sort((a, b) => {
      if (a.tier !== b.tier) return a.tier - b.tier;
      if (a.similarity !== b.similarity) return b.similarity - a.similarity;
      return a.username.localeCompare(b.username);
    });

    const page = ranked.slice(cursor, cursor + pageSize + 1);
    const hasNextPage = page.length > pageSize;
    const resultSlice = hasNextPage ? page.slice(0, pageSize) : page;

    const users: SearchUserResult[] = await Promise.all(
      resultSlice.map(async (user) => {
        const [mutualFollowsPreview, mutualCount] = await Promise.all([
          this.prisma.follow.findMany({
            where: {
              followingId: user.id,
              follower: { followers: { some: { followerId: requesterId } } },
            },
            select: {
              follower: {
                select: { username: true, avatarConfig: AVATAR_CONFIG_SELECT },
              },
            },
            take: 3,
          }),
          this.prisma.follow.count({
            where: {
              followingId: user.id,
              follower: { followers: { some: { followerId: requesterId } } },
            },
          }),
        ]);

        return {
          username: user.username,
          avatarCustomization: resolveAvatarCustomizationFromDb(user.avatarConfig),
          isFollowing: directFollowIdSet.has(user.id),
          mutualFollowers: {
            count: mutualCount,
            preview: mutualFollowsPreview.map((f) => ({
              username: f.follower.username,
              avatarCustomization: resolveAvatarCustomizationFromDb(f.follower.avatarConfig),
            })),
          },
        };
      }),
    );

    return {
      users,
      totalCount,
      nextCursor: hasNextPage ? cursor + pageSize : null,
    };
  }

  private escapeLikePattern(value: string): string {
    return value.replace(/[\\%_]/g, (char) => `\\${char}`);
  }

  private shortQuerySimilarity(query: string, username: string): number {
    const index = username.indexOf(query);
    if (index === -1) return 0;

    const positionScore = index === 0 ? 1 : 0.6;
    const lengthScore = query.length / username.length;
    return SEARCH_MIN_SIMILARITY + (1 - SEARCH_MIN_SIMILARITY) * positionScore * lengthScore;
  }

  private generateTrigrams(str: string): string[] {
    if (str.length < TRIGRAM_SIZE) return [str];
    const trigrams: string[] = [];
    for (let i = 0; i <= str.length - TRIGRAM_SIZE; i++) {
      trigrams.push(str.substring(i, i + TRIGRAM_SIZE));
    }
    return trigrams;
  }

  private trigramSimilarity(a: string, b: string): number {
    const triA = new Set(this.generateTrigrams(a));
    const triB = new Set(this.generateTrigrams(b));

    if (triA.size === 0 && triB.size === 0) return 1;
    if (triA.size === 0 || triB.size === 0) return 0;

    let intersection = 0;
    for (const t of triA) {
      if (triB.has(t)) intersection++;
    }

    return intersection / Math.min(triA.size, triB.size);
  }
}
