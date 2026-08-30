import {
  Injectable,
  Logger,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Cron, CronExpression } from '@nestjs/schedule';
import { StringValue } from 'ms';
import { ConsentType, PasswordHashScheme, Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { NotificationDispatchService } from '../notifications/services/notification-dispatch.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { ConsentVersionsMap } from '../consent/consent.constants';
import { LegalService } from '../legal/legal.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { AVATAR_COLOR_KEYS, type AvatarColorKey } from './constants/avatar.constants';
import {
  MAX_LOCATION_CHANGES,
  MAX_MADHAB_CHANGES,
  USERNAME_CHANGE_COOLDOWN_DAYS,
} from './constants/profile.constants';
import { AvatarColorsDto } from './dto/avatar-colors.dto';
import { resolveCityCoordinates } from './constants/tr-cities.constants';
import { resolveAvatarColors, resolveAvatarCustomizationFromDb } from './utils/avatar-config.util';
import { toAuthUser, USER_RESPONSE_SELECT } from './utils/user-response.util';
import { RegisterResponseDto } from './dto/register-response.dto';
import { UpdateProfileResponseDto } from './dto/update-profile-response.dto';
import { JwtPayload } from './strategies/jwt.strategy';
import { OtpService } from '../otp/otp.service';
import { CURRENT_HASH_SCHEME, hashPassword, verifyPassword } from './utils/password-hash.util';
import { PaginationDto } from '../common/dto/pagination.dto';
import { buildPageMeta, paginate, type Paginated } from '../common/utils/pagination.util';
import { LoginAttemptService } from './services/login-attempt.service';
import * as crypto from 'crypto';

const FOLLOW_USER_SELECT = {
  username: true,
  avatarConfig: {
    select: { colors: true, accessories: true, gender: true },
  },
} satisfies Prisma.UserSelect;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly PEPPER = process.env.PEPPER;
  private readonly JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
  private readonly REFRESH_TOKEN_EXPIRES_IN_DAYS = 1;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private otpService: OtpService,
    private legalService: LegalService,
    private loginAttemptService: LoginAttemptService,
    private notificationDispatch: NotificationDispatchService,
  ) {}

  async register(registerDto: RegisterDto): Promise<RegisterResponseDto> {
    const { username, email, password, gender, country, city, madhab, language } = registerDto;

    if (!email) {
      throw new BadRequestException('EMAIL_REQUIRED');
    }

    const { latitude, longitude } = resolveCityCoordinates(city);

    const existingUsername = await this.prisma.user.findUnique({
      where: { username },
    });

    if (existingUsername) {
      throw new ConflictException('USERNAME_ALREADY_EXISTS');
    }
    const existingEmail = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingEmail) {
      throw new ConflictException('USER_ALREADY_EXISTS');
    }

    const passwordHash = await hashPassword(password, this.PEPPER as string);

    await this.prisma.otpVerification.deleteMany({
      where: {
        OR: [{ email }, { username }],
        expiresAt: { lte: new Date() },
      },
    });

    await this.otpService.cleanupStaleRegistrations(email, username);

    const activeRegistration = await this.prisma.otpVerification.findFirst({
      where: {
        OR: [{ email }, { username }],
        expiresAt: { gt: new Date() },
      },
    });

    if (activeRegistration) {
      const isSameRegistration =
        activeRegistration.email === email && activeRegistration.username === username;
      const isOwner =
        isSameRegistration &&
        (await verifyPassword(
          password,
          activeRegistration.passwordHash,
          CURRENT_HASH_SCHEME,
          this.PEPPER as string,
        ));

      if (!isOwner) {
        throw new ConflictException('ACTIVE_REGISTRATION_EXISTS');
      }

      const remainingMs = activeRegistration.expiresAt.getTime() - Date.now();
      const resumedToken = this.jwtService.sign(
        { email, username, purpose: 'register' },
        { expiresIn: Math.max(Math.floor(remainingMs / 1000), 1) },
      );

      await this.prisma.otpVerification.update({
        where: { id: activeRegistration.id },
        data: { tokenHash: this.otpService.hashToken(resumedToken) },
      });

      return { tempToken: resumedToken };
    }

    const tempToken = this.jwtService.sign(
      { email, username, purpose: 'register' },
      { expiresIn: '10m' },
    );

    const versions = this.legalService.getConsentVersions();
    await this.otpService.create(tempToken, {
      email,
      username,
      passwordHash,
      gender,
      country,
      city,
      latitude,
      longitude,
      madhab,
      language,
      termsVersion: versions[ConsentType.TERMS_OF_SERVICE],
      privacyPolicyVersion: versions[ConsentType.PRIVACY_POLICY],
      specialCategoryVersion: versions[ConsentType.SPECIAL_CATEGORY_DATA],
    });

    return {
      tempToken,
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponseDto> {
    const { identifier, password } = loginDto;

    if (!identifier) {
      throw new BadRequestException('IDENTIFIER_REQUIRED');
    }
    const where = this.resolveIdentifierWhereClause(identifier);

    const user = await this.prisma.user.findUnique({
      where,
      include: {
        credentials: true,
        avatarConfig: {
          select: { colors: true, accessories: true, gender: true },
        },
      },
    });

    if (!user || !user.credentials) {
      throw new UnauthorizedException('INVALID_CREDENTIALS');
    }

    const isValid = await verifyPassword(
      password,
      user.credentials.passwordHash,
      user.credentials.hashScheme,
      this.PEPPER as string,
    );

    if (this.loginAttemptService.isLocked(user.credentials)) {
      throw new UnauthorizedException('ACCOUNT_TEMPORARILY_LOCKED');
    }

    if (!isValid) {
      await this.loginAttemptService.registerFailure(user.id);
      throw new UnauthorizedException('INVALID_CREDENTIALS');
    }

    await this.loginAttemptService.registerSuccess(user.id);
    await this.upgradeHashSchemeIfNeeded(user.id, user.credentials.hashScheme, password);

    const tokens = await this.generateTokens(user.id, user.username);
    return {
      ...tokens,
      user: toAuthUser(user),
    };
  }

  async refresh(refreshTokenDto: { refreshToken: string }): Promise<AuthResponseDto> {
    const { refreshToken } = refreshTokenDto;
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          select: USER_RESPONSE_SELECT,
        },
      },
    });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('INVALID_OR_EXPIRED_REFRESH_TOKEN');
    }

    if (storedToken.isRevoked) {
      await this.revokeTokenFamily(storedToken.userId, storedToken.familyId);
      throw new UnauthorizedException('INVALID_OR_EXPIRED_REFRESH_TOKEN');
    }

    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { isRevoked: true },
    });

    const tokens = await this.generateTokens(
      storedToken.user.id,
      storedToken.user.username,
      storedToken.familyId,
    );
    return {
      ...tokens,
      user: toAuthUser(storedToken.user),
    };
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
    });

    if (!storedToken) {
      throw new UnauthorizedException('INVALID_REFRESH_TOKEN');
    }

    if (storedToken.userId !== userId) {
      throw new UnauthorizedException('INVALID_REFRESH_TOKEN');
    }

    if (storedToken.isRevoked) {
      throw new UnauthorizedException('TOKEN_ALREADY_INVALIDATED');
    }

    if (storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('REFRESH_TOKEN_EXPIRED');
    }

    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { isRevoked: true },
    });
  }

  async deleteAccount(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true },
    });

    if (!user) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.passwordReset.deleteMany({ where: { userId } });
      await tx.otpVerification.deleteMany({ where: { email: user.email } });
      await tx.user.delete({ where: { id: userId } });
    });
  }

  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredRefreshTokens(): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
  }

  private getProfileSelect(isOwner: boolean) {
    const base = {
      username: true,
      createdAt: true,
      country: true,
      city: true,
      language: true,
    };

    // madhab, KVKK m.6 kapsamında özel nitelikli veridir (inanç); yalnızca hesabın
    // sahibine döner, başka kullanıcılara asla gösterilmez.
    const ownerOnly = {
      id: true,
      email: true,
      madhab: true,
      updatedAt: true,
      locationChangeCount: true,
      madhabChangeCount: true,
    };

    return isOwner ? { ...base, ...ownerOnly } : base;
  }

  async getProfileByUsername(username: string, viewerId: string) {
    const target = await this.prisma.user.findUnique({
      where: { username },
      select: { id: true },
    });

    if (!target) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const isOwner = viewerId === target.id;

    const [profile, mutualFollowers, isFollowing, followerCount, followingCount] =
      await Promise.all([
        this.prisma.user.findUnique({
          where: { id: target.id },
          select: {
            ...this.getProfileSelect(isOwner),
            avatarConfig: { select: { colors: true, accessories: true, gender: true } },
          },
        }),
        this.getMutualFollowers(isOwner, target.id, viewerId),
        this.getIsFollowing(isOwner, target.id, viewerId),
        this.prisma.follow.count({ where: { followingId: target.id } }),
        this.prisma.follow.count({ where: { followerId: target.id } }),
      ]);

    if (!profile) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const { avatarConfig, ...rest } = profile;

    return {
      ...rest,
      avatarCustomization: resolveAvatarCustomizationFromDb(avatarConfig),
      isFollowing: isOwner ? null : !!isFollowing,
      followerCount,
      followingCount,
      mutualFollowers: {
        count: mutualFollowers.length,
        preview: mutualFollowers.map((f) => ({
          username: f.follower.username,
          avatarCustomization: resolveAvatarCustomizationFromDb(f.follower.avatarConfig),
        })),
      },
    };
  }

  private getMutualFollowers(isOwner: boolean, targetId: string, viewerId: string) {
    if (isOwner) return Promise.resolve([]);

    return this.prisma.follow.findMany({
      where: {
        followingId: targetId,
        follower: { followers: { some: { followerId: viewerId } } },
      },
      select: {
        follower: {
          select: {
            username: true,
            avatarConfig: {
              select: { colors: true, accessories: true, gender: true },
            },
          },
        },
      },
      take: 3,
    });
  }

  private getIsFollowing(isOwner: boolean, targetId: string, viewerId: string) {
    if (isOwner) return Promise.resolve(null);

    return this.prisma.follow.findUnique({
      where: { followerId_followingId: { followerId: viewerId, followingId: targetId } },
      select: { id: true },
    });
  }

  private mergeAvatarColorPatch(
    current: Record<AvatarColorKey, string>,
    patch: AvatarColorsDto,
  ): Record<AvatarColorKey, string> {
    const next = { ...current };
    for (const key of AVATAR_COLOR_KEYS) {
      const v = patch[key];
      if (v !== undefined) {
        next[key] = v;
      }
    }
    return next;
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
  ): Promise<UpdateProfileResponseDto> {
    let passwordChanged = false;
    const {
      username,
      gender,
      avatarColors,
      currentPassword,
      newPassword,
      language,
      country,
      city,
      madhab,
    } = updateProfileDto;

    const locationParts = [country, city];
    const providedLocationParts = locationParts.filter((v) => v !== undefined).length;
    if (providedLocationParts > 0 && providedLocationParts < locationParts.length) {
      throw new BadRequestException('INCOMPLETE_LOCATION_UPDATE');
    }

    const currentUser = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        username: true,
        country: true,
        city: true,
        madhab: true,
        locationChangeCount: true,
        madhabChangeCount: true,
        usernameUpdatedAt: true,
      },
    });
    if (!currentUser) {
      throw new UnauthorizedException('USER_NOT_FOUND');
    }
    const current = currentUser;

    const locationChanged =
      providedLocationParts === locationParts.length &&
      (country !== current.country || city !== current.city);
    if (locationChanged && current.locationChangeCount >= MAX_LOCATION_CHANGES) {
      throw new ConflictException('LOCATION_CHANGE_LIMIT_REACHED');
    }
    const resolvedCoordinates = locationChanged ? resolveCityCoordinates(city as string) : null;

    const madhabChanged = madhab !== undefined && madhab !== current.madhab;
    if (madhabChanged && current.madhabChangeCount >= MAX_MADHAB_CHANGES) {
      throw new ConflictException('MADHAB_CHANGE_LIMIT_REACHED');
    }

    const usernameChanged = username !== undefined && username !== currentUser.username;
    if (usernameChanged) {
      const existingUser = await this.prisma.user.findFirst({
        where: {
          username,
          NOT: { id: userId },
        },
      });

      if (existingUser) {
        throw new ConflictException('USERNAME_ALREADY_EXISTS');
      }

      const lastRename = currentUser.usernameUpdatedAt;
      if (lastRename) {
        const cooldownEndsAt =
          lastRename.getTime() + USERNAME_CHANGE_COOLDOWN_DAYS * 24 * 60 * 60 * 1000;
        if (Date.now() < cooldownEndsAt) {
          throw new ConflictException('USERNAME_CHANGE_COOLDOWN_ACTIVE');
        }
      }
    }

    if (currentPassword || newPassword) {
      if (!currentPassword || !newPassword) {
        throw new BadRequestException('PASSWORD_FIELDS_REQUIRED');
      }

      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { credentials: true },
      });

      if (!user || !user.credentials) {
        throw new UnauthorizedException('USER_NOT_FOUND');
      }

      const isPasswordValid = await verifyPassword(
        currentPassword,
        user.credentials.passwordHash,
        user.credentials.hashScheme,
        this.PEPPER as string,
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('INVALID_CURRENT_PASSWORD');
      }

      if (newPassword === currentPassword) {
        throw new BadRequestException('NEW_PASSWORD_MUST_DIFFER');
      }

      const hashedPassword = await hashPassword(newPassword, this.PEPPER as string);

      await this.prisma.$transaction(async (tx) => {
        await tx.userCredential.update({
          where: { userId },
          data: {
            passwordHash: hashedPassword,
            hashScheme: CURRENT_HASH_SCHEME,
            passwordUpdatedAt: new Date(),
            failedLoginAttempts: 0,
            lockedUntil: null,
            tokenVersion: { increment: 1 },
          },
        });

        await tx.refreshToken.updateMany({
          where: { userId, isRevoked: false },
          data: { isRevoked: true },
        });
      });

      passwordChanged = true;
    }

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(usernameChanged && { username, usernameUpdatedAt: new Date() }),
        ...(language !== undefined && { language }),
        ...(locationChanged &&
          resolvedCoordinates && {
            country,
            city,
            latitude: resolvedCoordinates.latitude,
            longitude: resolvedCoordinates.longitude,
            locationChangeCount: { increment: 1 },
          }),
        ...(madhabChanged && { madhab, madhabChangeCount: { increment: 1 } }),
      },
      select: {
        id: true,
        username: true,
        email: true,
        country: true,
        city: true,
        madhab: true,
        language: true,
        locationChangeCount: true,
        madhabChangeCount: true,
      },
    });

    if (avatarColors !== undefined || gender !== undefined) {
      const existing = await this.prisma.userAvatarConfig.findUnique({
        where: { userId },
      });
      const mergedColors =
        avatarColors !== undefined
          ? this.mergeAvatarColorPatch(resolveAvatarColors(existing?.colors), avatarColors)
          : resolveAvatarColors(existing?.colors);
      const mergedGender = gender !== undefined ? gender : (existing?.gender ?? 'MALE');

      await this.prisma.userAvatarConfig.upsert({
        where: { userId },
        create: {
          userId,
          colors: mergedColors,
          accessories: {},
          gender: mergedGender,
        },
        update: {
          colors: mergedColors,
          ...(gender !== undefined && { gender: mergedGender }),
        },
      });
    }

    const avatarRow = await this.prisma.userAvatarConfig.findUnique({
      where: { userId },
    });

    const rotatedTokens = passwordChanged
      ? await this.generateTokens(user.id, user.username)
      : undefined;

    return {
      ...user,
      avatarCustomization: resolveAvatarCustomizationFromDb(avatarRow),
      ...(rotatedTokens && { tokens: rotatedTokens }),
    };
  }

  private resolveIdentifierWhereClause(
    identifier: string,
  ): { email: string } | { username: string } {
    const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (EMAIL_REGEX.test(identifier)) {
      return { email: identifier };
    }
    return { username: identifier };
  }

  private async revokeTokenFamily(userId: string, familyId: string): Promise<void> {
    await this.prisma.$transaction([
      this.prisma.refreshToken.updateMany({
        where: { userId, familyId, isRevoked: false },
        data: { isRevoked: true },
      }),
      this.prisma.userCredential.updateMany({
        where: { userId },
        data: { tokenVersion: { increment: 1 } },
      }),
    ]);
  }

  private async upgradeHashSchemeIfNeeded(
    userId: string,
    scheme: PasswordHashScheme,
    plainPassword: string,
  ): Promise<void> {
    if (scheme === CURRENT_HASH_SCHEME) return;

    const passwordHash = await hashPassword(plainPassword, this.PEPPER as string);
    await this.prisma.userCredential.update({
      where: { userId },
      data: { passwordHash, hashScheme: CURRENT_HASH_SCHEME },
    });
  }

  private async generateTokens(
    userId: string,
    username: string,
    familyId?: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const credentials = await this.prisma.userCredential.findUnique({
      where: { userId },
      select: { tokenVersion: true },
    });

    const payload: JwtPayload = {
      sub: userId,
      username,
      tv: credentials?.tokenVersion ?? 0,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.JWT_EXPIRES_IN as StringValue,
    });

    const refreshToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRES_IN_DAYS);

    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
        ...(familyId ? { familyId } : {}),
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private async resolveUserIdByUsername(username: string): Promise<string> {
    const target = await this.prisma.user.findUnique({
      where: { username },
      select: { id: true },
    });

    if (!target) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    return target.id;
  }

  async getFollowers(username: string, pagination?: PaginationDto): Promise<Paginated<unknown>> {
    const targetId = await this.resolveUserIdByUsername(username);
    const { skip, take, page, pageSize } = paginate(pagination);

    const [follows, total] = await Promise.all([
      this.prisma.follow.findMany({
        where: { followingId: targetId },
        select: { follower: { select: FOLLOW_USER_SELECT } },
        orderBy: { createdAt: 'desc' },
        skip,
        take,
      }),
      this.prisma.follow.count({ where: { followingId: targetId } }),
    ]);

    return {
      items: follows.map((f) => ({
        username: f.follower.username,
        avatarCustomization: resolveAvatarCustomizationFromDb(f.follower.avatarConfig),
      })),
      meta: buildPageMeta(page, pageSize, total),
    };
  }

  async getFollowing(username: string, pagination?: PaginationDto): Promise<Paginated<unknown>> {
    const targetId = await this.resolveUserIdByUsername(username);
    const { skip, take, page, pageSize } = paginate(pagination);

    const [follows, total] = await Promise.all([
      this.prisma.follow.findMany({
        where: { followerId: targetId },
        select: { following: { select: FOLLOW_USER_SELECT } },
        orderBy: { createdAt: 'desc' },
        skip,
        take,
      }),
      this.prisma.follow.count({ where: { followerId: targetId } }),
    ]);

    return {
      items: follows.map((f) => ({
        username: f.following.username,
        avatarCustomization: resolveAvatarCustomizationFromDb(f.following.avatarConfig),
      })),
      meta: buildPageMeta(page, pageSize, total),
    };
  }

  async toggleFollow(currentUserId: string, targetUsername: string) {
    const target = await this.prisma.user.findUnique({
      where: { username: targetUsername },
      select: { id: true },
    });

    if (!target) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    if (currentUserId === target.id) {
      throw new BadRequestException('CANNOT_FOLLOW_YOURSELF');
    }

    const existing = await this.prisma.follow.findUnique({
      where: {
        followerId_followingId: {
          followerId: currentUserId,
          followingId: target.id,
        },
      },
    });

    if (existing) {
      await this.prisma.follow.delete({
        where: {
          followerId_followingId: {
            followerId: currentUserId,
            followingId: target.id,
          },
        },
      });
      return { following: false };
    }

    await this.prisma.follow.create({
      data: {
        followerId: currentUserId,
        followingId: target.id,
      },
    });

    await this.notifyNewFollower(currentUserId, target.id);

    return { following: true };
  }

  private async notifyNewFollower(followerId: string, targetUserId: string): Promise<void> {
    try {
      const follower = await this.prisma.user.findUnique({
        where: { id: followerId },
        select: { username: true },
      });
      if (!follower) return;

      await this.notificationDispatch.dispatch({
        userId: targetUserId,
        topic: 'NEW_FOLLOWER',
        dedupeKey: `NEW_FOLLOWER:${new Date().toISOString().slice(0, 10)}:${followerId}`,
        title: 'Yeni takipçin var',
        body: `${follower.username} seni takip etmeye başladı.`,
        url: `/profile/${follower.username}`,
      });
    } catch (error) {
      this.logger.warn({ err: error as Error, targetUserId }, 'NEW_FOLLOWER_NOTIFICATION_FAILED');
    }
  }
}
