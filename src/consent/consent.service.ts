import { BadRequestException, Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { ConsentType, Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import {
  CONSENT_CACHE_PREFIX,
  CONSENT_CACHE_TTL_MS,
  ConsentErrorCode,
  ConsentVersionsMap,
} from './consent.constants';
import { ConsentStatusItemDto, ConsentStatusResponseDto } from './dto/consent-status.dto';

const CONSENT_TYPES: ConsentType[] = [
  ConsentType.TERMS_OF_SERVICE,
  ConsentType.PRIVACY_POLICY,
  ConsentType.SPECIAL_CATEGORY_DATA,
];
type LatestConsentRow = { type: ConsentType; version: string };

@Injectable()
export class ConsentService implements OnModuleInit {
  private readonly logger = new Logger(ConsentService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
  ) {}

  onModuleInit() {
    const versions = this.getRequiredVersions();
    this.logger.log(
      `CONSENT_VERSIONS loaded: ${Object.entries(versions)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')}`,
    );
  }

  getRequiredVersions(): ConsentVersionsMap {
    const fromConfig = this.config.get<ConsentVersionsMap>('CONSENT_VERSIONS');
    if (!fromConfig) {
      throw new Error('CONSENT_VERSIONS_NOT_CONFIGURED');
    }

    const resolved: ConsentVersionsMap = { ...fromConfig };
    for (const type of CONSENT_TYPES) {
      const envKey = `CONSENT_VERSION_${type}`;
      const override = this.config.get<string>(envKey);
      if (override && override.length > 0) {
        resolved[type] = override;
      }
    }
    return resolved;
  }

  async getStatus(userId: string): Promise<ConsentStatusResponseDto> {
    const required = this.getRequiredVersions();

    const latest = await this.fetchLatestPerType(userId);
    const byType = new Map(latest.map((row) => [row.type, row.version]));

    const items: ConsentStatusItemDto[] = CONSENT_TYPES.map((type) => {
      const acceptedVersion = byType.get(type) ?? null;
      const currentVersion = required[type];
      return {
        type,
        acceptedVersion,
        currentVersion,
        requiresReaccept: acceptedVersion !== currentVersion,
      };
    });

    return {
      items,
      blocked: items.some((item) => item.requiresReaccept),
    };
  }

  async accept(userId: string, type: ConsentType, version: string): Promise<void> {
    const required = this.getRequiredVersions();
    const expected = required[type];

    if (version !== expected) {
      throw new BadRequestException(ConsentErrorCode.CONSENT_OUTDATED);
    }

    try {
      await this.prisma.userConsent.create({
        data: {
          userId,
          type,
          version,
        },
      });
    } catch (err) {
      if (!(err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002')) {
        throw err;
      }
    }

    await this.invalidateCache(userId);
  }

  async fetchLatestPerType(userId: string): Promise<LatestConsentRow[]> {
    const cacheKey = this.cacheKey(userId);
    const cached = await this.cache.get<LatestConsentRow[]>(cacheKey);
    if (cached) {
      return cached;
    }

    const rows = await this.prisma.userConsent.findMany({
      where: { userId },
      select: { type: true, version: true, acceptedAt: true },
      orderBy: [{ type: 'asc' }, { acceptedAt: 'desc' }],
      distinct: ['type'],
    });

    const normalized: LatestConsentRow[] = rows.map(({ type, version }) => ({
      type,
      version,
    }));

    await this.cache.set(cacheKey, normalized, CONSENT_CACHE_TTL_MS);
    return normalized;
  }

  async invalidateCache(userId: string): Promise<void> {
    await this.cache.del(this.cacheKey(userId));
  }

  private cacheKey(userId: string): string {
    return `${CONSENT_CACHE_PREFIX}${userId}`;
  }
}
