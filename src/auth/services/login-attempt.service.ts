import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import {
  LOGIN_LOCK_DURATION_MS,
  LOGIN_MAX_FAILED_ATTEMPTS,
} from '../../common/throttler/throttle.constants';

@Injectable()
export class LoginAttemptService {
  constructor(private readonly prisma: PrismaService) {}

  isLocked(credentials: { lockedUntil: Date | null } | null): boolean {
    return credentials?.lockedUntil != null && credentials.lockedUntil.getTime() > Date.now();
  }

  retryAfterSeconds(credentials: { lockedUntil: Date | null } | null): number {
    if (!this.isLocked(credentials)) return 0;
    return Math.ceil(
      ((credentials as { lockedUntil: Date }).lockedUntil.getTime() - Date.now()) / 1000,
    );
  }

  async registerFailure(userId: string, tx?: Prisma.TransactionClient): Promise<void> {
    const db = tx ?? this.prisma;
    try {
      const updated = await db.userCredential.update({
        where: { userId },
        data: { failedLoginAttempts: { increment: 1 } },
        select: { failedLoginAttempts: true },
      });

      if (updated.failedLoginAttempts >= LOGIN_MAX_FAILED_ATTEMPTS) {
        await db.userCredential.update({
          where: { userId },
          data: {
            lockedUntil: new Date(Date.now() + LOGIN_LOCK_DURATION_MS),
            failedLoginAttempts: 0,
          },
        });
      }
    } catch {}
  }

  async registerSuccess(userId: string, tx?: Prisma.TransactionClient): Promise<void> {
    const db = tx ?? this.prisma;
    try {
      await db.userCredential.update({
        where: { userId },
        data: { failedLoginAttempts: 0, lockedUntil: null },
      });
    } catch {}
  }
}
