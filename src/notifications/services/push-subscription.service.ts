import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { PushTarget } from '../types/notification.types';
import { PUSH_MAX_FAILURES } from '../constants/notification.constants';
import { CreatePushSubscriptionDto } from '../dto/push-subscription.dto';

@Injectable()
export class PushSubscriptionService {
  private readonly logger = new Logger(PushSubscriptionService.name);

  constructor(private readonly prisma: PrismaService) {}

  async register(userId: string, dto: CreatePushSubscriptionDto): Promise<{ id: string }> {
    const subscription = await this.prisma.pushSubscription.upsert({
      where: { endpoint: dto.endpoint },
      create: {
        userId,
        endpoint: dto.endpoint,
        p256dh: dto.p256dh,
        auth: dto.auth,
        userAgent: dto.userAgent ?? null,
      },
      update: {
        userId,
        p256dh: dto.p256dh,
        auth: dto.auth,
        userAgent: dto.userAgent ?? null,
        failureCount: 0,
        lastSeenAt: new Date(),
      },
      select: { id: true },
    });

    return subscription;
  }

  async remove(userId: string, endpoint: string): Promise<void> {
    await this.prisma.pushSubscription.deleteMany({ where: { userId, endpoint } });
  }

  async removeAllForUser(userId: string): Promise<void> {
    await this.prisma.pushSubscription.deleteMany({ where: { userId } });
  }

  async listTargets(userId: string, tx?: Prisma.TransactionClient): Promise<PushTarget[]> {
    const client = tx ?? this.prisma;
    return client.pushSubscription.findMany({
      where: { userId },
      select: { id: true, endpoint: true, p256dh: true, auth: true, failureCount: true },
    });
  }

  async markSent(subscriptionId: string): Promise<void> {
    await this.prisma.pushSubscription.update({
      where: { id: subscriptionId },
      data: { failureCount: 0, lastSeenAt: new Date() },
    });
  }

  async discard(subscriptionId: string): Promise<void> {
    await this.prisma.pushSubscription.deleteMany({ where: { id: subscriptionId } });
  }

  async recordFailure(subscriptionId: string, currentFailureCount: number): Promise<void> {
    if (currentFailureCount + 1 >= PUSH_MAX_FAILURES) {
      await this.discard(subscriptionId);
      this.logger.log({ subscriptionId }, 'PUSH_SUBSCRIPTION_PRUNED');
      return;
    }

    await this.prisma.pushSubscription.updateMany({
      where: { id: subscriptionId },
      data: { failureCount: { increment: 1 } },
    });
  }
}
