import { Injectable, Logger } from '@nestjs/common';
import { NotificationTopic, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { WebPushService } from './web-push.service';
import { PushSubscriptionService } from './push-subscription.service';
import { PushPayload } from '../types/notification.types';

export interface DispatchRequest {
  userId: string;
  topic: NotificationTopic;
  dedupeKey: string;
  title: string;
  body: string;
  url: string;
}

@Injectable()
export class NotificationDispatchService {
  private readonly logger = new Logger(NotificationDispatchService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly webPush: WebPushService,
    private readonly subscriptions: PushSubscriptionService,
  ) {}

  async dispatch(request: DispatchRequest): Promise<boolean> {
    const { userId, topic, dedupeKey } = request;

    const claimed = await this.claim(request);
    if (!claimed) return false;

    const preference = await this.prisma.notificationPreference.findUnique({
      where: { userId_topic: { userId, topic } },
      select: { enabled: true },
    });

    if (!preference?.enabled) {
      await this.release(claimed.id);
      return false;
    }

    const targets = await this.subscriptions.listTargets(userId);
    if (targets.length === 0) {
      await this.prisma.notificationDelivery.update({
        where: { id: claimed.id },
        data: { status: 'NO_DEVICE' },
      });
      return false;
    }

    const payload: PushPayload = {
      topic,
      title: request.title,
      body: request.body,
      url: request.url,
      tag: dedupeKey,
    };

    let anySent = false;
    let anyFailure = false;

    for (const target of targets) {
      const outcome = await this.webPush.send(target, payload);

      if (outcome.status === 'SENT') {
        anySent = true;
        await this.subscriptions.markSent(target.id);
      } else if (outcome.status === 'GONE') {
        await this.subscriptions.discard(target.id);
      } else {
        anyFailure = true;
        await this.subscriptions.recordFailure(target.id, target.failureCount);
      }
    }

    const status = anySent ? 'SENT' : anyFailure ? 'FAILED' : 'SUBSCRIPTION_GONE';
    await this.prisma.notificationDelivery.update({
      where: { id: claimed.id },
      data: { status },
    });

    return anySent;
  }

  async sendTest(userId: string): Promise<number> {
    const targets = await this.subscriptions.listTargets(userId);
    if (targets.length === 0) return 0;

    const payload: PushPayload = {
      topic: 'PRAYER_TIME',
      title: 'NamazGo bildirimleri açık',
      body: 'Bu bir deneme bildirimi. Bundan sonra seçtiğin hatırlatmalar buraya gelecek.',
      url: '/settings/notifications',
      tag: 'notification-test',
    };

    let delivered = 0;
    for (const target of targets) {
      const outcome = await this.webPush.send(target, payload);
      if (outcome.status === 'SENT') {
        delivered += 1;
        await this.subscriptions.markSent(target.id);
      } else if (outcome.status === 'GONE') {
        await this.subscriptions.discard(target.id);
      } else {
        await this.subscriptions.recordFailure(target.id, target.failureCount);
      }
    }

    return delivered;
  }

  private async claim(request: DispatchRequest): Promise<{ id: string } | null> {
    try {
      return await this.prisma.notificationDelivery.create({
        data: {
          userId: request.userId,
          topic: request.topic,
          dedupeKey: request.dedupeKey,
          status: 'FAILED',
          title: request.title,
          body: request.body,
          url: request.url,
        },
        select: { id: true },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        return null;
      }
      throw error;
    }
  }

  private async release(deliveryId: string): Promise<void> {
    await this.prisma.notificationDelivery.deleteMany({ where: { id: deliveryId } });
  }
}
