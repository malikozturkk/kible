import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { NOTIFICATION_FEED_MAX_LIMIT } from '../constants/notification.constants';
import { NotificationFeedDto, NotificationFeedItemDto } from '../dto/notification-feed.dto';

@Injectable()
export class NotificationFeedService {
  constructor(private readonly prisma: PrismaService) {}

  async list(userId: string, limit?: number): Promise<NotificationFeedDto> {
    const take = Math.min(
      Math.max(limit ?? NOTIFICATION_FEED_MAX_LIMIT, 1),
      NOTIFICATION_FEED_MAX_LIMIT,
    );

    const [rows, unreadCount] = await this.prisma.$transaction([
      this.prisma.notificationDelivery.findMany({
        where: { userId },
        orderBy: { sentAt: 'desc' },
        take,
        select: {
          id: true,
          topic: true,
          title: true,
          body: true,
          url: true,
          readAt: true,
          sentAt: true,
        },
      }),
      this.prisma.notificationDelivery.count({ where: { userId, readAt: null } }),
    ]);

    const items: NotificationFeedItemDto[] = rows.map((row) => ({
      id: row.id,
      topic: row.topic,
      title: row.title,
      body: row.body,
      url: row.url,
      read: row.readAt !== null,
      sentAt: row.sentAt.toISOString(),
    }));

    return { items, unreadCount };
  }

  async markAllRead(userId: string): Promise<NotificationFeedDto> {
    await this.prisma.notificationDelivery.updateMany({
      where: { userId, readAt: null },
      data: { readAt: new Date() },
    });

    return this.list(userId);
  }
}
