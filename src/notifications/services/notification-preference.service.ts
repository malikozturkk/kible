import { Injectable } from '@nestjs/common';
import { NotificationTopic } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { NOTIFICATION_TOPICS } from '../constants/notification.constants';
import {
  NotificationPreferenceDto,
  NotificationPreferencesDto,
} from '../dto/notification-preferences.dto';

@Injectable()
export class NotificationPreferenceService {
  constructor(private readonly prisma: PrismaService) {}

  async list(userId: string): Promise<NotificationPreferencesDto> {
    const rows = await this.prisma.notificationPreference.findMany({
      where: { userId },
      select: { topic: true, enabled: true, optedInAt: true, optedOutAt: true },
    });
    const byTopic = new Map(rows.map((row) => [row.topic, row]));

    const topics: NotificationPreferenceDto[] = NOTIFICATION_TOPICS.map((meta) => {
      const row = byTopic.get(meta.topic);
      return {
        topic: meta.topic,
        title: meta.title,
        description: meta.description,
        enabled: row?.enabled ?? false,
        optedInAt: row?.optedInAt?.toISOString() ?? null,
        optedOutAt: row?.optedOutAt?.toISOString() ?? null,
      };
    });

    return { topics };
  }

  async setEnabled(
    userId: string,
    topic: NotificationTopic,
    enabled: boolean,
  ): Promise<NotificationPreferencesDto> {
    const now = new Date();

    await this.prisma.notificationPreference.upsert({
      where: { userId_topic: { userId, topic } },
      create: {
        userId,
        topic,
        enabled,
        optedInAt: enabled ? now : null,
        optedOutAt: enabled ? null : now,
      },
      update: {
        enabled,
        ...(enabled ? { optedInAt: now } : { optedOutAt: now }),
      },
    });

    return this.list(userId);
  }

  async enabledTopicsByUser(): Promise<Map<string, Set<NotificationTopic>>> {
    const rows = await this.prisma.notificationPreference.findMany({
      where: { enabled: true },
      select: { userId: true, topic: true },
    });

    const map = new Map<string, Set<NotificationTopic>>();
    for (const row of rows) {
      const set = map.get(row.userId) ?? new Set<NotificationTopic>();
      set.add(row.topic);
      map.set(row.userId, set);
    }
    return map;
  }
}
