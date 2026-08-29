import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { NotificationTopic } from '@prisma/client';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { PrayerTimesService } from '../../worship/services/prayer-times.service';
import { buildPrayerSlots } from '../../gamification/helpers/prayer-schedule.helper';
import { toHijri } from '../../gamification/helpers/hijri.helper';
import { PrayerSlot } from '../../gamification/types/gamification.types';
import { resolveTimezone } from '../../common/utils/timezone.util';
import { LocalDate } from '../../common/utils/local-date';
import { NotificationDispatchService } from './notification-dispatch.service';
import { NotificationPreferenceService } from './notification-preference.service';
import {
  MARK_WINDOW_CLOSING_LEAD_MINUTES,
  PRAYER_DISPLAY_NAMES,
  NOTIFICATION_DELIVERY_RETENTION_DAYS,
  SCHEDULER_TICK_MINUTES,
  STREAK_AT_RISK_LEAD_MINUTES,
} from '../constants/notification.constants';

interface Candidate {
  id: string;
  latitude: number;
  longitude: number;
  topics: Set<NotificationTopic>;
}

const DASHBOARD_URL = '/';

@Injectable()
export class PrayerNotificationScheduler {
  private readonly logger = new Logger(PrayerNotificationScheduler.name);
  private isRunning = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerTimes: PrayerTimesService,
    private readonly preferences: NotificationPreferenceService,
    private readonly dispatch: NotificationDispatchService,
  ) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async tick(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    try {
      const candidates = await this.loadCandidates();
      if (candidates.length === 0) return;

      const slotCache = new Map<string, PrayerSlot[]>();
      let sent = 0;

      for (const candidate of candidates) {
        try {
          sent += await this.evaluateUser(candidate, slotCache);
        } catch (error) {
          this.logger.error(
            { err: error as Error, userId: candidate.id },
            'NOTIFICATION_TICK_USER_FAILED',
          );
        }
      }

      if (sent > 0) {
        this.logger.log({ sent, candidates: candidates.length }, 'NOTIFICATIONS_SENT');
      }
    } finally {
      this.isRunning = false;
    }
  }

  private async loadCandidates(): Promise<Candidate[]> {
    const topicsByUser = await this.preferences.enabledTopicsByUser();
    if (topicsByUser.size === 0) return [];

    const users = await this.prisma.user.findMany({
      where: {
        id: { in: [...topicsByUser.keys()] },
        latitude: { not: null },
        longitude: { not: null },
        pushSubscriptions: { some: {} },
      },
      select: { id: true, latitude: true, longitude: true },
    });

    return users.map((user) => ({
      id: user.id,
      latitude: user.latitude!,
      longitude: user.longitude!,
      topics: topicsByUser.get(user.id)!,
    }));
  }

  private async evaluateUser(
    candidate: Candidate,
    slotCache: Map<string, PrayerSlot[]>,
  ): Promise<number> {
    const timezone = resolveTimezone(candidate.latitude, candidate.longitude);
    const now = DateTime.now().setZone(timezone);
    const today = now.startOf('day');
    const slots = this.slotsFor(candidate, today, timezone, slotCache);

    let sent = 0;
    const dateKey = today.toFormat('yyyy-LL-dd');

    if (candidate.topics.has('PRAYER_TIME')) {
      sent += await this.notifyPrayerTime(candidate.id, slots, now, dateKey);
    }

    if (candidate.topics.has('MARK_WINDOW_CLOSING')) {
      sent += await this.notifyMarkWindowClosing(
        candidate.id,
        slots,
        now,
        today,
        timezone,
        dateKey,
      );
    }

    if (candidate.topics.has('STREAK_AT_RISK')) {
      sent += await this.notifyStreakAtRisk(candidate.id, slots, now, today, timezone, dateKey);
    }

    return sent;
  }

  private slotsFor(
    candidate: Candidate,
    day: DateTime,
    timezone: string,
    cache: Map<string, PrayerSlot[]>,
  ): PrayerSlot[] {
    const key = `${candidate.latitude},${candidate.longitude}|${day.toFormat('yyyy-LL-dd')}`;
    const cached = cache.get(key);
    if (cached) return cached;

    const times = this.prayerTimes.getDay({
      latitude: candidate.latitude,
      longitude: candidate.longitude,
      date: day,
      timezone,
    });

    const slots = buildPrayerSlots({
      todayPrayerTimes: times.prayerTimes,
      tomorrowPrayerTimes: times.tomorrowPrayerTimes,
      zonedDate: day,
      timezone,
      hijri: toHijri(day),
    });

    cache.set(key, slots);
    return slots;
  }

  private firesNow(target: DateTime, now: DateTime): boolean {
    const minutesSince = now.diff(target).as('minutes');
    return minutesSince >= 0 && minutesSince < SCHEDULER_TICK_MINUTES;
  }

  private async notifyPrayerTime(
    userId: string,
    slots: PrayerSlot[],
    now: DateTime,
    dateKey: string,
  ): Promise<number> {
    let sent = 0;

    for (const slot of slots) {
      if (!this.firesNow(slot.scheduledAt, now)) continue;

      const name = PRAYER_DISPLAY_NAMES[slot.type];
      const ok = await this.dispatch.dispatch({
        userId,
        topic: 'PRAYER_TIME',
        dedupeKey: `PRAYER_TIME:${dateKey}:${slot.type}`,
        title: `${name} vakti girdi`,
        body: `${name} vaktindesin. Kıldıktan sonra işaretlemeyi unutma.`,
        url: DASHBOARD_URL,
      });
      if (ok) sent++;
    }

    return sent;
  }

  private async notifyMarkWindowClosing(
    userId: string,
    slots: PrayerSlot[],
    now: DateTime,
    day: DateTime,
    timezone: string,
    dateKey: string,
  ): Promise<number> {
    const due = slots.filter((slot) =>
      this.firesNow(
        slot.markWindowEndsAt.minus({ minutes: MARK_WINDOW_CLOSING_LEAD_MINUTES }),
        now,
      ),
    );
    if (due.length === 0) return 0;

    const completed = await this.completedTypes(userId, day, timezone);
    let sent = 0;

    for (const slot of due) {
      if (completed.has(slot.type)) continue;

      const name = PRAYER_DISPLAY_NAMES[slot.type];
      const ok = await this.dispatch.dispatch({
        userId,
        topic: 'MARK_WINDOW_CLOSING',
        dedupeKey: `MARK_WINDOW_CLOSING:${dateKey}:${slot.type}`,
        title: `${name} işaretlemesi kapanıyor`,
        body: `${name} için ${MARK_WINDOW_CLOSING_LEAD_MINUTES} dakikan kaldı.`,
        url: DASHBOARD_URL,
      });
      if (ok) sent++;
    }

    return sent;
  }

  private async notifyStreakAtRisk(
    userId: string,
    slots: PrayerSlot[],
    now: DateTime,
    day: DateTime,
    timezone: string,
    dateKey: string,
  ): Promise<number> {
    const lastChance = slots.reduce<DateTime | null>(
      (latest, slot) =>
        !latest || slot.markWindowEndsAt > latest ? slot.markWindowEndsAt : latest,
      null,
    );
    if (!lastChance) return 0;
    if (!this.firesNow(lastChance.minus({ minutes: STREAK_AT_RISK_LEAD_MINUTES }), now)) return 0;

    const completed = await this.completedTypes(userId, day, timezone);
    if (completed.size > 0) return 0;

    const streak = await this.prisma.userStreak.findUnique({
      where: { userId },
      select: { currentStreak: true },
    });
    if (!streak || streak.currentStreak <= 0) return 0;

    const ok = await this.dispatch.dispatch({
      userId,
      topic: 'STREAK_AT_RISK',
      dedupeKey: `STREAK_AT_RISK:${dateKey}`,
      title: 'Serin tehlikede',
      body: `${streak.currentStreak} günlük serini kaybetmek üzeresin. Bugün henüz namaz işaretlemedin.`,
      url: DASHBOARD_URL,
    });

    return ok ? 1 : 0;
  }

  private async completedTypes(
    userId: string,
    day: DateTime,
    timezone: string,
  ): Promise<Set<string>> {
    const localDate = LocalDate.fromInstant(day, timezone);
    const rows = await this.prisma.prayerCompletion.findMany({
      where: { userId, prayerDate: localDate.toUtcMidnight() },
      select: { prayerType: true },
    });
    return new Set(rows.map((row) => row.prayerType));
  }

  @Cron(CronExpression.EVERY_DAY_AT_4AM)
  async pruneDeliveries(): Promise<void> {
    const cutoff = DateTime.now().minus({ days: NOTIFICATION_DELIVERY_RETENTION_DAYS }).toJSDate();
    const { count } = await this.prisma.notificationDelivery.deleteMany({
      where: { sentAt: { lt: cutoff } },
    });
    if (count > 0) {
      this.logger.log({ count }, 'NOTIFICATION_DELIVERIES_PRUNED');
    }
  }
}
