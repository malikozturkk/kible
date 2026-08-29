import { NotificationTopic, PrayerType } from '@prisma/client';

export const NOTIFICATION_GROUPS = [
  { key: 'PRAYER', title: 'Namaz vakitleri' },
  { key: 'STREAK', title: 'Seri ve ilerleme' },
  { key: 'SOCIAL', title: 'Sosyal' },
] as const;

export type NotificationGroupKey = (typeof NOTIFICATION_GROUPS)[number]['key'];

export interface NotificationTopicMeta {
  topic: NotificationTopic;
  group: NotificationGroupKey;
  title: string;
  description: string;
}

export const NOTIFICATION_TOPICS: readonly NotificationTopicMeta[] = [
  {
    topic: 'PRAYER_TIME',
    group: 'PRAYER',
    title: 'Namaz vakti girdi',
    description: 'Bulunduğun ilin vakti girdiğinde haber verir.',
  },
  {
    topic: 'MARK_WINDOW_CLOSING',
    group: 'PRAYER',
    title: 'İşaretleme süresi doluyor',
    description: 'Kılmadığın bir namazın işaretleme süresi dolmadan 20 dakika önce hatırlatır.',
  },
  {
    topic: 'STREAK_AT_RISK',
    group: 'STREAK',
    title: 'Serim tehlikede',
    description: 'Gün bitmeden hiç namaz işaretlemediysen serini kaybetmeden önce uyarır.',
  },
  {
    topic: 'NEW_FOLLOWER',
    group: 'SOCIAL',
    title: 'Yeni takipçi',
    description: 'Biri seni takip etmeye başladığında haber verir.',
  },
];

export const NOTIFICATION_TOPIC_VALUES = NOTIFICATION_TOPICS.map((t) => t.topic);

export const PRAYER_DISPLAY_NAMES: Record<PrayerType, string> = {
  FAJR: 'Sabah',
  DHUHR: 'Öğle',
  ASR: 'İkindi',
  MAGHRIB: 'Akşam',
  ISHA: 'Yatsı',
  JUMUAH: 'Cuma',
  TARAWIH: 'Teravih',
  EID_FITR: 'Ramazan Bayramı',
  EID_ADHA: 'Kurban Bayramı',
};

export const NOTIFICATION_FEED_MAX_LIMIT = 50;
export const SCHEDULER_TICK_MINUTES = 1;
export const MARK_WINDOW_CLOSING_LEAD_MINUTES = 20;
export const STREAK_AT_RISK_LEAD_MINUTES = 90;
export const PUSH_MAX_FAILURES = 5;
export const NOTIFICATION_DELIVERY_RETENTION_DAYS = 30;
export const PUSH_TTL_SECONDS = 15 * 60;
