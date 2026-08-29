import { NotificationTopic } from '@prisma/client';

export interface PushPayload {
  topic: NotificationTopic;
  title: string;
  body: string;
  url: string;
  tag: string;
}

export interface PushTarget {
  id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  failureCount: number;
}

export interface DispatchResult {
  attempted: number;
  sent: number;
  failed: number;
  gone: number;
}
