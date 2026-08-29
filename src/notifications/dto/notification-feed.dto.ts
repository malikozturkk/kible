import { NotificationTopic } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsInt, IsOptional, Max, Min } from 'class-validator';
import { NOTIFICATION_FEED_MAX_LIMIT } from '../constants/notification.constants';

export class NotificationFeedQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'INVALID_LIMIT' })
  @Min(1, { message: 'INVALID_LIMIT' })
  @Max(NOTIFICATION_FEED_MAX_LIMIT, { message: 'INVALID_LIMIT' })
  limit?: number;
}

export class NotificationFeedItemDto {
  id: string;
  topic: NotificationTopic;
  title: string;
  body: string;
  url: string;
  read: boolean;
  sentAt: string;
}

export class NotificationFeedDto {
  items: NotificationFeedItemDto[];
  unreadCount: number;
}
