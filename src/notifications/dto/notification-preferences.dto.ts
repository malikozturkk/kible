import { NotificationTopic } from '@prisma/client';
import { IsBoolean, IsEnum } from 'class-validator';

export class UpdateNotificationPreferenceDto {
  @IsEnum(NotificationTopic, { message: 'INVALID_NOTIFICATION_TOPIC' })
  topic: NotificationTopic;

  @IsBoolean({ message: 'INVALID_ENABLED' })
  enabled: boolean;
}

export class NotificationPreferenceDto {
  topic: NotificationTopic;
  title: string;
  description: string;
  enabled: boolean;
  optedInAt: string | null;
  optedOutAt: string | null;
}

export class NotificationPreferencesDto {
  topics: NotificationPreferenceDto[];
}
