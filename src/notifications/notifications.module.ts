import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { WorshipModule } from '../worship/worship.module';
import { NotificationsController } from './notifications.controller';
import { NotificationPreferenceService } from './services/notification-preference.service';
import { PushSubscriptionService } from './services/push-subscription.service';
import { WebPushService } from './services/web-push.service';
import { NotificationDispatchService } from './services/notification-dispatch.service';
import { NotificationFeedService } from './services/notification-feed.service';
import { PrayerNotificationScheduler } from './services/prayer-notification.scheduler';
import { webPushConfig } from './config/web-push.config';

@Module({
  imports: [ConfigModule.forFeature(webPushConfig), PrismaModule, WorshipModule],
  controllers: [NotificationsController],
  providers: [
    NotificationPreferenceService,
    PushSubscriptionService,
    WebPushService,
    NotificationDispatchService,
    NotificationFeedService,
    PrayerNotificationScheduler,
  ],
  exports: [NotificationDispatchService, NotificationPreferenceService, PushSubscriptionService],
})
export class NotificationsModule {}
