import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Put,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import {
  THROTTLE_NOTIFICATION_SUBSCRIPTION,
  THROTTLE_NOTIFICATION_TEST,
} from '../common/throttler/throttle.constants';
import { NotificationPreferenceService } from './services/notification-preference.service';
import { PushSubscriptionService } from './services/push-subscription.service';
import { NotificationDispatchService } from './services/notification-dispatch.service';
import { NotificationFeedService } from './services/notification-feed.service';
import { WebPushService } from './services/web-push.service';
import {
  NotificationPreferencesDto,
  UpdateNotificationPreferenceDto,
} from './dto/notification-preferences.dto';
import { NotificationFeedDto, NotificationFeedQueryDto } from './dto/notification-feed.dto';
import {
  CreatePushSubscriptionDto,
  DeletePushSubscriptionDto,
  PushSubscriptionResponseDto,
  TestNotificationResultDto,
  VapidPublicKeyDto,
} from './dto/push-subscription.dto';

@Controller('notifications')
@UseGuards(JwtAuthGuard)
export class NotificationsController {
  constructor(
    private readonly preferences: NotificationPreferenceService,
    private readonly subscriptions: PushSubscriptionService,
    private readonly webPush: WebPushService,
    private readonly dispatch: NotificationDispatchService,
    private readonly feed: NotificationFeedService,
  ) {}

  @Get('public-key')
  publicKey(): VapidPublicKeyDto {
    return { publicKey: this.webPush.getPublicKey() };
  }

  @Get('feed')
  async listFeed(
    @Request() req: AuthenticatedRequest,
    @Query() query: NotificationFeedQueryDto,
  ): Promise<NotificationFeedDto> {
    return this.feed.list(req.user.id, query.limit);
  }

  @Post('feed/read')
  @HttpCode(HttpStatus.OK)
  async markFeedRead(@Request() req: AuthenticatedRequest): Promise<NotificationFeedDto> {
    return this.feed.markAllRead(req.user.id);
  }

  @Get('preferences')
  async listPreferences(@Request() req: AuthenticatedRequest): Promise<NotificationPreferencesDto> {
    return this.preferences.list(req.user.id);
  }

  @Put('preferences')
  async updatePreference(
    @Request() req: AuthenticatedRequest,
    @Body() body: UpdateNotificationPreferenceDto,
  ): Promise<NotificationPreferencesDto> {
    return this.preferences.setEnabled(req.user.id, body.topic, body.enabled);
  }

  @Post('subscriptions')
  @Throttle({ default: THROTTLE_NOTIFICATION_SUBSCRIPTION })
  async subscribe(
    @Request() req: AuthenticatedRequest,
    @Body() body: CreatePushSubscriptionDto,
  ): Promise<PushSubscriptionResponseDto> {
    return this.subscriptions.register(req.user.id, body);
  }

  @Post('test')
  @Throttle({ default: THROTTLE_NOTIFICATION_TEST })
  async sendTest(@Request() req: AuthenticatedRequest): Promise<TestNotificationResultDto> {
    const delivered = await this.dispatch.sendTest(req.user.id);
    return { delivered };
  }

  @Delete('subscriptions')
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({ default: THROTTLE_NOTIFICATION_SUBSCRIPTION })
  async unsubscribe(
    @Request() req: AuthenticatedRequest,
    @Body() body: DeletePushSubscriptionDto,
  ): Promise<void> {
    await this.subscriptions.remove(req.user.id, body.endpoint);
  }
}
