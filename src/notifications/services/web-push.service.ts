import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as webPush from 'web-push';
import { PushPayload, PushTarget } from '../types/notification.types';
import { PUSH_TTL_SECONDS } from '../constants/notification.constants';
import { WEB_PUSH_CONFIG_KEY, WebPushConfig } from '../config/web-push.config';

export type PushSendOutcome =
  { status: 'SENT' } | { status: 'GONE' } | { status: 'FAILED'; statusCode?: number };

@Injectable()
export class WebPushService implements OnModuleInit {
  private readonly logger = new Logger(WebPushService.name);
  private config!: WebPushConfig;

  constructor(private readonly configService: ConfigService) {}

  onModuleInit(): void {
    this.config = this.configService.getOrThrow<WebPushConfig>(WEB_PUSH_CONFIG_KEY);
    webPush.setVapidDetails(this.config.subject, this.config.publicKey, this.config.privateKey);
  }

  getPublicKey(): string {
    return this.config.publicKey;
  }

  async send(target: PushTarget, payload: PushPayload): Promise<PushSendOutcome> {
    try {
      await webPush.sendNotification(
        {
          endpoint: target.endpoint,
          keys: { p256dh: target.p256dh, auth: target.auth },
        },
        JSON.stringify(payload),
        { TTL: PUSH_TTL_SECONDS },
      );
      return { status: 'SENT' };
    } catch (error) {
      const statusCode =
        error instanceof webPush.WebPushError
          ? error.statusCode
          : (undefined as number | undefined);

      if (statusCode === 404 || statusCode === 410) {
        return { status: 'GONE' };
      }

      this.logger.warn(
        { statusCode, subscriptionId: target.id, topic: payload.topic },
        'PUSH_SEND_FAILED',
      );
      return { status: 'FAILED', statusCode };
    }
  }
}
