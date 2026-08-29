import { IsNotEmpty, IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class CreatePushSubscriptionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(2048)
  @IsUrl({ protocols: ['https'], require_protocol: true }, { message: 'INVALID_PUSH_ENDPOINT' })
  endpoint: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(256)
  p256dh: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(256)
  auth: string;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  userAgent?: string;
}

export class DeletePushSubscriptionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(2048)
  endpoint: string;
}

export class PushSubscriptionResponseDto {
  id: string;
}

export class VapidPublicKeyDto {
  publicKey: string;
}

export class TestNotificationResultDto {
  delivered: number;
}
