export interface WebPushConfig {
  publicKey: string;
  privateKey: string;
  subject: string;
}

export const WEB_PUSH_CONFIG_KEY = 'WEB_PUSH';

export const webPushConfig = (): { [WEB_PUSH_CONFIG_KEY]: WebPushConfig } => {
  const publicKey = process.env.VAPID_PUBLIC_KEY?.trim() ?? '';
  const privateKey = process.env.VAPID_PRIVATE_KEY?.trim() ?? '';
  const subject = process.env.VAPID_SUBJECT?.trim() ?? '';

  const missing = [
    ['VAPID_PUBLIC_KEY', publicKey],
    ['VAPID_PRIVATE_KEY', privateKey],
    ['VAPID_SUBJECT', subject],
  ]
    .filter(([, value]) => value.length === 0)
    .map(([key]) => key);

  if (missing.length > 0) {
    throw new Error(`WEB_PUSH_NOT_CONFIGURED: missing env vars: ${missing.join(', ')}`);
  }

  if (!subject.startsWith('mailto:') && !subject.startsWith('https://')) {
    throw new Error('WEB_PUSH_INVALID_SUBJECT: VAPID_SUBJECT must start with mailto: or https://');
  }

  return { [WEB_PUSH_CONFIG_KEY]: { publicKey, privateKey, subject } };
};
