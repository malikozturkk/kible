import { SetMetadata } from '@nestjs/common';

export const CONSENT_BYPASS_KEY = 'consentBypass';
export const ConsentBypass = () => SetMetadata(CONSENT_BYPASS_KEY, true);
